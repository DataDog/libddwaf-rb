# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Module responsible for Ruby-to-C and C-to-Ruby conversions
      module Converter
        INT64_MIN = -(2**63)
        UINT16_MAX = 2**16 - 1
        UINT32_MAX = 2**32 - 1
        UINT64_MAX = 2**64 - 1

        module_function

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def ruby_to_object(val, max_container_size: nil, max_container_depth: nil, max_string_length: nil, top_obj: nil, coerce: true)
          allocator = LibDDWAF.ddwaf_get_default_allocator
          raise ConversionError, "Could not obtain the native allocator" if allocator.null?

          object = LibDDWAF::Object.new

          begin
            populate_object(
              object, val,
              allocator: allocator,
              top_obj: top_obj || object,
              max_container_size: max_container_size,
              max_container_depth: max_container_depth,
              max_string_length: max_string_length,
              coerce: coerce
            )
            complete = true
            object
          ensure
            LibDDWAF.ddwaf_object_destroy(object, allocator) unless complete
          end
        end

        # Populate a fresh root or container slot; only the owning root handles cleanup.
        def populate_object(object, val, allocator:, top_obj:, max_container_size:, max_container_depth:, max_string_length:, coerce:)
          result = case val
          when Array
            capacity = container_capacity(val.size, max_container_size, max_container_depth)
            container = LibDDWAF.ddwaf_object_set_array(object, capacity, allocator)
            raise ConversionError, "Could not create array object" if container.to_ptr.null?

            if max_container_depth == 0
              top_obj.mark_truncated! unless val.empty?
            else
              val.each.with_index do |element, i|
                if max_container_size && i >= max_container_size
                  top_obj.mark_truncated!
                  break
                end

                slot = LibDDWAF.ddwaf_object_insert(object, allocator)
                raise ConversionError, "Could not insert array element" if slot.to_ptr.null?

                populate_object(
                  slot, element,
                  allocator: allocator,
                  top_obj: top_obj,
                  max_container_size: max_container_size,
                  max_container_depth: (max_container_depth - 1 if max_container_depth),
                  max_string_length: max_string_length,
                  coerce: coerce
                )
              end
            end
            object
          when Hash
            capacity = container_capacity(val.size, max_container_size, max_container_depth)
            container = LibDDWAF.ddwaf_object_set_map(object, capacity, allocator)
            raise ConversionError, "Could not create map object" if container.to_ptr.null?

            if max_container_depth == 0
              top_obj.mark_truncated! unless val.empty?
            else
              val.each.with_index do |entry, i|
                if max_container_size && i >= max_container_size
                  top_obj.mark_truncated!
                  break
                end

                key = entry[0].to_s
                if max_string_length && key.length > max_string_length
                  key = key[0, max_string_length] #: String
                  top_obj.mark_truncated!
                end
                length = key.bytesize
                raise ConversionError, "Map key exceeds the native length limit" if length > UINT32_MAX

                slot = LibDDWAF.ddwaf_object_insert_key(object, key, length, allocator)
                raise ConversionError, "Could not insert map entry" if slot.to_ptr.null?

                populate_object(
                  slot, entry[1],
                  allocator: allocator,
                  top_obj: top_obj,
                  max_container_size: max_container_size,
                  max_container_depth: (max_container_depth - 1 if max_container_depth),
                  max_string_length: max_string_length,
                  coerce: coerce
                )
              end
            end
            object
          when JSONString
            length = val.bytesize
            raise ConversionError, "JSON string exceeds the native length limit" if length > UINT32_MAX

            # In libddwaf 2.0.0, failed parsing leaves this fresh slot invalid.
            unless LibDDWAF.ddwaf_object_from_json(object, val, length, allocator)
              raise ConversionError, "Could not convert JSON string"
            end
            object
          when String
            string = val.to_s.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
            if max_string_length && string.length > max_string_length
              string = string[0, max_string_length] #: String
              top_obj.mark_truncated!
            end
            string_to_object(object, string, allocator)
          when Symbol
            string = val.to_s
            if max_string_length && string.length > max_string_length
              string = string[0, max_string_length] #: String
              top_obj.mark_truncated!
            end
            string_to_object(object, string, allocator)
          when Integer
            if coerce
              string_to_object(object, val.to_s, allocator)
            elsif val < 0
              clamped = val.clamp(INT64_MIN, -1) #: Integer
              LibDDWAF.ddwaf_object_set_signed(object, clamped)
            else
              clamped = val.clamp(0, UINT64_MAX) #: Integer
              LibDDWAF.ddwaf_object_set_unsigned(object, clamped)
            end
          when Float
            if coerce
              string_to_object(object, val.to_s, allocator)
            else
              LibDDWAF.ddwaf_object_set_float(object, val)
            end
          when TrueClass, FalseClass
            if coerce
              string_to_object(object, val.to_s, allocator)
            else
              LibDDWAF.ddwaf_object_set_bool(object, val)
            end
          when NilClass
            if coerce
              string_to_object(object, "", allocator)
            else
              LibDDWAF.ddwaf_object_set_null(object)
            end
          else
            string_to_object(object, "", allocator)
          end

          raise ConversionError, "Could not populate native object" if result.to_ptr.null?

          object
        end

        def string_to_object(object, string, allocator)
          length = string.bytesize
          raise ConversionError, "String exceeds the native length limit" if length > UINT32_MAX

          LibDDWAF.ddwaf_object_set_string(object, string, length, allocator)
        end

        def container_capacity(size, max_container_size, max_container_depth)
          return 0 if max_container_depth == 0

          capacity = max_container_size ? [size, max_container_size].min : size
          unless capacity.between?(0, UINT16_MAX)
            raise ConversionError, "Container exceeds the native size limit"
          end

          capacity
        end
        # standard:enable Metrics/MethodLength,Metrics/CyclomaticComplexity

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def object_to_ruby(obj)
          case LibDDWAF.ddwaf_object_get_type(obj)
          when :ddwaf_obj_invalid, :ddwaf_obj_null
            nil
          when :ddwaf_obj_bool
            LibDDWAF.ddwaf_object_get_bool(obj)
          when :ddwaf_obj_string, :ddwaf_obj_literal_string, :ddwaf_obj_small_string
            object_to_string(obj)
          when :ddwaf_obj_signed
            LibDDWAF.ddwaf_object_get_signed(obj)
          when :ddwaf_obj_unsigned
            LibDDWAF.ddwaf_object_get_unsigned(obj)
          when :ddwaf_obj_float
            LibDDWAF.ddwaf_object_get_float(obj)
          when :ddwaf_obj_array
            (0...LibDDWAF.ddwaf_object_get_size(obj)).each.with_object([]) do |i, array| #$ ::Array[WAF::opaque]
              array << object_to_ruby(LibDDWAF.ddwaf_object_at_value(obj, i))
            end
          when :ddwaf_obj_map
            (0...LibDDWAF.ddwaf_object_get_size(obj)).each.with_object({}) do |i, hash| #$ ::Hash[::String, WAF::opaque]
              key = object_to_string(LibDDWAF.ddwaf_object_at_key(obj, i))
              value = object_to_ruby(LibDDWAF.ddwaf_object_at_value(obj, i))
              hash[key] = value
            end
          end
        end

        def object_to_string(obj)
          length = LibDDWAF::SizeTPtr.new
          pointer = LibDDWAF.ddwaf_object_get_string(obj, length)
          bytes = pointer.read_bytes(length[:value])

          # FFI reads binary strings; restore UTF-8 for non-ASCII content.
          bytes.ascii_only? ? bytes : bytes.force_encoding(Encoding::UTF_8)
        end
        # standard:enable Metrics/MethodLength,Metrics/CyclomaticComplexity
      end
    end
  end
end
