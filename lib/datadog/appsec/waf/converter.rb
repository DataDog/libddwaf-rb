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
        def ruby_to_object(val, limits: nil, coerce: true)
          raise TypeError, "WAF input must be a Hash" if limits && !(Hash === val)

          allocator = LibDDWAF.ddwaf_get_default_allocator
          raise ConversionError, "Could not obtain the native allocator" if allocator.null?

          object = LibDDWAF::Object.new

          begin
            populate_object(
              object, val,
              allocator: allocator,
              top_obj: object,
              limits: limits,
              depth: 0,
              coerce: coerce
            )
            complete = true
            object
          ensure
            LibDDWAF.ddwaf_object_destroy(object, allocator) unless complete
          end
        end

        # Populate a fresh root or container slot; only the owning root handles cleanup.
        def populate_object(object, val, allocator:, top_obj:, limits:, depth:, coerce:)
          result = case val
          when Array
            capacity = container_capacity(val.size, limits: limits, depth: depth)
            container = LibDDWAF.ddwaf_object_set_array(object, capacity, allocator)
            raise ConversionError, "Could not create array object" if container.to_ptr.null?

            val.each.with_index do |element, i|
              if i >= capacity
                top_obj.mark_truncated!
                break
              end

              slot = LibDDWAF.ddwaf_object_insert(object, allocator)
              raise ConversionError, "Could not insert array element" if slot.to_ptr.null?

              populate_object(
                slot, element,
                allocator: allocator,
                top_obj: top_obj,
                limits: limits,
                depth: depth + 1,
                coerce: coerce
              )
            end
            object
          when Hash
            capacity = container_capacity(val.size, limits: limits, depth: depth)
            container = LibDDWAF.ddwaf_object_set_map(object, capacity, allocator)
            raise ConversionError, "Could not create map object" if container.to_ptr.null?

            val.each.with_index do |entry, i|
              if i >= capacity
                top_obj.mark_truncated!
                break
              end

              key = entry[0].to_s
              if limits
                key = key.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
                if depth.zero?
                  if key.length > LibDDWAF::DDWAF_MAX_STRING_LENGTH || key.bytesize > LibDDWAF::DEFAULT_MAX_STRING_LENGTH
                    top_obj.mark_truncated!
                    next
                  end
                else
                  key = truncate_input_string(key, max_bytes: limits.fetch(:max_string_length), top_obj: top_obj)
                end
              end
              length = key.bytesize
              raise ConversionError, "Map key exceeds the native length limit" if length > UINT32_MAX

              slot = LibDDWAF.ddwaf_object_insert_key(object, key, length, allocator)
              raise ConversionError, "Could not insert map entry" if slot.to_ptr.null?

              populate_object(
                slot, entry[1],
                allocator: allocator,
                top_obj: top_obj,
                limits: limits,
                depth: depth + 1,
                coerce: coerce
              )
            end
            object
          when JSONString
            # TODO: Pass request limits to JSON parsing once libddwaf supports them.
            length = val.bytesize
            raise ConversionError, "JSON string exceeds the native length limit" if length > UINT32_MAX

            # In libddwaf 2.0.0, failed parsing leaves this fresh slot invalid.
            unless LibDDWAF.ddwaf_object_from_json(object, val, length, allocator)
              raise ConversionError, "Could not convert JSON string"
            end
            object
          when String, Symbol
            string_to_object(object, val.to_s, allocator, limits: limits, top_obj: top_obj)
          when Integer
            if coerce
              string_to_object(object, val.to_s, allocator, limits: limits, top_obj: top_obj)
            elsif val < 0
              clamped = val.clamp(INT64_MIN, -1) #: Integer
              LibDDWAF.ddwaf_object_set_signed(object, clamped)
            else
              clamped = val.clamp(0, UINT64_MAX) #: Integer
              LibDDWAF.ddwaf_object_set_unsigned(object, clamped)
            end
          when Float
            if coerce
              string_to_object(object, val.to_s, allocator, limits: limits, top_obj: top_obj)
            else
              LibDDWAF.ddwaf_object_set_float(object, val)
            end
          when TrueClass, FalseClass
            if coerce
              string_to_object(object, val.to_s, allocator, limits: limits, top_obj: top_obj)
            else
              LibDDWAF.ddwaf_object_set_bool(object, val)
            end
          when NilClass
            if coerce
              string_to_object(object, "", allocator, limits: limits, top_obj: top_obj)
            else
              LibDDWAF.ddwaf_object_set_null(object)
            end
          else
            string_to_object(object, "", allocator, limits: limits, top_obj: top_obj)
          end

          raise ConversionError, "Could not populate native object" if result.to_ptr.null?

          object
        end

        def truncate_input_string(string, max_bytes:, top_obj:)
          if string.length > LibDDWAF::DDWAF_MAX_STRING_LENGTH
            string = string[0, LibDDWAF::DDWAF_MAX_STRING_LENGTH] #: String
            top_obj.mark_truncated!
          end

          truncate_string_bytes(string, max_bytes: max_bytes, top_obj: top_obj)
        end

        def truncate_string_bytes(string, max_bytes:, top_obj:)
          return string if string.bytesize <= max_bytes

          prefix = string.byteslice(0, max_bytes) #: String
          prefix = prefix.scrub("")
          top_obj.mark_truncated!
          prefix
        end

        def string_to_object(object, string, allocator, limits:, top_obj:)
          string = string.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
          string = truncate_input_string(string, max_bytes: limits.fetch(:max_string_length), top_obj: top_obj) if limits
          length = string.bytesize
          raise ConversionError, "String exceeds the native length limit" if length > UINT32_MAX

          LibDDWAF.ddwaf_object_set_string(object, string, length, allocator)
        end

        def container_capacity(size, limits:, depth:)
          if limits
            max_depth = [limits.fetch(:max_container_depth), LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH - 1].min
            return 0 if depth > max_depth

            max_size = if depth.zero?
              LibDDWAF::DDWAF_MAX_CONTAINER_SIZE
            else
              [limits.fetch(:max_container_size), LibDDWAF::DDWAF_MAX_CONTAINER_SIZE].min
            end
            size = [size, max_size].min
          end

          unless size.between?(0, UINT16_MAX)
            raise ConversionError, "Container exceeds the native size limit"
          end

          size
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
