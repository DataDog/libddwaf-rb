# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      module Converter
        MAX_CONTAINER_SIZE = 256
        MAX_CONTAINER_DEPTH = 20
        MAX_STRING_LENGTH = 4096

        INT64_MIN = -(2**63)
        UINT16_MAX = 2**16 - 1
        UINT32_MAX = 2**32 - 1
        UINT64_MAX = 2**64 - 1

        module_function

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def ruby_to_object(val, object: nil, allocator: nil, top_obj: nil, current_depth: 0, truncate: true)
          if object.nil?
            allocator = LibDDWAF.ddwaf_get_default_allocator
            raise ConversionError, "Could not obtain the native allocator" if allocator.null?

            object = LibDDWAF::Object.new

            begin
              ruby_to_object(val, object: object, allocator: allocator, top_obj: object, truncate: truncate)
              complete = true
              return object
            ensure
              LibDDWAF.ddwaf_object_destroy(object, allocator) unless complete
            end
          end

          result = case val
          when Array
            array_to_object(object, val, allocator, top_obj: top_obj, current_depth: current_depth, truncate: truncate)
          when Hash
            hash_to_object(object, val, allocator, top_obj: top_obj, current_depth: current_depth, truncate: truncate)
          when JSONString
            json_to_object(object, val, allocator)
          when String, Symbol
            string_to_object(object, val.to_s, allocator, top_obj: top_obj, truncate: truncate)
          when Integer
            if val < 0
              LibDDWAF.ddwaf_object_set_signed(object, val.clamp(INT64_MIN, -1))
            else
              LibDDWAF.ddwaf_object_set_unsigned(object, val.clamp(0, UINT64_MAX))
            end
          when Float
            LibDDWAF.ddwaf_object_set_float(object, val)
          when TrueClass, FalseClass
            LibDDWAF.ddwaf_object_set_bool(object, val)
          when NilClass
            LibDDWAF.ddwaf_object_set_null(object)
          else
            string_to_object(object, "", allocator, top_obj: top_obj, truncate: truncate)
          end

          raise ConversionError, "Could not populate native object" if result.to_ptr.null?

          object
        end

        def array_to_object(object, array, allocator, top_obj:, current_depth:, truncate: true)
          max_capacity =
            if !truncate || current_depth.zero?
              UINT16_MAX
            elsif current_depth > MAX_CONTAINER_DEPTH
              0
            else
              MAX_CONTAINER_SIZE
            end

          capacity = (array.size > max_capacity) ? max_capacity : array.size

          container = LibDDWAF.ddwaf_object_set_array(object, capacity, allocator)
          raise ConversionError, "Could not create array object" if container.to_ptr.null?

          array.each_with_index do |element, i|
            if i >= capacity
              top_obj.mark_truncated!
              break
            end

            slot = LibDDWAF.ddwaf_object_insert(object, allocator)
            raise ConversionError, "Could not insert array element" if slot.to_ptr.null?

            ruby_to_object(
              element,
              object: slot,
              allocator: allocator,
              top_obj: top_obj,
              current_depth: current_depth + 1,
              truncate: truncate
            )
          end
          object
        end

        def hash_to_object(object, hash, allocator, top_obj:, current_depth:, truncate: true)
          max_capacity =
            if !truncate || current_depth.zero?
              UINT16_MAX
            elsif current_depth > MAX_CONTAINER_DEPTH
              0
            else
              MAX_CONTAINER_SIZE
            end

          capacity = (hash.size > max_capacity) ? max_capacity : hash.size

          container = LibDDWAF.ddwaf_object_set_map(object, capacity, allocator)
          raise ConversionError, "Could not create map object" if container.to_ptr.null?

          hash.each.with_index do |entry, i|
            if i >= capacity
              top_obj.mark_truncated!
              break
            end

            key = entry[0].to_s
            if truncate
              key = key.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
              if key.length > MAX_STRING_LENGTH
                top_obj.mark_truncated!
                key = key[0, MAX_STRING_LENGTH] #: String
              end
            end
            length = key.bytesize
            raise ConversionError, "Map key exceeds the native length limit" if length > UINT32_MAX

            slot = LibDDWAF.ddwaf_object_insert_key(object, key, length, allocator)
            raise ConversionError, "Could not insert map entry" if slot.to_ptr.null?

            ruby_to_object(
              entry[1],
              object: slot,
              allocator: allocator,
              top_obj: top_obj,
              current_depth: current_depth + 1,
              truncate: truncate
            )
          end
          object
        end

        def json_to_object(object, json, allocator)
          # TODO: Pass request limits to JSON parsing once libddwaf supports them.
          length = json.bytesize
          raise ConversionError, "JSON string exceeds the native length limit" if length > UINT32_MAX

          # In libddwaf 2.0.0, failed parsing leaves this fresh slot invalid.
          unless LibDDWAF.ddwaf_object_from_json(object, json, length, allocator)
            raise ConversionError, "Could not convert JSON string"
          end
          object
        end

        def string_to_object(object, string, allocator, top_obj:, truncate: true)
          string = string.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
          if truncate && string.length > MAX_STRING_LENGTH
            top_obj.mark_truncated!
            string = string[0, MAX_STRING_LENGTH] #: String
          end
          length = string.bytesize
          raise ConversionError, "String exceeds the native length limit" if length > UINT32_MAX

          LibDDWAF.ddwaf_object_set_string(object, string, length, allocator)
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
