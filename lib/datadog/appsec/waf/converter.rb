# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Module responsible for Ruby-to-C and C-to-Ruby conversions
      module Converter
        module_function

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def ruby_to_object(val, max_container_size: nil, max_container_depth: nil, max_string_length: nil, top_obj: nil, coerce: true)
          case val
          when Array
            obj = LibDDWAF::Object.new
            res = LibDDWAF.ddwaf_object_array(obj)
            raise ConversionError, "Could not convert into object: #{val}" if res.null?

            if max_container_depth == 0
              top_obj&.mark_truncated!
            else
              val.each.with_index do |e, i|
                if max_container_size && i >= max_container_size
                  (top_obj || obj).mark_truncated!
                  break val
                end

                member = Converter.ruby_to_object(
                  e,
                  max_container_size: max_container_size,
                  max_container_depth: (max_container_depth - 1 if max_container_depth),
                  max_string_length: max_string_length,
                  top_obj: top_obj || obj,
                  coerce: coerce
                )
                e_res = LibDDWAF.ddwaf_object_array_add(obj, member)
                raise ConversionError, "Could not add to array object: #{e.inspect}" unless e_res
              end
            end

            obj
          when Hash
            obj = LibDDWAF::Object.new
            res = LibDDWAF.ddwaf_object_map(obj)
            raise ConversionError, "Could not convert into object: #{val}" if res.null?

            if max_container_depth == 0
              top_obj&.mark_truncated!
            else
              val.each.with_index do |e, i|
                if max_container_size && i >= max_container_size
                  (top_obj || obj).mark_truncated!
                  break val
                end

                # for Steep, which doesn't handle |(k, v), i|
                k = e[0].to_s
                v = e[1]

                if max_string_length && k.length > max_string_length
                  k = k[0, max_string_length]
                  (top_obj || obj).mark_truncated!
                end
                member = Converter.ruby_to_object(
                  v,
                  max_container_size: max_container_size,
                  max_container_depth: (max_container_depth - 1 if max_container_depth),
                  max_string_length: max_string_length,
                  top_obj: top_obj || obj,
                  coerce: coerce
                )
                kv_res = LibDDWAF.ddwaf_object_map_addl(obj, k, k.bytesize, member)
                raise ConversionError, "Could not add to map object: #{e[0].inspect} => #{v.inspect}" unless kv_res
              end
            end

            obj
          when String
            obj = LibDDWAF::Object.new
            encoded_val = val.to_s.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
            if max_string_length && encoded_val.length > max_string_length
              encoded_val = encoded_val[0, max_string_length] #: String
              (top_obj || obj).mark_truncated!
            end
            res = LibDDWAF.ddwaf_object_stringl(obj, encoded_val, encoded_val.bytesize)
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.null?

            obj
          when Symbol
            obj = LibDDWAF::Object.new
            str = val.to_s
            if max_string_length && str.length > max_string_length
              str = str[0, max_string_length] #: String
              (top_obj || obj).mark_truncated!
            end
            res = LibDDWAF.ddwaf_object_stringl(obj, str, str.bytesize)
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.null?

            obj
          when Integer
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj, val.to_s)
            elsif val < 0
              LibDDWAF.ddwaf_object_signed(obj, val)
            else
              LibDDWAF.ddwaf_object_unsigned(obj, val)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.null?

            obj
          when Float
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj, val.to_s)
            else
              LibDDWAF.ddwaf_object_float(obj, val)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.null?

            obj
          when TrueClass, FalseClass
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj, val.to_s)
            else
              LibDDWAF.ddwaf_object_bool(obj, val)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.null?

            obj
          when NilClass
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj, "")
            else
              LibDDWAF.ddwaf_object_null(obj)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.null?

            obj
          else
            Converter.ruby_to_object("")
          end
        end
        # standard:enable Metrics/MethodLength,Metrics/CyclomaticComplexity

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def object_to_ruby(obj)
          case obj[:type]
          when :ddwaf_obj_invalid, :ddwaf_obj_null
            nil
          when :ddwaf_obj_bool
            obj[:valueUnion][:boolean]
          when :ddwaf_obj_string
            # NOTE: FFI's `AbstractMemoryPointer#read_bytes` returns a binary string,
            #       which is not automatically encoded as UTF-8 and will raise an error
            #       if it contains non-ASCII characters and is used in a JSON#generate call.
            bytes = obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])
            bytes.ascii_only? ? bytes : bytes.force_encoding(Encoding::UTF_8)
          when :ddwaf_obj_signed
            obj[:valueUnion][:intValue]
          when :ddwaf_obj_unsigned
            obj[:valueUnion][:uintValue]
          when :ddwaf_obj_float
            obj[:valueUnion][:f64]
          when :ddwaf_obj_array
            (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * LibDDWAF::Object.size
              e = Converter.object_to_ruby(LibDDWAF::Object.new(ptr))
              a << e # steep:ignore
            end
          when :ddwaf_obj_map
            (0...obj[:nbEntries]).each.with_object({}) do |i, h|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              l = o[:parameterNameLength]
              k = o[:parameterName].read_bytes(l)
              v = Converter.object_to_ruby(LibDDWAF::Object.new(ptr))
              h[k] = v # steep:ignore
            end
          end
        end
        # standard:enable Metrics/MethodLength,Metrics/CyclomaticComplexity
      end
    end
  end
end
