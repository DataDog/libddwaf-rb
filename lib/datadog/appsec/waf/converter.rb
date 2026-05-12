# frozen_string_literal: true

require "libddwaf_ext"
require "datadog/appsec/waf/errors"

module Datadog
  module AppSec
    module WAF
      # Ruby ↔ ddwaf_object conversion. Backed by the C extension
      # (`LibDDWAF::Object` + `LibDDWAF.ddwaf_object_*`).
      module Converter
        INT64_MIN = -(2**63)
        UINT64_MAX = 2**64 - 1

        module_function

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def ruby_to_object(val, max_container_size: nil, max_container_depth: nil, max_string_length: nil, top_obj: nil, coerce: true)
          case val
          when Array
            obj = LibDDWAF::Object.new
            res = LibDDWAF.ddwaf_object_array(obj.object_ptr)
            raise ConversionError, "Could not convert into object: #{val}" if res.zero?

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
                e_res = LibDDWAF.ddwaf_object_array_add(obj.object_ptr, member.object_ptr)
                raise ConversionError, "Could not add to array object: #{e.inspect}" unless e_res
                member.disown!
              end
            end

            obj
          when Hash
            obj = LibDDWAF::Object.new
            res = LibDDWAF.ddwaf_object_map(obj.object_ptr)
            raise ConversionError, "Could not convert into object: #{val}" if res.zero?

            if max_container_depth == 0
              top_obj&.mark_truncated!
            else
              val.each.with_index do |e, i|
                if max_container_size && i >= max_container_size
                  (top_obj || obj).mark_truncated!
                  break val
                end

                k = e[0].to_s
                v = e[1]

                if max_string_length && k.length > max_string_length
                  k = k[0, max_string_length] #: String
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
                kv_res = LibDDWAF.ddwaf_object_map_addl(obj.object_ptr, k, k.bytesize, member.object_ptr)
                raise ConversionError, "Could not add to map object: #{e[0].inspect} => #{v.inspect}" unless kv_res
                member.disown!
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
            res = LibDDWAF.ddwaf_object_stringl(obj.object_ptr, encoded_val, encoded_val.bytesize)
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.zero?

            obj
          when Symbol
            obj = LibDDWAF::Object.new
            str = val.to_s
            if max_string_length && str.length > max_string_length
              str = str[0, max_string_length] #: String
              (top_obj || obj).mark_truncated!
            end
            res = LibDDWAF.ddwaf_object_stringl(obj.object_ptr, str, str.bytesize)
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.zero?

            obj
          when Integer
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj.object_ptr, val.to_s)
            elsif val < 0
              clamped = val.clamp(INT64_MIN, -1) #: Integer
              LibDDWAF.ddwaf_object_signed(obj.object_ptr, clamped)
            else
              clamped = val.clamp(0, UINT64_MAX) #: Integer
              LibDDWAF.ddwaf_object_unsigned(obj.object_ptr, clamped)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.zero?

            obj
          when Float
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj.object_ptr, val.to_s)
            else
              LibDDWAF.ddwaf_object_float(obj.object_ptr, val)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.zero?

            obj
          when TrueClass, FalseClass
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj.object_ptr, val.to_s)
            else
              LibDDWAF.ddwaf_object_bool(obj.object_ptr, val)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.zero?

            obj
          when NilClass
            obj = LibDDWAF::Object.new
            res = if coerce
              LibDDWAF.ddwaf_object_string(obj.object_ptr, "")
            else
              LibDDWAF.ddwaf_object_null(obj.object_ptr)
            end
            raise ConversionError, "Could not convert into object: #{val.inspect}" if res.zero?

            obj
          else
            Converter.ruby_to_object("")
          end
        end
        # standard:enable Metrics/MethodLength,Metrics/CyclomaticComplexity

        # standard:disable Metrics/MethodLength,Metrics/CyclomaticComplexity
        def object_to_ruby(obj)
          case obj.type
          when :ddwaf_obj_invalid, :ddwaf_obj_null
            nil
          when :ddwaf_obj_bool
            obj.bool_value
          when :ddwaf_obj_string
            bytes = obj.string_bytes
            bytes.ascii_only? ? bytes : bytes.force_encoding(Encoding::UTF_8)
          when :ddwaf_obj_signed
            obj.signed_value
          when :ddwaf_obj_unsigned
            obj.unsigned_value
          when :ddwaf_obj_float
            obj.float_value
          when :ddwaf_obj_array
            (0...obj.nb_entries).each.with_object([]) do |i, a| #$ ::Array[WAF::opaque]
              a << Converter.object_to_ruby(obj.array_index(i))
            end
          when :ddwaf_obj_map
            (0...obj.nb_entries).each.with_object({}) do |i, h| #$ ::Hash[::String, WAF::opaque]
              entry = obj.array_index(i)
              key = entry.key_bytes
              raise ConversionError, "map entry without parameterName at index #{i}" if key.nil?
              h[key] = Converter.object_to_ruby(entry)
            end
          end
        end
        # standard:enable Metrics/MethodLength,Metrics/CyclomaticComplexity
      end
    end
  end
end
