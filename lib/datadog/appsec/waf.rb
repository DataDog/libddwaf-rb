# frozen_string_literal: true

require 'datadog/appsec/waf/lib_ddwaf'

require 'datadog/appsec/waf/version'
require 'datadog/appsec/waf/handle'
require 'datadog/appsec/waf/result'
require 'datadog/appsec/waf/context'

module Datadog
  module AppSec
    # The main module exposed outside
    # rubocop:disable Metrics/ModuleLength
    module WAF
      RESULT_CODE = {
        ddwaf_err_internal:         :err_internal,
        ddwaf_err_invalid_object:   :err_invalid_object,
        ddwaf_err_invalid_argument: :err_invalid_argument,
        ddwaf_ok:                   :ok,
        ddwaf_match:                :match,
      }.freeze

      module_function

      def version
        LibDDWAF.ddwaf_get_version
      end

      # rubocop:disable Metrics/MethodLength,Metrics/CyclomaticComplexity,Metrics/PerceivedComplexity
      def ruby_to_object(val, max_container_size: nil, max_container_depth: nil, max_string_length: nil, coerce: true)
        case val
        when Array
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_array(obj)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          max_index = max_container_size - 1 if max_container_size
          val.each.with_index do |e, i|
            member = ruby_to_object(e,
                                    max_container_size: max_container_size,
                                    max_container_depth: (max_container_depth - 1 if max_container_depth),
                                    max_string_length: max_string_length,
                                    coerce: coerce)
            e_res = LibDDWAF.ddwaf_object_array_add(obj, member)
            unless e_res
              fail LibDDWAF::Error, "Could not add to array object: #{e.inspect}"
            end

            break val if max_index && i >= max_index
          end unless max_container_depth == 0

          obj
        when Hash
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_map(obj)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          max_index = max_container_size - 1 if max_container_size
          val.each.with_index do |e, i|
            k, v = e[0], e[1] # for Steep, which doesn't handle |(k, v), i|

            k = k.to_s[0, max_string_length] if max_string_length
            member = ruby_to_object(v,
                                    max_container_size: max_container_size,
                                    max_container_depth: (max_container_depth - 1 if max_container_depth),
                                    max_string_length: max_string_length,
                                    coerce: coerce)
            kv_res = LibDDWAF.ddwaf_object_map_addl(obj, k.to_s, k.to_s.bytesize, member)
            unless kv_res
              fail LibDDWAF::Error, "Could not add to map object: #{k.inspect} => #{v.inspect}"
            end

            break val if max_index && i >= max_index
          end unless max_container_depth == 0

          obj
        when String
          obj = LibDDWAF::Object.new
          encoded_val = val.to_s.encode('utf-8', invalid: :replace, undef: :replace)
          val = encoded_val[0, max_string_length] if max_string_length
          str = val.to_s
          res = LibDDWAF.ddwaf_object_stringl(obj, str, str.bytesize)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val.inspect}"
          end

          obj
        when Symbol
          obj = LibDDWAF::Object.new
          val = val.to_s[0, max_string_length] if max_string_length
          str = val.to_s
          res = LibDDWAF.ddwaf_object_stringl(obj, str, str.bytesize)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val.inspect}"
          end

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
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val.inspect}"
          end

          obj
        when Float
          obj = LibDDWAF::Object.new
          res = if coerce
                  LibDDWAF.ddwaf_object_string(obj, val.to_s)
                else
                  LibDDWAF.ddwaf_object_float(obj, val)
                end
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val.inspect}"
          end

          obj
        when TrueClass, FalseClass
          obj = LibDDWAF::Object.new
          res = if coerce
                  LibDDWAF.ddwaf_object_string(obj, val.to_s)
                else
                  LibDDWAF.ddwaf_object_bool(obj, val)
                end
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val.inspect}"
          end

          obj
        when NilClass
          obj = LibDDWAF::Object.new
          res = if coerce
                  LibDDWAF.ddwaf_object_string(obj, '')
                else
                  LibDDWAF.ddwaf_object_null(obj)
                end
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val.inspect}"
          end

          obj
        else
          ruby_to_object('')
        end
      end
      # rubocop:enable Metrics/MethodLength,Metrics/CyclomaticComplexity,Metrics/PerceivedComplexity

      def object_to_ruby(obj)
        case obj[:type]
        when :ddwaf_obj_invalid, :ddwaf_obj_null
          nil
        when :ddwaf_obj_bool
          obj[:valueUnion][:boolean]
        when :ddwaf_obj_string
          obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])
        when :ddwaf_obj_signed
          obj[:valueUnion][:intValue]
        when :ddwaf_obj_unsigned
          obj[:valueUnion][:uintValue]
        when :ddwaf_obj_float
          obj[:valueUnion][:f64]
        when :ddwaf_obj_array
          (0...obj[:nbEntries]).each.with_object([]) do |i, a|
            ptr = obj[:valueUnion][:array] + i * LibDDWAF::Object.size
            e = object_to_ruby(LibDDWAF::Object.new(ptr))
            a << e # steep:ignore
          end
        when :ddwaf_obj_map
          (0...obj[:nbEntries]).each.with_object({}) do |i, h|
            ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            v = object_to_ruby(LibDDWAF::Object.new(ptr))
            h[k] = v # steep:ignore
          end
        end
      end

      def log_callback(level, func, file, line, message, len)
        return if logger.nil?

        logger.debug do
          {
            level: level,
            func: func,
            file: file,
            line: line,
            message: message.read_bytes(len)
          }.inspect
        end
      end

      def logger
        @logger
      end

      def logger=(logger)
        unless @log_callback
          log_callback = method(:log_callback)
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_set_log_cb(log_callback, :ddwaf_log_trace)

          # retain logging proc if set properly
          @log_callback = log_callback
        end

        @logger = logger
      end

    end
    # rubocop:enable Metrics/ModuleLength
  end
end
