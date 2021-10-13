require 'ffi'
require 'json'
require 'datadog/security/waf/version'

module Datadog
  module Security
    module WAF
      module LibDDWAF
        class Error < StandardError; end

        extend ::FFI::Library

        def self.local_os
          if RUBY_ENGINE == 'jruby'
            os_name = java.lang.System.get_property('os.name')

            os = case os_name
                when /linux/i then 'linux'
                when /mac/i   then 'darwin'
                else raise Error, "unsupported JRuby os.name: #{os_name.inspect}"
                end

            return os
          end

          Gem::Platform.local.os
        end

        def self.local_cpu
          if RUBY_ENGINE == 'jruby'
            os_arch = java.lang.System.get_property('os.arch')

            cpu = case os_arch
                  when 'amd64' then 'x86_64'
                  else raise Error, "unsupported JRuby os.arch: #{os_arch.inspect}"
                  end

            return cpu
          end

          Gem::Platform.local.cpu
        end

        def self.shared_lib_extname
          Gem::Platform.local.os == 'darwin' ? '.dylib' : '.so'
        end

        def self.shared_lib_path
          File.join(__dir__, "../../../vendor/libddwaf/libddwaf-#{Datadog::Security::WAF::VERSION::BASE_STRING}-#{local_os}-#{local_cpu}/lib/libddwaf#{shared_lib_extname}")
        end

        ffi_lib [shared_lib_path]

        # version

        class Version < ::FFI::Struct
          layout :major, :uint16,
                :minor, :uint16,
                :patch, :uint16
        end

        typedef Version.by_ref, :ddwaf_version

        attach_function :ddwaf_get_version, [:ddwaf_version], :void

        # ddwaf::object data structure

        DDWAF_OBJ_TYPE = enum :ddwaf_obj_invalid,  0,
                              :ddwaf_obj_signed,   1 << 0,
                              :ddwaf_obj_unsigned, 1 << 1,
                              :ddwaf_obj_string,   1 << 2,
                              :ddwaf_obj_array,    1 << 3,
                              :ddwaf_obj_map,      1 << 4

        typedef :pointer, :charptr

        class ObjectValueUnion < ::FFI::Union
          layout :stringValue, :charptr,
                :uintValue,   :uint64,
                :intValue,    :int64,
                :array,       :pointer
        end

        class Object < ::FFI::Struct
          layout :parameterName,       :charptr,
                :parameterNameLength, :uint64,
                :valueUnion,          ObjectValueUnion,
                :nbEntries,           :uint64,
                :type,                DDWAF_OBJ_TYPE
        end

        typedef Object.by_ref, :ddwaf_object

        attach_function :ddwaf_object_invalid, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_string, [:ddwaf_object, :string], :ddwaf_object
        attach_function :ddwaf_object_stringl, [:ddwaf_object, :charptr, :size_t], :ddwaf_object
        attach_function :ddwaf_object_stringl_nc, [:ddwaf_object, :charptr, :size_t], :ddwaf_object
        attach_function :ddwaf_object_unsigned, [:ddwaf_object, :uint64], :ddwaf_object
        attach_function :ddwaf_object_signed, [:ddwaf_object, :int64], :ddwaf_object
        attach_function :ddwaf_object_unsigned_force, [:ddwaf_object, :uint64], :ddwaf_object
        attach_function :ddwaf_object_signed_force, [:ddwaf_object, :int64], :ddwaf_object

        attach_function :ddwaf_object_array, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_array_add, [:ddwaf_object, :ddwaf_object], :bool

        attach_function :ddwaf_object_map, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_map_add, [:ddwaf_object, :string, :pointer], :bool
        attach_function :ddwaf_object_map_addl, [:ddwaf_object, :charptr, :size_t, :pointer], :bool
        attach_function :ddwaf_object_map_addl_nc, [:ddwaf_object, :charptr, :size_t, :pointer], :bool

        ObjectFree = attach_function :ddwaf_object_free, [:ddwaf_object], :void
        ObjectNoFree = ::FFI::Pointer::NULL

        # main handle

        typedef :pointer, :ddwaf_handle
        typedef Object.by_ref, :ddwaf_rule

        class Config < ::FFI::Struct
          layout :maxArrayLength, :uint64,
                :maxMapDepth,    :uint64,
                :maxTimeStore,   :uint64
        end

        typedef Config.by_ref, :ddwaf_config

        attach_function :ddwaf_init, [:ddwaf_rule, :ddwaf_config], :ddwaf_handle
        attach_function :ddwaf_destroy, [:ddwaf_handle], :void

        # running

        typedef :pointer, :ddwaf_context

        callback :ddwaf_object_free_fn, [:ddwaf_object], :void

        attach_function :ddwaf_context_init, [:ddwaf_handle, :ddwaf_object_free_fn], :ddwaf_context
        attach_function :ddwaf_context_destroy, [:ddwaf_context], :void


        DDWAF_RET_CODE = enum :ddwaf_err_internal,         -4,
                              :ddwaf_err_invalid_object,   -3,
                              :ddwaf_err_invalid_argument, -2,
                              :ddwaf_err_timeout,          -1,
                              :ddwaf_good,                  0,
                              :ddwaf_monitor,               1,
                              :ddwaf_block,                 2

        class Result < ::FFI::Struct
          layout :action,           DDWAF_RET_CODE,
                :data,             :string,
                :perfData,         :string,
                :perfTotalRuntime, :uint32 # in us
        end

        typedef Result.by_ref, :ddwaf_result
        typedef :uint64, :timeout_us

        attach_function :ddwaf_run, [:ddwaf_context, :ddwaf_object, :ddwaf_result, :timeout_us], DDWAF_RET_CODE, blocking: true
        attach_function :ddwaf_result_free, [:ddwaf_result], :void

        # logging

        DDWAF_LOG_LEVEL = enum :ddwaf_log_trace,
                              :ddwaf_log_debug,
                              :ddwaf_log_info,
                              :ddwaf_log_warn,
                              :ddwaf_log_error,
                              :ddwaf_log_off

        callback :ddwaf_log_cb, [DDWAF_LOG_LEVEL, :string, :string, :uint, :charptr, :uint64], :void

        attach_function :ddwaf_set_log_cb, [:ddwaf_log_cb, DDWAF_LOG_LEVEL], :bool
      end

      def self.version
        version = LibDDWAF::Version.new
        LibDDWAF.ddwaf_get_version(version.pointer)

        [version[:major], version[:minor], version[:patch]]
      end

      def self.ruby_to_object(val)
        case val
        when Array
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_array(obj)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          val.each do |e|
            res = LibDDWAF.ddwaf_object_array_add(obj, ruby_to_object(e))
            unless res
              fail LibDDWAF::Error, "Could not add to map object: #{k.inspect} => #{v.inspect}"
            end
          end

          obj
        when Hash
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_map(obj)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          val.each do |k, v|
            res = LibDDWAF.ddwaf_object_map_addl(obj, k.to_s, k.to_s.size, ruby_to_object(v))
            unless res
              fail LibDDWAF::Error, "Could not add to map object: #{k.inspect} => #{v.inspect}"
            end
          end

          obj
        when String
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_stringl(obj, val, val.size)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        when Symbol
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_stringl(obj, val.to_s, val.size)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        when Integer
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_string(obj, val.to_s)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        when Float
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_string(obj, val.to_s)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        when TrueClass, FalseClass
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_string(obj, val.to_s)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        else
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_invalid(obj)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        end
      end

      def self.object_to_ruby(obj)
        case obj[:type]
        when :ddwaf_obj_invalid
          nil
        when :ddwaf_obj_string
          obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])
        when :ddwaf_obj_signed
          obj[:valueUnion][:intValue]
        when :ddwaf_obj_unsigned
          obj[:valueUnion][:uintValue]
        when :ddwaf_obj_array
          (0...obj[:nbEntries]).each.with_object([]) do |i, a|
            ptr = obj[:valueUnion][:array] + i * LibDDWAF::Object.size
            e = object_to_ruby(LibDDWAF::Object.new(ptr))
            a << e
          end
        when :ddwaf_obj_map
          (0...obj[:nbEntries]).each.with_object({}) do |i, h|
            ptr = obj[:valueUnion][:array] + i * Datadog::Security::WAF::LibDDWAF::Object.size
            o = Datadog::Security::WAF::LibDDWAF::Object.new(ptr)
            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            v = object_to_ruby(LibDDWAF::Object.new(ptr))
            h[k] = v
          end
        end
      end

      def self.logger=(logger)
        @log_cb = proc do |level, func, file, line, message, len|
          logger.debug { { level: level, func: func, file: file, message: message.read_bytes(len) }.inspect }
        end

        Datadog::Security::WAF::LibDDWAF.ddwaf_set_log_cb(@log_cb, :ddwaf_log_trace)
      end

      class Handle
        attr_reader :handle_obj

        DEFAULT_MAX_ARRAY_LENGTH = 0
        DEFAULT_MAX_MAP_DEPTH = 0
        DEFAULT_MAX_TIME_STORE = 0

        def initialize(rule, config = {})
          rule_obj = Datadog::Security::WAF.ruby_to_object(rule)
          if rule_obj.null? || rule_obj[:type] == :ddwaf_object_invalid
            fail LibDDWAF::Error, "Could not convert object #{rule.inspect}"
          end

          config_obj = Datadog::Security::WAF::LibDDWAF::Config.new
          if config_obj.null?
            fail LibDDWAF::Error, 'Could not create config struct'
          end

          config_obj[:maxArrayLength] = config[:max_array_length] || DEFAULT_MAX_ARRAY_LENGTH
          config_obj[:maxMapDepth]    = config[:max_map_depth]    || DEFAULT_MAX_MAP_DEPTH
          config_obj[:maxTimeStore]   = config[:max_time_store]   || DEFAULT_MAX_TIME_STORE

          @handle_obj = Datadog::Security::WAF::LibDDWAF.ddwaf_init(rule_obj, config_obj)
          if @handle_obj.null?
            fail LibDDWAF::Error, 'Could not create handle'
          end

          ObjectSpace.define_finalizer(self, Handle.finalizer(handle_obj))
        ensure
          Datadog::Security::WAF::LibDDWAF.ddwaf_object_free(rule_obj) if rule_obj
        end

        def self.finalizer(handle_obj)
          proc do |object_id|
            Datadog::Security::WAF::LibDDWAF.ddwaf_destroy(handle_obj)
          end
        end
      end

      Result = Struct.new(:action, :data, :perf_data, :perf_total_runtime)

      class Context
        attr_reader :context_obj

        def initialize(handle)
          handle_obj = handle.handle_obj
          free_func = Datadog::Security::WAF::LibDDWAF::ObjectNoFree

          @context_obj = Datadog::Security::WAF::LibDDWAF.ddwaf_context_init(handle_obj, free_func)
          if @context_obj.null?
            fail LibDDWAF::Error, 'Could not create context'
          end

          ObjectSpace.define_finalizer(self, Context.finalizer(context_obj))
        end

        def self.finalizer(context_obj)
          proc do |object_id|
            Datadog::Security::WAF::LibDDWAF.ddwaf_context_destroy(context_obj)
          end
        end

        DEFAULT_TIMEOUT_US = 10_0000
        ACTION_MAP_OUT = {
          ddwaf_err_internal:         :err_internal,
          ddwaf_err_invalid_object:   :err_invalid_object,
          ddwaf_err_invalid_argument: :err_invalid_argument,
          ddwaf_err_timeout:          :err_invalid_object,
          ddwaf_good:                 :good,
          ddwaf_monitor:              :monitor,
          ddwaf_block:                :block,
        }

        def run(input, timeout = DEFAULT_TIMEOUT_US)
          input_obj = Datadog::Security::WAF.ruby_to_object(input)
          if input_obj.null?
            fail LibDDWAF::Error, "Could not convert input: #{input.inspect}"
          end

          result_obj = Datadog::Security::WAF::LibDDWAF::Result.new
          if result_obj.null?
            fail LibDDWAF::Error, "Could not create result object"
          end

          code = Datadog::Security::WAF::LibDDWAF.ddwaf_run(@context_obj, input_obj, result_obj, timeout)

          result = Result.new(
            ACTION_MAP_OUT[result_obj[:action]],
            (JSON.parse(result_obj[:data]) if result_obj[:data] != nil),
            (JSON.parse(result_obj[:perfData]) if result_obj[:perfData] != nil),
            result_obj[:perfTotalRuntime],
          )

          [ACTION_MAP_OUT[code], result]
        ensure
          Datadog::Security::WAF::LibDDWAF.ddwaf_object_free(input_obj) if input_obj
          Datadog::Security::WAF::LibDDWAF.ddwaf_result_free(result_obj) if result_obj
        end
      end
    end
  end
end
