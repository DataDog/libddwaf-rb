require 'ffi'
require 'datadog/waf/version'

module Datadog
  module WAF
    module LibDDWAF
      extend ::FFI::Library

      def self.local_os
        Gem::Platform.local.os
      end

      def self.local_cpu
        Gem::Platform.local.cpu
      end

      def self.shared_lib_extname
        Gem::Platform.local.os == 'darwin' ? '.dylib' : '.so'
      end

      def self.shared_lib_path
        File.join(__dir__, "../../vendor/libddwaf/libddwaf-#{Datadog::WAF::VERSION::BASE_STRING}-#{local_os}-#{local_cpu}/lib/libddwaf#{shared_lib_extname}")
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
        LibDDWAF.ddwaf_object_array(obj)
        val.each { |e| LibDDWAF.ddwaf_object_array_add(obj, ruby_to_object(e)) }
        obj
      when Hash
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_map(obj)
        val.each { |k, v| LibDDWAF.ddwaf_object_map_addl(obj, k.to_s, k.to_s.size, ruby_to_object(v)) }
        obj
      when String
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_stringl(obj, val, val.size)
        obj
      when Symbol
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_stringl(obj, val.to_s, val.size)
        obj
      when Integer
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_string(obj, val.to_s)
        obj
      when Float
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_string(obj, val.to_s)
        obj
      when TrueClass, FalseClass
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_string(obj, val.to_s)
        obj
      else
        obj = LibDDWAF::Object.new
        LibDDWAF.ddwaf_object_invalid(obj)
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
          ptr = obj[:valueUnion][:array] + i * Datadog::WAF::LibDDWAF::Object.size
          o = Datadog::WAF::LibDDWAF::Object.new(ptr)
          l = o[:parameterNameLength]
          k = o[:parameterName].read_bytes(l)
          v = object_to_ruby(LibDDWAF::Object.new(ptr))
          h[k] = v
        end
      end
    end

    class Handle
      attr_reader :handle_obj

      DEFAULT_MAX_ARRAY_LENGTH = 256
      DEFAULT_MAX_MAP_DEPTH = 16
      DEFAULT_MAX_TIME_STORE = 128

      def initialize(rule, config = {})
        rule_obj = Datadog::WAF.ruby_to_object(rule)
        config_obj = Datadog::WAF::LibDDWAF::Config.new
        config_obj[:maxArrayLength] = DEFAULT_MAX_ARRAY_LENGTH
        config_obj[:maxMapDepth] = DEFAULT_MAX_MAP_DEPTH
        config_obj[:maxTimeStore] = DEFAULT_MAX_TIME_STORE

        @handle_obj = Datadog::WAF::LibDDWAF.ddwaf_init(rule_obj, config_obj)

        ObjectSpace.define_finalizer(self, Handle.finalizer(handle_obj))
      ensure
        Datadog::WAF::LibDDWAF.ddwaf_object_free(rule_obj) if rule_obj
      end

      def self.finalizer(handle_obj)
        proc do |object_id|
          Datadog::WAF::LibDDWAF.ddwaf_destroy(handle_obj)
        end
      end
    end

    Result = Struct.new(:action, :data, :perf_data, :perf_total_runtime)

    class Context
      attr_reader :context_obj

      def initialize(handle)
        handle_obj = handle.handle_obj
        free_func = Datadog::WAF::LibDDWAF::ObjectNoFree

        @context_obj = Datadog::WAF::LibDDWAF.ddwaf_context_init(handle_obj, free_func)

        ObjectSpace.define_finalizer(self, Context.finalizer(context_obj))
      end

      def self.finalizer(context_obj)
        proc do |object_id|
          Datadog::WAF::LibDDWAF.ddwaf_context_destroy(context_obj)
        end
      end

      DEFAULT_TIMEOUT_US = 10_0000

      def run(input, timeout = DEFAULT_TIMEOUT_US)
        input_obj = Datadog::WAF.ruby_to_object(input)
        result_obj = Datadog::WAF::LibDDWAF::Result.new

        code = Datadog::WAF::LibDDWAF.ddwaf_run(@context_obj, input_obj, result_obj, timeout)

        result = Result.new(
          result_obj[:action],
          result_obj[:data],
          result_obj[:perfData],
          result_obj[:perfTotalRuntime],
        )

        [code, result]
      ensure
        Datadog::WAF::LibDDWAF.ddwaf_object_free(input_obj) if input_obj
        Datadog::WAF::LibDDWAF.ddwaf_result_free(result_obj) if result_obj
      end
    end
  end
end
