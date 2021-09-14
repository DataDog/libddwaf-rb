require 'ffi'
require 'datadog/waf/version'

module Datadog
  module WAF
    module LibDDWAF
      extend ::FFI::Library

      ffi_lib ['vendor/libddwaf/libddwaf-1.0.8-darwin-x86_64/lib/libddwaf.dylib']

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
               :uintValue,   :uint64_t,
               :intValue,    :int64_t,
               :array,       :pointer
      end

      class Object < ::FFI::Struct
        layout :parameterName,       :charptr,
               :parameterNameLength, :uint64_t,
               :valueUnion,          ObjectValueUnion,
               :nbEntries,           :uint64_t,
               :type,                DDWAF_OBJ_TYPE
      end

      typedef Object.by_ref, :ddwaf_object

      attach_function :ddwaf_object_invalid, [:ddwaf_object], :ddwaf_object
      attach_function :ddwaf_object_string, [:ddwaf_object, :string], :ddwaf_object
      attach_function :ddwaf_object_stringl, [:ddwaf_object, :charptr, :size_t], :ddwaf_object
      attach_function :ddwaf_object_stringl_nc, [:ddwaf_object, :charptr, :size_t], :ddwaf_object
      attach_function :ddwaf_object_unsigned, [:ddwaf_object, :uint64_t], :ddwaf_object
      attach_function :ddwaf_object_signed, [:ddwaf_object, :int64_t], :ddwaf_object
      attach_function :ddwaf_object_unsigned_force, [:ddwaf_object, :uint64_t], :ddwaf_object
      attach_function :ddwaf_object_signed_force, [:ddwaf_object, :int64_t], :ddwaf_object

      attach_function :ddwaf_object_array, [:ddwaf_object], :ddwaf_object
      attach_function :ddwaf_object_array_add, [:ddwaf_object, :ddwaf_object], :bool

      attach_function :ddwaf_object_map, [:ddwaf_object], :ddwaf_object
      attach_function :ddwaf_object_map_add, [:ddwaf_object, :string, :pointer], :bool
      attach_function :ddwaf_object_map_addl, [:ddwaf_object, :charptr, :size_t, :pointer], :bool
      attach_function :ddwaf_object_map_addl_nc, [:ddwaf_object, :charptr, :size_t, :pointer], :bool

      attach_function :ddwaf_object_free, [:ddwaf_object], :void

      # main handle

      typedef :pointer, :ddwaf_handle
      typedef Object.by_ref, :ddwaf_rule

      class Config < ::FFI::Struct
        layout :maxArrayLength, :uint64_t,
               :maxMapDepth,    :uint64_t,
               :maxTimeStore,   :uint64_t
      end

      typedef Config.by_ref, :ddwaf_config

      attach_function :ddwaf_init, [:ddwaf_rule, :ddwaf_config], :ddwaf_handle
      attach_function :ddwaf_destroy, [:ddwaf_handle], :void

      # running

      typedef :pointer, :ddwaf_context
      typedef :pointer, :ddwaf_object_free_fn

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
               :perfTotalRuntime, :uint32_t # in us
      end

      typedef Result.by_ref, :ddwaf_result
      typedef :uint64, :timeout_us

      attach_function :ddwaf_run, [:ddwaf_context, :ddwaf_object, :ddwaf_result, :timeout_us], DDWAF_RET_CODE
      attach_function :ddwaf_result_free, [:ddwaf_result], :void

      # logging

      DDWAF_LOG_LEVEL = enum :ddwaf_log_trace,
                             :ddwaf_log_debug,
                             :ddwaf_log_info,
                             :ddwaf_log_warn,
                             :ddwaf_log_error,
                             :ddwaf_log_off

      callback :ddwaf_log_cb, [DDWAF_LOG_LEVEL, :string, :string, :uint, :charptr, :uint64_t], :void

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
        obj = LibDDWAF.ddwaf_object_array(LibDDWAF::Object.new)
        val.each { |e| LibDDWAF.ddwaf_object_array_add(obj, ruby_to_object(e)) }
        obj
      when Hash
        obj = LibDDWAF.ddwaf_object_map(LibDDWAF::Object.new)
        val.each { |k, v| LibDDWAF.ddwaf_object_map_addl(obj, k.to_s, k.to_s.size, ruby_to_object(v)) }
        obj
      when String
        LibDDWAF.ddwaf_object_stringl(LibDDWAF::Object.new, val, val.size)
      when Symbol
        LibDDWAF.ddwaf_object_stringl(LibDDWAF::Object.new, val.to_s, val.size)
      when Integer
        LibDDWAF.ddwaf_object_string(LibDDWAF::Object.new, val.to_s)
      when Float
        LibDDWAF.ddwaf_object_string(LibDDWAF::Object.new, val.to_s)
      when TrueClass, FalseClass
        LibDDWAF.ddwaf_object_string(LibDDWAF::Object.new, val.to_s)
      else
        LibDDWAF.ddwaf_object_invalid(LibDDWAF::Object.new)
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
  end
end
