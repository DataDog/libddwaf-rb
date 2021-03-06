require 'ffi'
require 'json'
require 'datadog/appsec/waf/version'

module Datadog
  module AppSec
    module WAF
      module LibDDWAF
        class Error < StandardError
          attr_reader :ruleset_info

          def initialize(msg, ruleset_info: nil)
            @ruleset_info = ruleset_info
          end
        end

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

        def self.local_version
          return nil unless local_os == 'linux'

          # Old rubygems don't handle non-gnu linux correctly
          return $1 if RUBY_PLATFORM =~ /linux-(.+)$/

          'gnu'
        end

        def self.local_cpu
          if RUBY_ENGINE == 'jruby'
            os_arch = java.lang.System.get_property('os.arch')

            cpu = case os_arch
                  when 'amd64' then 'x86_64'
                  when 'aarch64' then 'aarch64'
                  else raise Error, "unsupported JRuby os.arch: #{os_arch.inspect}"
                  end

            return cpu
          end

          Gem::Platform.local.cpu
        end

        def self.vendor_dir
          File.join(__dir__, '../../../vendor')
        end

        def self.libddwaf_vendor_dir
          File.join(vendor_dir, 'libddwaf')
        end

        def self.shared_lib_triplet
          local_version ? "#{local_os}-#{local_version}-#{local_cpu}" : "#{local_os}-#{local_cpu}"
        end

        def self.libddwaf_dir
          File.join(libddwaf_vendor_dir, "libddwaf-#{Datadog::AppSec::WAF::VERSION::BASE_STRING}-#{shared_lib_triplet}")
        end

        def self.shared_lib_extname
          Gem::Platform.local.os == 'darwin' ? '.dylib' : '.so'
        end

        def self.shared_lib_path
          File.join(libddwaf_dir, 'lib', "libddwaf#{shared_lib_extname}")
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
        typedef :pointer, :charptrptr

        class UInt32Ptr < ::FFI::Struct
          layout :value, :uint32
        end

        typedef UInt32Ptr.by_ref, :uint32ptr

        class UInt64Ptr < ::FFI::Struct
          layout :value, :uint64
        end

        typedef UInt64Ptr.by_ref, :uint64ptr

        class SizeTPtr < ::FFI::Struct
          layout :value, :size_t
        end

        typedef SizeTPtr.by_ref, :sizeptr

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

        ## setters

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

        ## getters

        attach_function :ddwaf_object_type, [:ddwaf_object], DDWAF_OBJ_TYPE
        attach_function :ddwaf_object_size, [:ddwaf_object], :uint64
        attach_function :ddwaf_object_length, [:ddwaf_object], :size_t
        attach_function :ddwaf_object_get_key, [:ddwaf_object, :sizeptr], :charptr
        attach_function :ddwaf_object_get_string, [:ddwaf_object, :sizeptr], :charptr
        attach_function :ddwaf_object_get_unsigned, [:ddwaf_object], :uint64
        attach_function :ddwaf_object_get_signed, [:ddwaf_object], :int64
        attach_function :ddwaf_object_get_index, [:ddwaf_object, :size_t], :ddwaf_object

        ## freeers

        ObjectFree = attach_function :ddwaf_object_free, [:ddwaf_object], :void
        ObjectNoFree = ::FFI::Pointer::NULL

        # main handle

        typedef :pointer, :ddwaf_handle
        typedef Object.by_ref, :ddwaf_rule

        class Config < ::FFI::Struct
          class Limits < ::FFI::Struct
            layout :max_container_size,  :uint32,
                   :max_container_depth, :uint32,
                   :max_string_length,   :uint32
          end

          class Obfuscator < ::FFI::Struct
            layout :key_regex,   :pointer, # :charptr
                   :value_regex, :pointer  # :charptr
          end

          layout :limits,     Limits,
                 :obfuscator, Obfuscator
        end

        typedef Config.by_ref, :ddwaf_config

        class RuleSetInfo < ::FFI::Struct
          layout :loaded, :uint16,
                 :failed, :uint16,
                 :errors, Object,
                 :version, :string
        end

        typedef RuleSetInfo.by_ref, :ddwaf_ruleset_info
        RuleSetInfoNone = Datadog::AppSec::WAF::LibDDWAF::RuleSetInfo.new(::FFI::Pointer::NULL)

        attach_function :ddwaf_ruleset_info_free, [:ddwaf_ruleset_info], :void

        attach_function :ddwaf_init, [:ddwaf_rule, :ddwaf_config, :ddwaf_ruleset_info], :ddwaf_handle
        attach_function :ddwaf_destroy, [:ddwaf_handle], :void

        attach_function :ddwaf_required_addresses, [:ddwaf_handle, UInt32Ptr], :charptrptr

        # running

        typedef :pointer, :ddwaf_context

        callback :ddwaf_object_free_fn, [:ddwaf_object], :void

        attach_function :ddwaf_context_init, [:ddwaf_handle, :ddwaf_object_free_fn], :ddwaf_context
        attach_function :ddwaf_context_destroy, [:ddwaf_context], :void

        DDWAF_RET_CODE = enum :ddwaf_err_internal,         -3,
                              :ddwaf_err_invalid_object,   -2,
                              :ddwaf_err_invalid_argument, -1,
                              :ddwaf_good,                  0,
                              :ddwaf_monitor,               1,
                              :ddwaf_block,                 2

        class Result < ::FFI::Struct
          layout :timeout,          :bool,
                 :data,             :string,
                 :total_runtime,    :uint64
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
            res = LibDDWAF.ddwaf_object_map_addl(obj, k.to_s, k.to_s.bytesize, ruby_to_object(v))
            unless res
              fail LibDDWAF::Error, "Could not add to map object: #{k.inspect} => #{v.inspect}"
            end
          end

          obj
        when String
          obj = LibDDWAF::Object.new
          res = LibDDWAF.ddwaf_object_stringl(obj, val, val.bytesize)
          if res.null?
            fail LibDDWAF::Error, "Could not convert into object: #{val}"
          end

          obj
        when Symbol
          obj = LibDDWAF::Object.new
          str = val.to_s
          res = LibDDWAF.ddwaf_object_stringl(obj, str, str.bytesize)
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
          ruby_to_object(''.freeze)
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
            ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            v = object_to_ruby(LibDDWAF::Object.new(ptr))
            h[k] = v
          end
        end
      end

      def self.logger=(logger)
        @log_cb = proc do |level, func, file, line, message, len|
          logger.debug { { level: level, func: func, file: file, line: line, message: message.read_bytes(len) }.inspect }
        end

        Datadog::AppSec::WAF::LibDDWAF.ddwaf_set_log_cb(@log_cb, :ddwaf_log_trace)
      end

      class Handle
        attr_reader :handle_obj

        DEFAULT_MAX_CONTAINER_SIZE  = 0
        DEFAULT_MAX_CONTAINER_DEPTH = 0
        DEFAULT_MAX_STRING_LENGTH   = 0

        attr_reader :ruleset_info

        def initialize(rule, limits: {}, obfuscator: {})
          rule_obj = Datadog::AppSec::WAF.ruby_to_object(rule)
          if rule_obj.null? || rule_obj[:type] == :ddwaf_object_invalid
            fail LibDDWAF::Error, "Could not convert object #{rule.inspect}"
          end

          config_obj = Datadog::AppSec::WAF::LibDDWAF::Config.new
          if config_obj.null?
            fail LibDDWAF::Error, 'Could not create config struct'
          end

          config_obj[:limits][:max_container_size]  = limits[:max_container_size]  || DEFAULT_MAX_CONTAINER_SIZE
          config_obj[:limits][:max_container_depth] = limits[:max_container_depth] || DEFAULT_MAX_CONTAINER_DEPTH
          config_obj[:limits][:max_string_length]   = limits[:max_string_length]   || DEFAULT_MAX_STRING_LENGTH
          config_obj[:obfuscator][:key_regex]       = FFI::MemoryPointer.from_string(obfuscator[:key_regex])   if obfuscator[:key_regex]
          config_obj[:obfuscator][:value_regex]     = FFI::MemoryPointer.from_string(obfuscator[:value_regex]) if obfuscator[:value_regex]

          ruleset_info = LibDDWAF::RuleSetInfo.new

          @handle_obj = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule_obj, config_obj, ruleset_info)

          @ruleset_info = {
            loaded: ruleset_info[:loaded],
            failed: ruleset_info[:failed],
            errors: WAF.object_to_ruby(ruleset_info[:errors]),
            version: ruleset_info[:version],
          }

          if @handle_obj.null?
            fail LibDDWAF::Error.new('Could not create handle', ruleset_info: @ruleset_info)
          end

          ObjectSpace.define_finalizer(self, Handle.finalizer(handle_obj))
        ensure
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_ruleset_info_free(ruleset_info) if ruleset_info
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(rule_obj) if rule_obj
        end

        def self.finalizer(handle_obj)
          proc do |object_id|
            Datadog::AppSec::WAF::LibDDWAF.ddwaf_destroy(handle_obj)
          end
        end

        def required_addresses
          count = Datadog::AppSec::WAF::LibDDWAF::UInt32Ptr.new
          list = Datadog::AppSec::WAF::LibDDWAF.ddwaf_required_addresses(handle_obj, count)

          return [] if count == 0 # list is null

          list.get_array_of_string(0, count[:value])
        end
      end

      Result = Struct.new(:action, :data, :total_runtime, :timeout)

      class Context
        attr_reader :context_obj

        def initialize(handle)
          @retained = []

          handle_obj = handle.handle_obj
          retain(handle_obj)
          free_func = Datadog::AppSec::WAF::LibDDWAF::ObjectNoFree

          @context_obj = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle_obj, free_func)
          if @context_obj.null?
            fail LibDDWAF::Error, 'Could not create context'
          end

          ObjectSpace.define_finalizer(self, Context.finalizer(context_obj, @input_objs))
        end

        def self.finalizer(context_obj, input_objs)
          proc do |object_id|
            input_objs.each do |input_obj|
              Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(input_obj)
            end
            Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_destroy(context_obj)
          end
        end

        DEFAULT_TIMEOUT_US = 10_000
        ACTION_MAP_OUT = {
          ddwaf_err_internal:         :err_internal,
          ddwaf_err_invalid_object:   :err_invalid_object,
          ddwaf_err_invalid_argument: :err_invalid_argument,
          ddwaf_good:                 :good,
          ddwaf_monitor:              :monitor,
          ddwaf_block:                :block,
        }

        def run(input, timeout = DEFAULT_TIMEOUT_US)
          input_obj = Datadog::AppSec::WAF.ruby_to_object(input)
          if input_obj.null?
            fail LibDDWAF::Error, "Could not convert input: #{input.inspect}"
          end

          result_obj = Datadog::AppSec::WAF::LibDDWAF::Result.new
          if result_obj.null?
            fail LibDDWAF::Error, "Could not create result object"
          end

          # retain C objects in memory for subsequent calls to run
          retain(input_obj)

          code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(@context_obj, input_obj, result_obj, timeout)

          result = Result.new(
            ACTION_MAP_OUT[code],
            (JSON.parse(result_obj[:data]) if result_obj[:data] != nil),
            result_obj[:total_runtime],
            result_obj[:timeout],
          )

          [ACTION_MAP_OUT[code], result]
        ensure
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_result_free(result_obj) if result_obj
        end

        private

        def retain(object)
          @retained << object
        end
      end
    end
  end
end
