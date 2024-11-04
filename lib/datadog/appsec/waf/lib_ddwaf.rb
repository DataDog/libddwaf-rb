# frozen_string_literal: true

require 'ffi'
require 'datadog/appsec/waf/version'

module Datadog
  module AppSec
    module WAF
      # FFI-binding for C-libddwaf
      # See https://github.com/DataDog/libddwaf
      module LibDDWAF
        # An exception binding raises in most of the cases
        class Error < StandardError
          attr_reader :diagnostics

          def initialize(msg, diagnostics: nil)
            @diagnostics = diagnostics

            super(msg)
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
          return ::Regexp.last_match(1) if RUBY_PLATFORM =~ /linux-(.+)$/

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

        def self.source_dir
          __dir__ || raise('__dir__ is nil: eval?')
        end

        def self.vendor_dir
          File.join(source_dir, '../../../../vendor')
        end

        def self.libddwaf_vendor_dir
          File.join(vendor_dir, 'libddwaf')
        end

        def self.shared_lib_triplet(version: local_version)
          version ? "#{local_os}-#{version}-#{local_cpu}" : "#{local_os}-#{local_cpu}"
        end

        def self.libddwaf_dir
          default = File.join(libddwaf_vendor_dir,
                              "libddwaf-#{Datadog::AppSec::WAF::VERSION::BASE_STRING}-#{shared_lib_triplet}")
          candidates = [
            default
          ]

          if local_os == 'linux'
            candidates << File.join(libddwaf_vendor_dir,
                                    "libddwaf-#{Datadog::AppSec::WAF::VERSION::BASE_STRING}-#{shared_lib_triplet(version: nil)}")
          end

          candidates.find { |d| Dir.exist?(d) } || default
        end

        def self.shared_lib_extname
          Gem::Platform.local.os == 'darwin' ? '.dylib' : '.so'
        end

        def self.shared_lib_path
          File.join(libddwaf_dir, 'lib', "libddwaf#{shared_lib_extname}")
        end

        ffi_lib [shared_lib_path]

        # version

        attach_function :ddwaf_get_version, [], :string

        # ddwaf::object data structure

        DDWAF_OBJ_TYPE = enum :ddwaf_obj_invalid,  0,
                              :ddwaf_obj_signed,   1 << 0,
                              :ddwaf_obj_unsigned, 1 << 1,
                              :ddwaf_obj_string,   1 << 2,
                              :ddwaf_obj_array,    1 << 3,
                              :ddwaf_obj_map,      1 << 4,
                              :ddwaf_obj_bool,     1 << 5,
                              :ddwaf_obj_float,    1 << 6,
                              :ddwaf_obj_null,     1 << 7

        typedef DDWAF_OBJ_TYPE, :ddwaf_obj_type

        typedef :pointer, :charptr
        typedef :pointer, :charptrptr

        # Ruby representation of C uint32_t
        class UInt32Ptr < ::FFI::Struct
          layout :value, :uint32
        end

        typedef UInt32Ptr.by_ref, :uint32ptr

        # Ruby representation of C uint64_t
        class UInt64Ptr < ::FFI::Struct
          layout :value, :uint64
        end

        typedef UInt64Ptr.by_ref, :uint64ptr

        # Ruby representation of C size_t
        class SizeTPtr < ::FFI::Struct
          layout :value, :size_t
        end

        typedef SizeTPtr.by_ref, :sizeptr

        # Ruby representation of C union
        class ObjectValueUnion < ::FFI::Union
          layout :stringValue, :charptr,
                 :uintValue,   :uint64,
                 :intValue,    :int64,
                 :array,       :pointer,
                 :boolean,     :bool,
                 :f64,         :double
        end

        # Ruby representation of ddwaf_object
        # See https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/include/ddwaf.h#L94C1-L115C3
        class Object < ::FFI::Struct
          layout :parameterName,       :charptr,
                 :parameterNameLength, :uint64,
                 :valueUnion,          ObjectValueUnion,
                 :nbEntries,           :uint64,
                 :type,                :ddwaf_obj_type
        end

        typedef Object.by_ref, :ddwaf_object

        ## setters

        attach_function :ddwaf_object_invalid, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_string, [:ddwaf_object, :string], :ddwaf_object
        attach_function :ddwaf_object_stringl, [:ddwaf_object, :charptr, :size_t], :ddwaf_object
        attach_function :ddwaf_object_stringl_nc, [:ddwaf_object, :charptr, :size_t], :ddwaf_object
        attach_function :ddwaf_object_string_from_unsigned, [:ddwaf_object, :uint64], :ddwaf_object
        attach_function :ddwaf_object_string_from_signed, [:ddwaf_object, :int64], :ddwaf_object
        attach_function :ddwaf_object_unsigned, [:ddwaf_object, :uint64], :ddwaf_object
        attach_function :ddwaf_object_signed, [:ddwaf_object, :int64], :ddwaf_object
        attach_function :ddwaf_object_bool, [:ddwaf_object, :bool], :ddwaf_object
        attach_function :ddwaf_object_null, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_float, [:ddwaf_object, :double], :ddwaf_object

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
        attach_function :ddwaf_object_get_bool, [:ddwaf_object], :bool
        attach_function :ddwaf_object_get_float, [:ddwaf_object], :double

        ## freeers

        ObjectFree = attach_function :ddwaf_object_free, [:ddwaf_object], :void
        ObjectNoFree = ::FFI::Pointer::NULL

        # main handle

        typedef :pointer, :ddwaf_handle
        typedef Object.by_ref, :ddwaf_rule

        callback :ddwaf_object_free_fn, [:ddwaf_object], :void

        # Ruby representation of ddwaf_config
        # https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/include/ddwaf.h#L129-L152
        class Config < ::FFI::Struct
          # Ruby representation of ddwaf_config_limits
          # https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/include/ddwaf.h#L131-L138
          class Limits < ::FFI::Struct
            layout :max_container_size,  :uint32,
                   :max_container_depth, :uint32,
                   :max_string_length,   :uint32
          end

          # Ruby representation of ddwaf_config_obfuscator
          # https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/include/ddwaf.h#L141-L146
          class Obfuscator < ::FFI::Struct
            layout :key_regex,   :pointer, # should be :charptr
                   :value_regex, :pointer  # should be :charptr
          end

          layout :limits,     Limits,
                 :obfuscator, Obfuscator,
                 :free_fn,    :pointer # :ddwaf_object_free_fn
        end

        typedef Config.by_ref, :ddwaf_config

        attach_function :ddwaf_init, [:ddwaf_rule, :ddwaf_config, :ddwaf_object], :ddwaf_handle
        attach_function :ddwaf_update, [:ddwaf_handle, :ddwaf_object, :ddwaf_object], :ddwaf_handle
        attach_function :ddwaf_destroy, [:ddwaf_handle], :void

        attach_function :ddwaf_known_addresses, [:ddwaf_handle, UInt32Ptr], :charptrptr

        # updating

        DDWAF_RET_CODE = enum :ddwaf_err_internal,         -3,
                              :ddwaf_err_invalid_object,   -2,
                              :ddwaf_err_invalid_argument, -1,
                              :ddwaf_ok,                    0,
                              :ddwaf_match,                 1
        typedef DDWAF_RET_CODE, :ddwaf_ret_code

        # running

        typedef :pointer, :ddwaf_context

        attach_function :ddwaf_context_init, [:ddwaf_handle], :ddwaf_context
        attach_function :ddwaf_context_destroy, [:ddwaf_context], :void

        # Ruby representation of ddwaf_result
        # See https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/include/ddwaf.h#L154-L173
        class Result < ::FFI::Struct
          layout :timeout,       :bool,
                 :events,        Object,
                 :actions,       Object,
                 :derivatives,   Object,
                 :total_runtime, :uint64
        end

        typedef Result.by_ref, :ddwaf_result
        typedef :uint64, :timeout_us

        attach_function :ddwaf_run, [:ddwaf_context, :ddwaf_object, :ddwaf_object, :ddwaf_result, :timeout_us], :ddwaf_ret_code, blocking: true
        attach_function :ddwaf_result_free, [:ddwaf_result], :void

        # logging

        DDWAF_LOG_LEVEL = enum :ddwaf_log_trace,
                               :ddwaf_log_debug,
                               :ddwaf_log_info,
                               :ddwaf_log_warn,
                               :ddwaf_log_error,
                               :ddwaf_log_off
        typedef DDWAF_LOG_LEVEL, :ddwaf_log_level

        callback :ddwaf_log_cb, [:ddwaf_log_level, :string, :string, :uint, :charptr, :uint64], :void

        attach_function :ddwaf_set_log_cb, [:ddwaf_log_cb, :ddwaf_log_level], :bool

        DEFAULT_MAX_CONTAINER_SIZE  = 256
        DEFAULT_MAX_CONTAINER_DEPTH = 20
        DEFAULT_MAX_STRING_LENGTH   = 16_384 # in bytes, UTF-8 worst case being 4x size in terms of code point)

        DDWAF_MAX_CONTAINER_SIZE  = 256
        DDWAF_MAX_CONTAINER_DEPTH = 20
        DDWAF_MAX_STRING_LENGTH   = 4096

        DDWAF_RUN_TIMEOUT = 5000
      end
    end
  end
end