# frozen_string_literal: true

require "ffi"
require "datadog/appsec/waf/version"

module Datadog
  module AppSec
    module WAF
      # FFI-binding for C-libddwaf
      # See https://github.com/DataDog/libddwaf
      module LibDDWAF
        DEFAULT_MAX_CONTAINER_SIZE = 256
        DEFAULT_MAX_CONTAINER_DEPTH = 20
        DEFAULT_MAX_STRING_LENGTH = 16_384 # in bytes, UTF-8 worst case being 4x size in terms of code point

        DDWAF_MAX_CONTAINER_SIZE = 256
        DDWAF_MAX_CONTAINER_DEPTH = 20
        DDWAF_MAX_STRING_LENGTH = 4096

        DDWAF_RUN_TIMEOUT = 5000

        extend ::FFI::Library

        def self.local_os
          if RUBY_ENGINE == "jruby"
            os_name = java.lang.System.get_property("os.name")

            os = case os_name
            when /linux/i then "linux"
            when /mac/i then "darwin"
            else raise Error, "unsupported JRuby os.name: #{os_name.inspect}"
            end

            return os
          end

          Gem::Platform.local.os
        end

        def self.local_cpu
          if RUBY_ENGINE == "jruby"
            os_arch = java.lang.System.get_property("os.arch")

            cpu = case os_arch
            when "amd64" then "x86_64"
            when "aarch64" then (local_os == "darwin") ? "arm64" : "aarch64"
            else raise Error, "unsupported JRuby os.arch: #{os_arch.inspect}"
            end

            return cpu
          end

          Gem::Platform.local.cpu
        end

        def self.source_dir
          __dir__ || raise("__dir__ is nil: eval?")
        end

        def self.shared_lib_extname
          if Gem::Platform.local.os == "darwin"
            ".dylib"
          elsif Gem::Platform.local.os == "java" && java.lang.System.get_property("os.name").match(/mac/i)
            ".dylib"
          else
            ".so"
          end
        end

        def self.shared_lib_path
          variant = "#{Datadog::AppSec::WAF::VERSION::BASE_STRING}-#{local_os}-#{local_cpu}"
          libddwaf_dir = File.join(source_dir, "../../../../vendor/libddwaf/libddwaf-#{variant}")

          File.join(libddwaf_dir, "lib", "libddwaf#{shared_lib_extname}")
        end

        ffi_lib [shared_lib_path]

        # version

        attach_function :ddwaf_get_version, [], :string

        # ddwaf::object data structure

        DDWAF_OBJ_TYPE = enum :ddwaf_obj_invalid, 0x00,
          :ddwaf_obj_null, 0x01,
          :ddwaf_obj_bool, 0x02,
          :ddwaf_obj_signed, 0x04,
          :ddwaf_obj_unsigned, 0x06,
          :ddwaf_obj_float, 0x08,
          :ddwaf_obj_string, 0x10,
          :ddwaf_obj_literal_string, 0x12,
          :ddwaf_obj_small_string, 0x14,
          :ddwaf_obj_array, 0x20,
          :ddwaf_obj_map, 0x40

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

        class ObjectBool < ::FFI::Struct
          layout :type, :uint8, :val, :bool
        end

        class ObjectSigned < ::FFI::Struct
          layout :type, :uint8, :val, :int64
        end

        class ObjectUnsigned < ::FFI::Struct
          layout :type, :uint8, :val, :uint64
        end

        class ObjectFloat < ::FFI::Struct
          layout :type, :uint8, :val, :double
        end

        class ObjectString < ::FFI::Struct
          layout :type, :uint8, :size, :uint32, :ptr, :pointer
        end

        class ObjectSmallString < ::FFI::Struct
          layout :type, :uint8, :size, :uint8, :data, [:char, 14]
        end

        class ObjectArray < ::FFI::Struct
          layout :type, :uint8, :size, :uint16, :capacity, :uint16, :ptr, :pointer
        end

        class ObjectMap < ::FFI::Struct
          layout :type, :uint8, :size, :uint16, :capacity, :uint16, :ptr, :pointer
        end

        class ObjectValueUnion < ::FFI::Union
          layout :b8, ObjectBool,
            :i64, ObjectSigned,
            :u64, ObjectUnsigned,
            :f64, ObjectFloat,
            :str, ObjectString,
            :sstr, ObjectSmallString,
            :array, ObjectArray,
            :map, ObjectMap
        end

        # See: https://github.com/DataDog/libddwaf/blob/2.0.0/include/ddwaf.h
        class Object < ::FFI::Union
          layout :type, :uint8,
            :via, ObjectValueUnion

          def truncated?
            @truncated == true
          end

          def mark_truncated!
            @truncated = true
          end
        end

        class ObjectKV < ::FFI::Struct
          layout :key, Object,
            :val, Object
        end

        typedef Object.by_ref, :ddwaf_object

        # allocators

        typedef :pointer, :ddwaf_allocator

        attach_function :ddwaf_get_default_allocator, [], :ddwaf_allocator
        attach_function :ddwaf_allocator_alloc, [:ddwaf_allocator, :size_t, :size_t], :pointer
        attach_function :ddwaf_allocator_free, [:ddwaf_allocator, :pointer, :size_t, :size_t], :void

        ## setters

        attach_function :ddwaf_object_set_invalid, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_set_null, [:ddwaf_object], :ddwaf_object
        attach_function :ddwaf_object_set_bool, [:ddwaf_object, :bool], :ddwaf_object
        attach_function :ddwaf_object_set_signed, [:ddwaf_object, :int64], :ddwaf_object
        attach_function :ddwaf_object_set_unsigned, [:ddwaf_object, :uint64], :ddwaf_object
        attach_function :ddwaf_object_set_float, [:ddwaf_object, :double], :ddwaf_object

        attach_function :ddwaf_object_from_json, [:ddwaf_object, :charptr, :uint32, :ddwaf_allocator], :bool

        attach_function :ddwaf_object_set_string, [:ddwaf_object, :charptr, :uint32, :ddwaf_allocator], :ddwaf_object
        attach_function :ddwaf_object_set_string_literal, [:ddwaf_object, :charptr, :uint32], :ddwaf_object
        attach_function :ddwaf_object_set_string_nocopy, [:ddwaf_object, :charptr, :uint32], :ddwaf_object

        attach_function :ddwaf_object_set_array, [:ddwaf_object, :uint16, :ddwaf_allocator], :ddwaf_object
        attach_function :ddwaf_object_set_map, [:ddwaf_object, :uint16, :ddwaf_allocator], :ddwaf_object

        attach_function :ddwaf_object_insert, [:ddwaf_object, :ddwaf_allocator], :ddwaf_object
        attach_function :ddwaf_object_insert_key, [:ddwaf_object, :charptr, :uint32, :ddwaf_allocator], :ddwaf_object
        attach_function :ddwaf_object_insert_key_nocopy, [:ddwaf_object, :charptr, :uint32, :ddwaf_allocator], :ddwaf_object

        ## getters

        attach_function :ddwaf_object_get_type, [:ddwaf_object], DDWAF_OBJ_TYPE
        attach_function :ddwaf_object_get_size, [:ddwaf_object], :size_t
        attach_function :ddwaf_object_get_length, [:ddwaf_object], :size_t
        attach_function :ddwaf_object_get_string, [:ddwaf_object, :sizeptr], :charptr
        attach_function :ddwaf_object_get_unsigned, [:ddwaf_object], :uint64
        attach_function :ddwaf_object_get_signed, [:ddwaf_object], :int64
        attach_function :ddwaf_object_get_bool, [:ddwaf_object], :bool
        attach_function :ddwaf_object_get_float, [:ddwaf_object], :double

        attach_function :ddwaf_object_at_key, [:ddwaf_object, :size_t], :ddwaf_object
        attach_function :ddwaf_object_at_value, [:ddwaf_object, :size_t], :ddwaf_object

        ## destruction

        attach_function :ddwaf_object_destroy, [:ddwaf_object, :ddwaf_allocator], :void

        # handle builder

        typedef :pointer, :ddwaf_builder
        typedef :pointer, :ddwaf_handle

        attach_function :ddwaf_builder_init, [], :ddwaf_builder
        attach_function :ddwaf_builder_destroy, [:ddwaf_builder], :void

        attach_function :ddwaf_builder_add_or_update_config, [:ddwaf_builder, :string, :uint32, :ddwaf_object, :ddwaf_object], :bool
        attach_function :ddwaf_builder_remove_config, [:ddwaf_builder, :string, :uint32], :bool

        attach_function :ddwaf_builder_build_instance, [:ddwaf_builder], :ddwaf_handle

        # handle

        attach_function :ddwaf_destroy, [:ddwaf_handle], :void

        attach_function :ddwaf_known_addresses, [:ddwaf_handle, UInt32Ptr], :charptrptr

        # updating

        DDWAF_RET_CODE = enum :ddwaf_err_internal, -3,
          :ddwaf_err_invalid_object, -2,
          :ddwaf_err_invalid_argument, -1,
          :ddwaf_ok, 0,
          :ddwaf_match, 1
        typedef DDWAF_RET_CODE, :ddwaf_ret_code

        # evaluation

        typedef :pointer, :ddwaf_context
        typedef :pointer, :ddwaf_subcontext
        typedef :uint64, :timeout_us

        attach_function :ddwaf_context_init, [:ddwaf_handle, :ddwaf_allocator], :ddwaf_context
        attach_function :ddwaf_context_destroy, [:ddwaf_context], :void
        attach_function :ddwaf_context_eval, [:ddwaf_context, :ddwaf_object, :ddwaf_allocator, :ddwaf_object, :timeout_us], :ddwaf_ret_code, blocking: true

        attach_function :ddwaf_subcontext_init, [:ddwaf_context], :ddwaf_subcontext
        attach_function :ddwaf_subcontext_destroy, [:ddwaf_subcontext], :void
        attach_function :ddwaf_subcontext_eval, [:ddwaf_subcontext, :ddwaf_object, :ddwaf_allocator, :ddwaf_object, :timeout_us], :ddwaf_ret_code, blocking: true

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
      end
    end
  end
end
