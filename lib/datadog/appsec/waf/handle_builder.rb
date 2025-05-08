# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      ##
      # Manages libddwaf configuration over the application's lifetime.
      class HandleBuilder
        def initialize(limits: {}, obfuscator: {})
          handle_config_obj = LibDDWAF::HandleBuilderConfig.new
          if handle_config_obj.null?
            raise LibDDWAFError, "Could not create config struct"
          end

          handle_config_obj[:limits][:max_container_size] = limits[:max_container_size] || LibDDWAF::DEFAULT_MAX_CONTAINER_SIZE
          handle_config_obj[:limits][:max_container_depth] = limits[:max_container_depth] || LibDDWAF::DEFAULT_MAX_CONTAINER_DEPTH
          handle_config_obj[:limits][:max_string_length] = limits[:max_string_length] || LibDDWAF::DEFAULT_MAX_STRING_LENGTH

          handle_config_obj[:obfuscator][:key_regex] = FFI::MemoryPointer.from_string(obfuscator[:key_regex]) if obfuscator[:key_regex]
          handle_config_obj[:obfuscator][:value_regex] = FFI::MemoryPointer.from_string(obfuscator[:value_regex]) if obfuscator[:value_regex]
          handle_config_obj[:free_fn] = LibDDWAF::ObjectNoFree

          @builder_ptr = LibDDWAF.ddwaf_builder_init(handle_config_obj)
        end

        def finalize!
          builder_ptr_to_destroy = @builder_ptr
          @builder_ptr = nil

          LibDDWAF.ddwaf_builder_destroy(builder_ptr_to_destroy)
        end

        # NOTE: libddwaf will return a null handle if no configuration has been loaded
        #
        # Not thread-safe
        def build_handle
          ensure_pointer_presence!

          handle_obj = LibDDWAF.ddwaf_builder_build_instance(@builder_ptr)
          raise LibDDWAFError, "Could not create handle" if handle_obj.null?

          Handle.new(handle_obj)
        end

        # Not thread-safe
        def add_or_update_config(config:, path:)
          ensure_pointer_presence!

          config_obj = Converter.ruby_to_object(config)
          diagnostics_obj = LibDDWAF::Object.new

          LibDDWAF.ddwaf_builder_add_or_update_config(@builder_ptr, path, path.length, config_obj, diagnostics_obj)

          Converter.object_to_ruby(diagnostics_obj)
        ensure
          LibDDWAF.ddwaf_object_free(config_obj) if config_obj
          LibDDWAF.ddwaf_object_free(diagnostics_obj) if diagnostics_obj
        end

        # Not thread-safe
        def remove_config(path:)
          ensure_pointer_presence!

          LibDDWAF.ddwaf_builder_remove_config(@builder_ptr, path, path.length)
        end

        private

        def ensure_pointer_presence!
          return unless @builder_ptr.nil?

          raise HandleBuilderFinalizedError, "Cannot use WAF handle builder after it has been finalized"
        end
      end
    end
  end
end
