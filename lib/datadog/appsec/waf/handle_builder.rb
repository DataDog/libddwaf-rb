# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # This class represents the libddwaf WAF builder, which is used to generate WAF handles.
      #
      # It handles merging of potentially overlapping configurations.
      class HandleBuilder
        OBFUSCATOR_CONFIG_PATH = "libddwaf-rb/obfuscator"

        def initialize(obfuscator: {})
          @builder_ptr = LibDDWAF.ddwaf_builder_init
          raise LibDDWAFError, "Could not create builder" if @builder_ptr.null?

          begin
            configure_obfuscator(obfuscator)
            initialized = true
          ensure
            finalize! unless initialized
          end
        end

        # Destroys the WAF builder and sets the pointer to nil.
        #
        # The instance becomes unusable after this method is called.
        def finalize!
          builder_ptr_to_destroy = @builder_ptr
          @builder_ptr = nil

          LibDDWAF.ddwaf_builder_destroy(builder_ptr_to_destroy)
        end

        # Builds a WAF handle from the current state of the builder.
        #
        # @raise [LibDDWAFError] if no rules were added to the builder before building the handle
        # @return [Handle] the WAF handle
        def build_handle
          ensure_pointer_presence!

          handle_obj = LibDDWAF.ddwaf_builder_build_instance(@builder_ptr)
          raise LibDDWAFError, "Could not create handle" if handle_obj.null?

          begin
            handle = Handle.new(handle_obj)
            initialized = true
            handle
          ensure
            LibDDWAF.ddwaf_destroy(handle_obj) unless initialized
          end
        end

        # :section: Configuration management methods
        # methods for adding, updating, and removing configurations from the WAF handle builder.

        # Adds or updates a configuration in the WAF handle builder for the given path.
        #
        # @return [Hash] diagnostics object
        # NOTE: default config that was read from file at application startup
        # has to be removed before adding configurations obtained through Remote Configuration.
        def add_or_update_config(config, path:)
          ensure_pointer_presence!
          raise ArgumentError, "Configuration path is reserved for the obfuscator" if path == OBFUSCATOR_CONFIG_PATH

          path_length = path.bytesize
          raise ArgumentError, "Configuration path exceeds the native length limit" if path_length > 0xffff_ffff

          allocator = LibDDWAF.ddwaf_get_default_allocator
          raise LibDDWAFError, "Could not obtain the native allocator" if allocator.null?

          config_obj = Converter.ruby_to_object(config, truncate: false)
          diagnostics_obj = LibDDWAF::Object.new

          LibDDWAF.ddwaf_builder_add_or_update_config(@builder_ptr, path, path_length, config_obj, diagnostics_obj)

          Converter.object_to_ruby(diagnostics_obj)
        ensure
          LibDDWAF.ddwaf_object_destroy(config_obj, allocator) if config_obj
          LibDDWAF.ddwaf_object_destroy(diagnostics_obj, allocator) if diagnostics_obj
        end

        # Removes a configuration from the WAF handle builder for the given path.
        #
        # @return [Boolean] true if the configuration was removed, false otherwise
        def remove_config_at_path(path)
          ensure_pointer_presence!
          raise ArgumentError, "Configuration path is reserved for the obfuscator" if path == OBFUSCATOR_CONFIG_PATH

          path_length = path.bytesize
          raise ArgumentError, "Configuration path exceeds the native length limit" if path_length > 0xffff_ffff

          LibDDWAF.ddwaf_builder_remove_config(@builder_ptr, path, path_length)
        end

        private

        def configure_obfuscator(obfuscator)
          settings = {
            key_regex: obfuscator[:key_regex],
            value_regex: obfuscator[:value_regex]
          }.reject { |_, pattern| pattern.nil? }

          allocator = LibDDWAF.ddwaf_get_default_allocator
          raise LibDDWAFError, "Could not obtain the native allocator" if allocator.null?

          config_obj = Converter.ruby_to_object({obfuscator: settings}, truncate: false)
          success = LibDDWAF.ddwaf_builder_add_or_update_config(
            @builder_ptr, OBFUSCATOR_CONFIG_PATH, OBFUSCATOR_CONFIG_PATH.bytesize, config_obj, nil
          )
          raise LibDDWAFError, "Could not configure obfuscator" unless success
        ensure
          LibDDWAF.ddwaf_object_destroy(config_obj, allocator) if config_obj
        end

        def ensure_pointer_presence!
          return if @builder_ptr

          raise InstanceFinalizedError, "Cannot use WAF handle builder after it has been finalized"
        end
      end
    end
  end
end
