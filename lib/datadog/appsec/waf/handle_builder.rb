# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby wrapper around `LibDDWAF::Builder`. Builds WAF handles from one or
      # more configuration documents (rulesets, exclusions, etc.); handles
      # config merging for Remote Configuration.
      class HandleBuilder
        def initialize(limits: {}, obfuscator: {})
          config = {
            limits: {
              max_container_size: limits[:max_container_size] || LibDDWAF::DEFAULT_MAX_CONTAINER_SIZE,
              max_container_depth: limits[:max_container_depth] || LibDDWAF::DEFAULT_MAX_CONTAINER_DEPTH,
              max_string_length: limits[:max_string_length] || LibDDWAF::DEFAULT_MAX_STRING_LENGTH,
            },
            obfuscator: {
              key_regex: obfuscator[:key_regex],
              value_regex: obfuscator[:value_regex],
            },
          }

          @builder = LibDDWAF.ddwaf_builder_init(config)
          raise LibDDWAFError, "Could not create builder" if @builder.nil?
        end

        # Destroys the WAF builder. Instance is unusable afterwards.
        def finalize!
          return if @builder.nil?

          to_destroy, @builder = @builder, nil
          LibDDWAF.ddwaf_builder_destroy(to_destroy)
        end

        # Builds a WAF handle from the builder's current state.
        #
        # @raise [LibDDWAFError] if no rules were added before the build call.
        # @return [Handle]
        def build_handle
          ensure_pointer_presence!

          native_handle = LibDDWAF.ddwaf_builder_build_instance(@builder)
          raise LibDDWAFError, "Could not create handle" if native_handle.nil?

          Handle.new(native_handle)
        end

        # :section: Configuration management methods

        # Adds or updates a configuration at the given path. Returns the
        # diagnostics from libddwaf as a Ruby Hash.
        def add_or_update_config(config, path:)
          ensure_pointer_presence!

          config_obj = Converter.ruby_to_object(config, coerce: false)
          diagnostics_obj = LibDDWAF::Object.new

          LibDDWAF.ddwaf_builder_add_or_update_config(@builder, path, config_obj, diagnostics_obj)
          Converter.object_to_ruby(diagnostics_obj)
        end

        # Removes the configuration at the given path. Returns true if
        # the path was known and removed, false otherwise.
        def remove_config_at_path(path)
          ensure_pointer_presence!

          LibDDWAF.ddwaf_builder_remove_config(@builder, path)
        end

        private

        def ensure_pointer_presence!
          return if @builder

          raise InstanceFinalizedError, "Cannot use WAF handle builder after it has been finalized"
        end
      end
    end
  end
end
