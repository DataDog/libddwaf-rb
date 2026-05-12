# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby wrapper around `LibDDWAF::Handle`. Built from a HandleBuilder.
      # Use `#build_context` to obtain a request-scoped Context for running
      # the WAF.
      class Handle
        def initialize(native_handle)
          @handle = native_handle
        end

        # Destroys the underlying WAF handle. Instance is unusable afterwards.
        def finalize!
          return if @handle.nil?

          to_destroy, @handle = @handle, nil
          LibDDWAF.ddwaf_destroy(to_destroy)
        end

        # Builds a request-scoped WAF context.
        #
        # @raise [LibDDWAFError] if libddwaf could not create the context.
        # @return [Context]
        def build_context
          ensure_pointer_presence!

          native_context = LibDDWAF.ddwaf_context_init(@handle)
          raise LibDDWAFError, "Could not create context" if native_context.nil?

          Context.new(native_context)
        end

        # Returns the list of known input addresses that the loaded ruleset
        # references. Memoised on first call.
        #
        # @return [Array<String>]
        def known_addresses
          return @known_addresses if defined?(@known_addresses)

          ensure_pointer_presence!

          @known_addresses = LibDDWAF.ddwaf_known_addresses(@handle)
        end

        private

        def ensure_pointer_presence!
          return if @handle

          raise InstanceFinalizedError, "Cannot use WAF handle after it has been finalized"
        end
      end
    end
  end
end
