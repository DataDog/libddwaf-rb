# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby wrapper around `LibDDWAF::Context`. Request-scoped. Holds persistent
      # input objects alive (libddwaf stores pointers into them) until the
      # context is destroyed.
      class Context
        EMPTY_RESULT = {
          "events" => [],     #: WAF::events
          "actions" => {},    #: WAF::actions
          "attributes" => {}, #: WAF::attributes
          "duration" => 0,
          "timeout" => false,
          "keep" => false
        }.freeze
        SUCCESS_RESULT_CODES = %i[ddwaf_ok ddwaf_match].freeze
        RESULT_CODE_TO_STATUS = {
          ddwaf_ok: :ok,
          ddwaf_match: :match,
          ddwaf_err_internal: :err_internal,
          ddwaf_err_invalid_object: :err_invalid_object,
          ddwaf_err_invalid_argument: :err_invalid_argument
        }.freeze

        def initialize(native_context)
          @context = native_context
          @retained = []
        end

        # Destroys the WAF context. Instance is unusable afterwards.
        def finalize!
          return if @context.nil?

          to_destroy, @context = @context, nil
          @retained.clear
          LibDDWAF.ddwaf_context_destroy(to_destroy)
        end

        # Runs the WAF against the given input data.
        #
        # @raise [ConversionError] if the conversion of persistent or ephemeral data fails.
        # @raise [LibDDWAFError] if libddwaf could not produce a result.
        # @return [Result]
        def run(persistent_data, ephemeral_data, timeout = LibDDWAF::DDWAF_RUN_TIMEOUT)
          ensure_pointer_presence!

          persistent_obj = Converter.ruby_to_object(
            persistent_data,
            max_container_size: LibDDWAF::DDWAF_MAX_CONTAINER_SIZE,
            max_container_depth: LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH,
            max_string_length: LibDDWAF::DDWAF_MAX_STRING_LENGTH,
            coerce: false
          )
          # libddwaf stores pointers into persistent_obj for the lifetime of
          # the context — retain so Ruby GC doesn't free the payload before
          # the context is destroyed.
          @retained << persistent_obj

          ephemeral_obj = Converter.ruby_to_object(
            ephemeral_data,
            max_container_size: LibDDWAF::DDWAF_MAX_CONTAINER_SIZE,
            max_container_depth: LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH,
            max_string_length: LibDDWAF::DDWAF_MAX_STRING_LENGTH,
            coerce: false
          )

          result_obj = LibDDWAF::Object.new
          code = LibDDWAF.ddwaf_run(@context, persistent_obj, ephemeral_obj, result_obj, timeout)
          result = Converter.object_to_ruby(result_obj)

          # On error, libddwaf doesn't populate the result; the conversion
          # returns nil. That's not a conversion failure — fall through to
          # EMPTY_RESULT below.
          if SUCCESS_RESULT_CODES.include?(code) && result.nil?
            raise ConversionError, "Could not convert result into object: #{code}"
          end

          result ||= EMPTY_RESULT
          result = Result.new(
            status: RESULT_CODE_TO_STATUS[code],
            events: result["events"],
            actions: result["actions"],
            attributes: result["attributes"],
            duration: result["duration"],
            timeout: result["timeout"],
            keep: result["keep"]
          )

          if persistent_obj.truncated? || ephemeral_obj.truncated?
            result.mark_input_truncated!
          end

          result
        end

        private

        def ensure_pointer_presence!
          return if @context

          raise InstanceFinalizedError, "Cannot use WAF context after it has been finalized"
        end
      end
    end
  end
end
