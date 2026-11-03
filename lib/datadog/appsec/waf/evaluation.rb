# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Internal evaluation conversion, ownership and result handling for both native adapters.
      module Evaluation
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

        module_function

        def call(data)
          allocator = LibDDWAF.ddwaf_get_default_allocator
          raise LibDDWAFError, "Could not obtain the native allocator" if allocator.null?

          Thread.handle_interrupt(::Object => :never) do
            input_obj = nil
            result_obj = nil
            input_transferred = false

            begin
              input_obj = Converter.ruby_to_object(data)
              input_truncated = input_obj.truncated?
              result_obj = LibDDWAF::Object.new

              code = yield input_obj, allocator, result_obj
              # only INVALID_ARGUMENT returns before input ownership transfers.
              input_transferred = code != :ddwaf_err_invalid_argument

              raw_result = if SUCCESS_RESULT_CODES.include?(code)
                decoded = Converter.object_to_ruby(result_obj)
                raise ConversionError, "Could not convert result into object: #{code}" unless decoded.is_a?(Hash)

                decoded #: as untyped
              else
                EMPTY_RESULT
              end

              result = Result.new(
                status: RESULT_CODE_TO_STATUS.fetch(code),
                events: raw_result["events"],
                actions: raw_result["actions"],
                attributes: raw_result["attributes"],
                duration: raw_result["duration"],
                timeout: raw_result["timeout"],
                keep: raw_result["keep"]
              )
              result.mark_input_truncated! if input_truncated
              result
            ensure
              LibDDWAF.ddwaf_object_destroy(result_obj, allocator) if result_obj
              LibDDWAF.ddwaf_object_destroy(input_obj, allocator) if input_obj && !input_transferred
            end
          end
        end
      end
    end
  end
end
