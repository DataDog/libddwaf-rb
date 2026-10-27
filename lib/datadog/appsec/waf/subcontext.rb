# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      class Subcontext
        def initialize(subcontext_ptr, context:, limits:)
          @subcontext_ptr = subcontext_ptr
          @context = context
          @limits = limits
          @state = :active
        end

        def finalize!
          Thread.handle_interrupt(::Object => :never) do
            @state = :finalized
            pointer = @subcontext_ptr
            return unless pointer

            @subcontext_ptr = nil
            LibDDWAF.ddwaf_subcontext_destroy(pointer)
          end
        end

        def eval(data, timeout = LibDDWAF::DDWAF_RUN_TIMEOUT)
          ensure_active!
          raise TypeError, "WAF input must be a Hash" unless Hash === data

          allocator = LibDDWAF.ddwaf_get_default_allocator
          raise LibDDWAFError, "Could not obtain the native allocator" if allocator.null?

          Thread.handle_interrupt(::Object => :never) do
            input_obj = nil
            result_obj = nil
            input_transferred = false

            begin
              input_obj = Converter.ruby_to_object(data, limits: @limits, coerce: false)
              input_truncated = input_obj.truncated?
              result_obj = LibDDWAF::Object.new

              code = LibDDWAF.ddwaf_subcontext_eval(ensure_active!, input_obj, allocator, result_obj, timeout)
              # In libddwaf 2.0.0, only INVALID_ARGUMENT returns before input ownership transfers.
              input_transferred = code != :ddwaf_err_invalid_argument

              @context.mark_failed! if code == :ddwaf_err_internal

              if code == :ddwaf_err_internal || code == :ddwaf_err_invalid_argument
                @state = :failed
                pointer = @subcontext_ptr
                @subcontext_ptr = nil
                LibDDWAF.ddwaf_subcontext_destroy(pointer) if pointer
              end

              raw_result = if Context::SUCCESS_RESULT_CODES.include?(code)
                decoded = Converter.object_to_ruby(result_obj)
                raise ConversionError, "Could not convert result into object: #{code}" unless decoded.is_a?(Hash)

                decoded #: as untyped
              else
                Context::EMPTY_RESULT
              end

              result = Result.new(
                status: Context::RESULT_CODE_TO_STATUS.fetch(code),
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

        private

        def ensure_active!
          case @state
          when :failed
            raise LibDDWAFError, "Cannot use WAF subcontext after a native error"
          when :finalized
            raise InstanceFinalizedError, "Cannot use WAF subcontext after it has been finalized"
          end

          raise LibDDWAFError, "Cannot use WAF subcontext after a native error" if @context.failed?

          @subcontext_ptr || raise(LibDDWAFError, "WAF subcontext pointer is missing")
        end
      end
    end
  end
end
