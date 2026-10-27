# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_context in libddwaf
      # See https://github.com/DataDog/libddwaf/blob/2.0.0/src/interface.cpp
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

        def initialize(context_ptr, limits:)
          @context_ptr = context_ptr
          @limits = limits
          @state = :active
          @failed = false
        end

        def failed?
          @failed
        end

        def mark_failed!
          @failed = true
        end

        def finalize!
          Thread.handle_interrupt(::Object => :never) do
            @state = :finalized
            destroy_context!
          end
        end

        def build_subcontext
          subcontext = nil #: Subcontext?
          caller_owned = false

          begin
            subcontext = Thread.handle_interrupt(::Object => :never) do
              pointer = LibDDWAF.ddwaf_subcontext_init(ensure_active!)
              raise LibDDWAFError, "Could not create subcontext" if pointer.null?

              begin
                subcontext = Subcontext.new(pointer, context: self, limits: @limits)
              ensure
                LibDDWAF.ddwaf_subcontext_destroy(pointer) unless subcontext
              end
            end

            if block_given?
              yield subcontext
            else
              caller_owned = true
              subcontext
            end
          ensure
            subcontext&.finalize! unless caller_owned
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

              code = LibDDWAF.ddwaf_context_eval(ensure_active!, input_obj, allocator, result_obj, timeout)
              # In libddwaf 2.0.0, only INVALID_ARGUMENT returns before input ownership transfers.
              input_transferred = code != :ddwaf_err_invalid_argument

              mark_failed! if code == :ddwaf_err_internal

              if code == :ddwaf_err_internal || code == :ddwaf_err_invalid_argument
                @state = :failed
                destroy_context!
              end

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

        private

        def ensure_active!
          case @state
          when :failed
            raise LibDDWAFError, "Cannot use WAF context after a native error"
          when :finalized
            raise InstanceFinalizedError, "Cannot use WAF context after it has been finalized"
          end

          raise LibDDWAFError, "Cannot use WAF context after a native error" if failed?

          @context_ptr || raise(LibDDWAFError, "WAF context pointer is missing")
        end

        def destroy_context!
          pointer = @context_ptr
          return unless pointer

          @context_ptr = nil
          LibDDWAF.ddwaf_context_destroy(pointer)
        end
      end
    end
  end
end
