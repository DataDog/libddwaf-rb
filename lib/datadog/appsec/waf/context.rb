# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_context in libddwaf
      # See https://github.com/DataDog/libddwaf/blob/2.0.0/src/interface.cpp
      class Context
        def initialize(context_ptr)
          @context_ptr = context_ptr
        end

        def finalize!
          Thread.handle_interrupt(::Object => :never) do
            pointer = @context_ptr
            return unless pointer

            @context_ptr = nil
            LibDDWAF.ddwaf_context_destroy(pointer)
          end
        end

        def build_subcontext
          subcontext = nil #: Subcontext?
          caller_owned = false

          begin
            subcontext = Thread.handle_interrupt(::Object => :never) do
              ensure_pointer_presence!

              pointer = LibDDWAF.ddwaf_subcontext_init(@context_ptr)
              raise LibDDWAFError, "Could not create subcontext" if pointer.null?

              begin
                subcontext = Subcontext.new(pointer, context: self)
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
          ensure_pointer_presence!

          Evaluation.call(data) do |input_obj, allocator, result_obj|
            LibDDWAF.ddwaf_context_eval(
              @context_ptr, #: ::FFI::Pointer
              input_obj, allocator, result_obj, timeout
            )
          end
        end

        private

        def ensure_pointer_presence!
          return if @context_ptr

          raise InstanceFinalizedError, "Cannot use WAF context after it has been finalized"
        end
      end
    end
  end
end
