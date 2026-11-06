# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      class Subcontext
        def initialize(subcontext_ptr, context:)
          @subcontext_ptr = subcontext_ptr
          @context = context
        end

        def finalize!
          Thread.handle_interrupt(::Object => :never) do
            pointer = @subcontext_ptr
            return unless pointer

            @subcontext_ptr = nil
            LibDDWAF.ddwaf_subcontext_destroy(pointer)
          end
        end

        def eval(data, timeout = LibDDWAF::DDWAF_RUN_TIMEOUT)
          ensure_pointer_presence!

          Evaluation.call(data) do |input_obj, allocator, result_obj|
            LibDDWAF.ddwaf_subcontext_eval(
              @subcontext_ptr, #: ::FFI::Pointer
              input_obj, allocator, result_obj, timeout
            )
          end
        end

        private

        def ensure_pointer_presence!
          return if @subcontext_ptr

          raise InstanceFinalizedError, "Cannot use WAF subcontext after it has been finalized"
        end
      end
    end
  end
end
