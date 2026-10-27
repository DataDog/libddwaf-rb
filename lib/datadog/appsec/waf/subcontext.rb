# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      class Subcontext
        def initialize(subcontext_ptr, limits:)
          @subcontext_ptr = subcontext_ptr
          @limits = limits
        end

        def finalize!
          Thread.handle_interrupt(::Object => :never) do
            pointer = @subcontext_ptr
            return unless pointer

            @subcontext_ptr = nil
            LibDDWAF.ddwaf_subcontext_destroy(pointer)
          end
        end
      end
    end
  end
end
