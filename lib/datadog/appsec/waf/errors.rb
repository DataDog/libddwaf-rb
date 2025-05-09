module Datadog
  module AppSec
    module WAF
      class Error < StandardError
      end

      class InstanceFinalizedError < Error
      end

      # The reason for such specific error classes is that we don't
      # send error message via telemetry, only the error class
      class HandleBuilderFinalizedError < InstanceFinalizedError
      end

      class HandleFinalizedError < InstanceFinalizedError
      end

      class ContextFinalizedError < InstanceFinalizedError
      end

      class ConversionError < Error
      end

      class LibDDWAFError < Error
        attr_reader :diagnostics

        def initialize(msg, diagnostics: nil)
          @diagnostics = diagnostics

          super(msg)
        end
      end
    end
  end
end
