# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the result of adding or updating a configuration in the WAF handle builder.
      class ConfigurationResult
        attr_reader :diagnostics

        def initialize(success:, diagnostics:)
          @success = success
          @diagnostics = diagnostics
        end

        def success?
          @success
        end
      end
    end
  end
end
