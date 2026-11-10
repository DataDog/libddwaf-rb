# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
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
