# frozen_string_literal: true

require "libddwaf_native"

require "datadog/appsec/waf/handle_builder"
require "datadog/appsec/waf/handle"
require "datadog/appsec/waf/converter"
require "datadog/appsec/waf/errors"
require "datadog/appsec/waf/result"
require "datadog/appsec/waf/context"
require "datadog/appsec/waf/version"

module Datadog
  module AppSec
    module WAF
      module_function

      def version
        LibDDWAF.ddwaf_get_version
      end

      def logger
        @logger
      end

      # Sets the application-side logger. NOTE: libddwaf's internal
      # `ddwaf_set_log_cb` integration is not yet wired in the C extension —
      # this currently only sets the Ruby-side `@logger` reference; libddwaf
      # internal log messages are not forwarded here.
      def logger=(logger)
        @logger = logger
      end
    end
  end
end
