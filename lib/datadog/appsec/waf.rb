# frozen_string_literal: true

require 'datadog/appsec/waf/lib_ddwaf'

module Datadog
  module AppSec
    # The main module exposed outside
    # rubocop:disable Metrics/ModuleLength
    module WAF
      module_function

      def version
        LibDDWAF.ddwaf_get_version
      end

      def log_callback(level, func, file, line, message, len)
        return if logger.nil?

        logger.debug do
          {
            level: level,
            func: func,
            file: file,
            line: line,
            message: message.read_bytes(len)
          }.inspect
        end
      end

      def logger
        @logger
      end

      def logger=(logger)
        unless @log_callback
          log_callback = method(:log_callback)
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_set_log_cb(log_callback, :ddwaf_log_trace)

          # retain logging proc if set properly
          @log_callback = log_callback
        end

        @logger = logger
      end
    end
    # rubocop:enable Metrics/ModuleLength
  end
end

require 'datadog/appsec/waf/version'
require 'datadog/appsec/waf/handle'
require 'datadog/appsec/waf/result'
require 'datadog/appsec/waf/context'
