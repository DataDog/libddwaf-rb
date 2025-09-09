# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_result of a libddwaf run.
      # See https://github.com/DataDog/libddwaf/blob/8dbee187ff74a0aa25e1bcbdde51677f77930e1b/include/ddwaf.h#L277-L290
      class Result
        attr_reader :status, :events, :total_runtime, :timeout, :actions, :derivatives

        def initialize(status, events, total_runtime, timeout, actions, derivatives)
          @status = status
          @events = events
          @total_runtime = total_runtime
          @timeout = timeout
          @actions = actions
          @derivatives = derivatives
          @input_truncated = false
        end

        def mark_input_truncated!
          @input_truncated = true
        end

        def input_truncated?
          @input_truncated
        end

        def to_h
          {
            status: @status,
            events: @events,
            total_runtime: @total_runtime,
            timeout: @timeout,
            actions: @actions,
            derivatives: @derivatives
          }
        end
      end
    end
  end
end
