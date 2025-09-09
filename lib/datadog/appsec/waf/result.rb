# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_result of a libddwaf run.
      # See https://github.com/DataDog/libddwaf/blob/8dbee187ff74a0aa25e1bcbdde51677f77930e1b/include/ddwaf.h#L277-L290
      class Result
        attr_reader :status, :events, :actions, :derivatives, :total_runtime, :timeout

        def initialize(status, events, actions, derivatives, total_runtime, timeout)
          @status = status
          @events = events
          @actions = actions
          @derivatives = derivatives
          @total_runtime = total_runtime
          @timeout = timeout
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
            actions: @actions,
            derivatives: @derivatives,
            total_runtime: @total_runtime,
            timeout: @timeout,
            input_truncated: @input_truncated
          }
        end
      end
    end
  end
end
