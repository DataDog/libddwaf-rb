# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_result of a libddwaf run.
      # See https://github.com/DataDog/libddwaf/blob/8dbee187ff74a0aa25e1bcbdde51677f77930e1b/include/ddwaf.h#L277-L290
      class Result
        attr_reader :status, :events, :actions, :attributes, :duration

        def initialize(status:, events:, actions:, attributes:, duration:, timeout:, keep:)
          @status = status
          @events = events
          @actions = actions
          @attributes = attributes
          @duration = duration

          @keep = !!keep
          @timeout = !!timeout
          @input_truncated = false
        end

        def mark_input_truncated!
          @input_truncated = true
        end

        def timeout?
          @timeout
        end

        def keep?
          @keep
        end

        def input_truncated?
          @input_truncated
        end

        def to_h
          {
            status: @status,
            events: @events,
            actions: @actions,
            attributes: @attributes,
            duration: @duration,
            keep: @keep,
            timeout: @timeout,
            input_truncated: @input_truncated
          }
        end
      end
    end
  end
end
