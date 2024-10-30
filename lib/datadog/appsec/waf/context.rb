module Datadog
  module AppSec
    module WAF
      # Ruby
      class Context
        attr_reader :context_obj

        def initialize(handle)
          handle_obj = handle.handle_obj
          retain(handle)

          @context_obj = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle_obj)
          raise LibDDWAF::Error, 'Could not create context' if @context_obj.null?

          validate!
        end

        def finalize
          invalidate!

          retained.each do |retained_obj|
            next unless retained_obj.is_a?(Datadog::AppSec::WAF::LibDDWAF::Object)

            Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(retained_obj)
          end

          Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_destroy(context_obj)
        end

        def run(persistent_data, ephemeral_data, timeout = LibDDWAF::DDWAF_RUN_TIMEOUT)
          valid!

          persistent_data_obj = Datadog::AppSec::WAF.ruby_to_object(
            persistent_data,
            max_container_size: LibDDWAF::DDWAF_MAX_CONTAINER_SIZE,
            max_container_depth: LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH,
            max_string_length: LibDDWAF::DDWAF_MAX_STRING_LENGTH,
            coerce: false
          )
          raise LibDDWAF::Error, "Could not convert persistent data: #{persistent_data.inspect}" if persistent_data_obj.null?

          # retain C objects in memory for subsequent calls to run
          retain(persistent_data_obj)

          ephemeral_data_obj = Datadog::AppSec::WAF.ruby_to_object(
            ephemeral_data,
            max_container_size: LibDDWAF::DDWAF_MAX_CONTAINER_SIZE,
            max_container_depth: LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH,
            max_string_length: LibDDWAF::DDWAF_MAX_STRING_LENGTH,
            coerce: false
          )
          raise LibDDWAF::Error, "Could not convert ephemeral data: #{ephemeral_data.inspect}" if ephemeral_data_obj.null?

          result_obj = Datadog::AppSec::WAF::LibDDWAF::Result.new
          raise LibDDWAF::Error, 'Could not create result object' if result_obj.null?

          code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(@context_obj, persistent_data_obj, ephemeral_data_obj, result_obj, timeout)

          result = Result.new(
            RESULT_CODE[code],
            Datadog::AppSec::WAF.object_to_ruby(result_obj[:events]),
            result_obj[:total_runtime],
            result_obj[:timeout],
            Datadog::AppSec::WAF.object_to_ruby(result_obj[:actions]),
            Datadog::AppSec::WAF.object_to_ruby(result_obj[:derivatives])
          )

          [RESULT_CODE[code], result]
        ensure
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_result_free(result_obj) if result_obj
        end

        private

        def validate!
          @valid = true
        end

        def invalidate!
          @valid = false
        end

        def valid?
          @valid
        end

        def valid!
          return if valid?

          raise LibDDWAF::Error, "Attempt to use an invalid instance: #{inspect}"
        end

        def retained
          @retained ||= []
        end

        def retain(object)
          retained << object
        end

        def release(object)
          retained.delete(object)
        end
      end
    end
  end
end
