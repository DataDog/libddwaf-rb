# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_context in libddwaf
      # See https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/BINDING_IMPL_NOTES.md?plain=1#L125-L158
      class Context
        RESULT_CODE = {
          ddwaf_ok: :ok,
          ddwaf_match: :match,
          ddwaf_err_internal: :err_internal,
          ddwaf_err_invalid_object: :err_invalid_object,
          ddwaf_err_invalid_argument: :err_invalid_argument
        }.freeze

        attr_reader :context_obj

        def initialize(handle)
          handle_obj = handle.handle_obj
          retain(handle)

          @context_obj = LibDDWAF.ddwaf_context_init(handle_obj)
          raise LibDDWAF::Error, 'Could not create context' if @context_obj.null?

          validate!
        end

        def finalize
          invalidate!

          retained.each do |retained_obj|
            next unless retained_obj.is_a?(LibDDWAF::Object)

            LibDDWAF.ddwaf_object_free(retained_obj)
          end

          retained.clear
          LibDDWAF.ddwaf_context_destroy(context_obj)
        end

        def run(persistent_data, ephemeral_data, timeout = LibDDWAF::DDWAF_RUN_TIMEOUT)
          valid!

          persistent_data_obj = Converter.ruby_to_object(
            persistent_data,
            max_container_size: LibDDWAF::DDWAF_MAX_CONTAINER_SIZE,
            max_container_depth: LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH,
            max_string_length: LibDDWAF::DDWAF_MAX_STRING_LENGTH,
            coerce: false
          )
          if persistent_data_obj.null?
            raise LibDDWAF::Error, "Could not convert persistent data: #{persistent_data.inspect}"
          end

          # retain C objects in memory for subsequent calls to run
          retain(persistent_data_obj)

          ephemeral_data_obj = Converter.ruby_to_object(
            ephemeral_data,
            max_container_size: LibDDWAF::DDWAF_MAX_CONTAINER_SIZE,
            max_container_depth: LibDDWAF::DDWAF_MAX_CONTAINER_DEPTH,
            max_string_length: LibDDWAF::DDWAF_MAX_STRING_LENGTH,
            coerce: false
          )
          if ephemeral_data_obj.null?
            raise LibDDWAF::Error, "Could not convert ephemeral data: #{ephemeral_data.inspect}"
          end

          result_obj = LibDDWAF::Result.new
          raise LibDDWAF::Error, 'Could not create result object' if result_obj.null?

          code = LibDDWAF.ddwaf_run(@context_obj, persistent_data_obj, ephemeral_data_obj, result_obj, timeout)

          result = Result.new(
            RESULT_CODE[code],
            Converter.object_to_ruby(result_obj[:events]),
            result_obj[:total_runtime],
            result_obj[:timeout],
            Converter.object_to_ruby(result_obj[:actions]),
            Converter.object_to_ruby(result_obj[:derivatives])
          )

          [RESULT_CODE[code], result]
        ensure
          LibDDWAF.ddwaf_result_free(result_obj) if result_obj
          LibDDWAF.ddwaf_object_free(ephemeral_data_obj) if ephemeral_data_obj
        end

        private

        # FIXME: Rename into something which reflect that it's impossible to run
        #        libddwaf on finalized context (closed)
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
