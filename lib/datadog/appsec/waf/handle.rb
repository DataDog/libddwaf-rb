# frozen_string_literal: true

module Datadog
  module AppSec
    module WAF
      # Ruby representation of the ddwaf_handle in libddwaf
      # See https://github.com/DataDog/libddwaf/blob/10e3a1dfc7bc9bb8ab11a09a9f8b6b339eaf3271/BINDING_IMPL_NOTES.md?plain=1#L4-L19
      class Handle
        attr_reader :handle_obj, :diagnostics, :config

        def initialize(rule, limits: {}, obfuscator: {})
          rule_obj = Converter.ruby_to_object(rule)
          if rule_obj.null? || rule_obj[:type] == :ddwaf_object_invalid
            raise LibDDWAF::Error, "Could not convert object #{rule.inspect}"
          end

          config_obj = Datadog::AppSec::WAF::LibDDWAF::Config.new
          if config_obj.null?
            raise LibDDWAF::Error, 'Could not create config struct'
          end

          config_obj[:limits][:max_container_size]  = limits[:max_container_size]  || LibDDWAF::DEFAULT_MAX_CONTAINER_SIZE
          config_obj[:limits][:max_container_depth] = limits[:max_container_depth] || LibDDWAF::DEFAULT_MAX_CONTAINER_DEPTH
          config_obj[:limits][:max_string_length]   = limits[:max_string_length]   || LibDDWAF::DEFAULT_MAX_STRING_LENGTH
          config_obj[:obfuscator][:key_regex]       = FFI::MemoryPointer.from_string(obfuscator[:key_regex])   if obfuscator[:key_regex]
          config_obj[:obfuscator][:value_regex]     = FFI::MemoryPointer.from_string(obfuscator[:value_regex]) if obfuscator[:value_regex]
          config_obj[:free_fn] = LibDDWAF::ObjectNoFree

          @config = config_obj

          diagnostics_obj = LibDDWAF::Object.new

          @handle_obj = LibDDWAF.ddwaf_init(rule_obj, config_obj, diagnostics_obj)

          @diagnostics = Converter.object_to_ruby(diagnostics_obj)

          if @handle_obj.null?
            raise LibDDWAF::Error.new('Could not create handle', diagnostics: @diagnostics)
          end

          validate!
        ensure
          LibDDWAF.ddwaf_object_free(diagnostics_obj) if diagnostics_obj
          LibDDWAF.ddwaf_object_free(rule_obj) if rule_obj
        end

        def finalize
          invalidate!

          LibDDWAF.ddwaf_destroy(handle_obj)
        end

        def required_addresses
          valid!

          count = LibDDWAF::UInt32Ptr.new
          list = LibDDWAF.ddwaf_known_addresses(handle_obj, count)

          return [] if count == 0 # list is null

          list.get_array_of_string(0, count[:value])
        end

        def merge(data)
          data_obj = Converter.ruby_to_object(data, coerce: false)
          diagnostics_obj = LibDDWAF::Object.new
          new_handle = LibDDWAF.ddwaf_update(handle_obj, data_obj, diagnostics_obj)

          return if new_handle.null?

          diagnostics = Converter.object_to_ruby(diagnostics_obj)
          new_from_handle(new_handle, diagnostics, config)
        ensure
          LibDDWAF.ddwaf_object_free(data_obj) if data_obj
          LibDDWAF.ddwaf_object_free(diagnostics_obj) if diagnostics_obj
        end

        private

        def new_from_handle(handle_object, diagnostics, config)
          obj = self.class.allocate
          obj.instance_variable_set(:@handle_obj, handle_object)
          obj.instance_variable_set(:@diagnostics, diagnostics)
          obj.instance_variable_set(:@config, config)
          obj
        end

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
      end
    end
  end
end
