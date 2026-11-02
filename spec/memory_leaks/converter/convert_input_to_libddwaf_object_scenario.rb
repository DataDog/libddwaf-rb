# frozen_string_literal: true

require "libddwaf"

converter = Datadog::AppSec::WAF::Converter
allocator = Datadog::AppSec::WAF::LibDDWAF.ddwaf_get_default_allocator

deep_value = "leaf"
(converter::MAX_CONTAINER_DEPTH + 1).times { deep_value = [deep_value] }
input = {
  "body" => {"é" * (converter::MAX_STRING_LENGTH + 1) => "😀" * (converter::MAX_STRING_LENGTH + 1)},
  "array" => Array.new(converter::MAX_CONTAINER_SIZE + 1, "value"),
  "depth" => deep_value
}

object = converter.ruby_to_object(input)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator)

begin
  object = converter.ruby_to_object(input.merge("invalid" => Datadog::AppSec::WAF::JSONString.new("{")))
  Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator)
  raise "Expected invalid JSON to fail conversion"
rescue Datadog::AppSec::WAF::ConversionError
  nil
end
