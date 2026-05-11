# frozen_string_literal: true

require "libddwaf"
require "json"

# Exercise every Converter shape. LibDDWAF::Object cleans up its ddwaf_object
# payload via TypedData dfree on GC — no explicit free is needed at the call
# sites the way the FFI binding required.
Datadog::AppSec::WAF::Converter.ruby_to_object("foo", coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object(12, coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object(12.2, coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object(true, coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object(true, coerce: false)
Datadog::AppSec::WAF::Converter.ruby_to_object(nil, coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object(nil, coerce: false)
Datadog::AppSec::WAF::Converter.ruby_to_object(%w[foo bar baz], coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object([%w[foo bar baz], [1, 2, 3]], coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object({foo: "bar", baz: "qux"}, coerce: true)
Datadog::AppSec::WAF::Converter.ruby_to_object({foo: "bar", baz: {banana: true}, qux: [1, 2, 3]}, coerce: true)

# Force a GC sweep so any retained payloads are visible to the leak detector.
GC.start
