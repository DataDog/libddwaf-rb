# frozen_string_literal: true

require "libddwaf"
require "json"

allocator = Datadog::AppSec::WAF::LibDDWAF.ddwaf_get_default_allocator

# string
str_object = Datadog::AppSec::WAF::Converter.ruby_to_object("foo")
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(str_object, allocator)

# integer
int_object = Datadog::AppSec::WAF::Converter.ruby_to_object(12)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(int_object, allocator)

# float
float_object = Datadog::AppSec::WAF::Converter.ruby_to_object(12.2)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(float_object, allocator)

# boolean that gets converted to a string
bool_object = Datadog::AppSec::WAF::Converter.ruby_to_object(true)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(bool_object, allocator)

# boolean that gets converted to a boolean
bool_object = Datadog::AppSec::WAF::Converter.ruby_to_object(true, coerce: false)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(bool_object, allocator)

# nil that gets converted to an empty string
nil_object = Datadog::AppSec::WAF::Converter.ruby_to_object(nil)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(nil_object, allocator)

# nil that gets converted to a null object
nil_object = Datadog::AppSec::WAF::Converter.ruby_to_object(nil, coerce: false)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(nil_object, allocator)

# simple array
arr_object = Datadog::AppSec::WAF::Converter.ruby_to_object(%w[foo bar baz])
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(arr_object, allocator)

# nested array
arr_object = Datadog::AppSec::WAF::Converter.ruby_to_object([%w[foo bar baz], [1, 2, 3]])
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(arr_object, allocator)

# flat map
map_object = Datadog::AppSec::WAF::Converter.ruby_to_object({foo: "bar", baz: "qux"})
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(map_object, allocator)

# nested map
map_object = Datadog::AppSec::WAF::Converter.ruby_to_object({foo: "bar", baz: {banana: true}, qux: [1, 2, 3]})
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(map_object, allocator)
