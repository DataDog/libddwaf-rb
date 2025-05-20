# frozen_string_literal: true

require "libddwaf"
require "json"

# string
str_object = Datadog::AppSec::WAF::Converter.ruby_to_object("foo")
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(str_object)

# integer
int_object = Datadog::AppSec::WAF::Converter.ruby_to_object(12)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(int_object)

# float
float_object = Datadog::AppSec::WAF::Converter.ruby_to_object(12.2)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(float_object)

# boolean that gets converted to a string
bool_object = Datadog::AppSec::WAF::Converter.ruby_to_object(true)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(bool_object)

# boolean that gets converted to a boolean
bool_object = Datadog::AppSec::WAF::Converter.ruby_to_object(true, coerce: false)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(bool_object)

# nil that gets converted to an empty string
nil_object = Datadog::AppSec::WAF::Converter.ruby_to_object(nil)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(nil_object)

# nil that gets converted to a null object
nil_object = Datadog::AppSec::WAF::Converter.ruby_to_object(nil, coerce: false)
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(nil_object)

# simple array
arr_object = Datadog::AppSec::WAF::Converter.ruby_to_object(%w[foo bar baz])
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(arr_object)

# nested array
arr_object = Datadog::AppSec::WAF::Converter.ruby_to_object([%w[foo bar baz], [1, 2, 3]])
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(arr_object)

# flat map
map_object = Datadog::AppSec::WAF::Converter.ruby_to_object({foo: "bar", baz: "qux"})
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(map_object)

# nested map
map_object = Datadog::AppSec::WAF::Converter.ruby_to_object({foo: "bar", baz: {banana: true}, qux: [1, 2, 3]})
Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_free(map_object)
