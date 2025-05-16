require "libddwaf"
require "json"

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
