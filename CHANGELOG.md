# 2023-03-03 v1.8.2.0.0

- Update to libddwaf 1.8.2
- Added Waf::Handle#merge method
- Remove Waf::Handle#update_rule_data and Waf::Handle#toggle_rules methods
- Remove WAF::LibDDWAF.ddwaf_required_rule_data_ids method

# 2023-02-03 v1.7.0.0.0

- Update to libddwaf 1.7.0

# 2023-02-03 v1.6.2.0.0

- Update to libddwaf 1.6.2
- Add specs for the getter functions

# 2023-02-01 v1.5.1.0.1

- Fix incorrect size in input string limit
- Fix object freeing on `update_rule_data` and `toggle_rules`

# 2022-10-04 v1.5.1.0.0

- Update to libddwaf 1.5.1
- Add live rule data update API
- Add live rule toggle API
- Add libddwaf boolean type support
- Add Ruby to libddwaf object conversion limits
- Add Ruby to libddwaf object converter optional coercion of scalars to string
- Add static type checking via RBS+Steep
- Change version to return a string
- Change free function to be passed as config instead of context init argument
- Change result to include action list
- Change return code from action to status
- Change handle and context freeing model from GC-based to explicit
- Fix double-free upon finalization of retained C objects
- Fix context crash by retaining necessary C objects

# 2022-05-20 v1.3.0.2.0

- Fix multibyte string handling
- Support JRuby

# 2022-04-29 v1.3.0.1.0

Promotion of v1.3.0.1.0.beta1 to stable

# 2022-04-25 v1.3.0.1.0.beta1

- Add obfuscator configuration
- Add nested object limit configuration
- Add report ruleset information

# 2022-04-29 v1.3.0.0.0

- Promote v1.3.0.0.0.beta1 to stable

# 2022-04-20 v1.3.0.0.0.beta1

- Update to libddwaf 1.3.0

# 2022-03-18 v1.2.1.0.0.beta1

- Update to libddwaf 1.2.1
- Fix incorrect types for a few binding functions

# 2022-03-04 v1.0.14.2.1.beta1

- Fix incorrect return code
- Fix passing nil in libddwaf object containers

# 2022-02-07 v1.0.14.2.0.beta1

- Change Datadog::Security to Datadog::AppSec

# 2022-02-01 v1.0.14.1.0.beta2

- Add support for Ruby 3.1

# 2021-12-14 v1.0.14.1.0.beta1

- Fix sequential runs on a single context by retaining C input data objects

# 2021-11-24 v1.0.14.0.0.beta1

- Update to libddwaf 1.0.14

# 2021-11-24 v1.0.13.0.0.beta1

- Add ruby platform fallback for unsupported platforms
- Update to libddwaf 1.0.13

# 2021-10-13 v1.0.12.0.0.beta1

- Initial release
