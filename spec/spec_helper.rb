require 'pry'

require 'datadog/appsec/waf'

require_relative 'support/barrier'

RSpec.configure do |config|
  config.default_formatter = 'doc'
  config.filter_run_excluding stress_tests: true
end
