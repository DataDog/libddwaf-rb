require "pry"
require "json"

require "datadog/appsec/waf"

require_relative "support/barrier"

RSpec.configure do |config|
  config.default_formatter = "doc"
  config.filter_run_excluding stress_tests: true, memory_leaks: true

  # RSpec prints the seed; rerun a failing order with `--seed <seed>`.
  config.order = :random
  Kernel.srand config.seed

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
end
