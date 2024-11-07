require 'pry'

require 'datadog/appsec/waf'

require_relative 'support/barrier'

RSpec.configure do |config|
  config.default_formatter = 'doc'
end
