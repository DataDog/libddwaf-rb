# frozen_string_literal: true

require "libddwaf"
require "json"

builder = Datadog::AppSec::WAF::HandleBuilder.new

# LibDDWAFError is raised when no configuration was added to the builder.
begin
  builder.build_handle.finalize!
  raise "Expected building a handle without configuration to fail"
rescue Datadog::AppSec::WAF::LibDDWAFError
  nil
ensure
  builder.finalize!
end
