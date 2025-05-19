# frozen_string_literal: true

require "libddwaf"
require "json"

builder = Datadog::AppSec::WAF::HandleBuilder.new

# LibDDWAFError is raised when no configuration was added to the builder.
begin
  builder.build_handle
rescue Datadog::AppSec::WAF::LibDDWAFError
end

builder.finalize!
