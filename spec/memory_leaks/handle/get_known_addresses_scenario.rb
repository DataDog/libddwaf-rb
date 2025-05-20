# frozen_string_literal: true

require "libddwaf"
require "json"

builder = Datadog::AppSec::WAF::HandleBuilder.new

config = JSON.parse(File.read("spec/fixtures/waf_rules.json"))
builder.add_or_update_config(config, path: "APPSEC/DEFAULT")

handle = builder.build_handle
handle.known_addresses

handle.finalize!
builder.finalize!
