# frozen_string_literal: true

require "libddwaf"
require "json"

builder = Datadog::AppSec::WAF::HandleBuilder.new

# default config is usually loaded at application start
default_rules = JSON.parse(File.read("spec/fixtures/waf_rules.json"))
builder.add_or_update_config(default_rules, path: "APPSEC/DEFAULT")

# # default config has to be removed before adding config from Remote Configuration
builder.remove_config_at_path("APPSEC/DEFAULT")

# load config from Remote Configuration
config = JSON.parse(File.read("spec/fixtures/valid_config.json"))
builder.add_or_update_config(config, path: "APPSEC/RC_CONFIG")

builder.finalize!
