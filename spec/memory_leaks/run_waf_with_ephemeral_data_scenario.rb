# frozen_string_literal: true

require "libddwaf"
require "json"

builder = Datadog::AppSec::WAF::HandleBuilder.new

config = JSON.parse(File.read("spec/fixtures/valid_config.json"))
builder.add_or_update_config(config, path: "APPSEC/RC_CONFIG")

handle = builder.build_handle
context = handle.build_context

context.run({}, {"server.db.statement" => "SELECT * from users where id = 'foo';delete from users;--'"})

context.finalize!
handle.finalize!
builder.finalize!
