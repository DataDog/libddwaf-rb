# frozen_string_literal: true

require "spec_helper"
require "open3"

RSpec.describe "Memory leaks", memory_leaks: true do
  %w[
    full_waf_run.rb
    add_remote_config.rb
    handle_known_addresses.rb
  ].each do |scenario_file|
    it "does not detect memory leaks in #{scenario_file}" do
      _, stderr, status = Open3.capture3("ruby_memcheck -I lib spec/memory_leak_scenarios/#{scenario_file}")

      expect(status).to be_success,
        "Expected no memory leaks in #{scenario_file}.\n\nValgrind output:\n#{stderr}"
    end
  end
end
