# frozen_string_literal: true

require "spec_helper"
require "open3"

RSpec.describe "Memory leaks", memory_leaks: true do
  Dir.glob("spec/memory_leaks/**/*_scenario.rb").each do |scenario_file|
    it "does not detect memory leaks in #{scenario_file}" do
      _, stderr, status = Open3.capture3("ruby_memcheck -I lib #{scenario_file}")

      expect(status).to be_success,
        "Expected no memory leaks when running #{scenario_file}.\n\nValgrind output:\n#{stderr}"
    end
  end
end
