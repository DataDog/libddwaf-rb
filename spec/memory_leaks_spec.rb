# frozen_string_literal: true

require "spec_helper"
require "open3"
require "stringio"

RSpec.describe "Memory leaks", memory_leaks: true do
  Dir.glob("spec/memory_leaks/**/*_scenario.rb").each do |scenario_file|
    it "does not detect memory leaks in #{scenario_file}" do
      require "ruby_memcheck"

      string_io = StringIO.new

      ruby_memcheck_config = RubyMemcheck::Configuration.new(
        output_io: string_io,
        valgrind_generate_suppressions: true,
        valgrind_options: [
          "--num-callers=50",
          "--error-limit=no",
          "--trace-children=yes",
          "--undef-value-errors=no",
          "--leak-check=full",
          "--show-leak-kinds=definite",
          "--keep-debuginfo=yes",
          "--read-inline-info=yes",
          "--read-var-info=yes",
          "--suppressions=suppressions/re2.supp"
        ]
      )

      runner = RubyMemcheck::RubyRunner.new(ruby_memcheck_config)

      begin
        status = runner.run("-I", "lib", scenario_file)
      rescue RuntimeError
        fail("Expected no memory leaks when running #{scenario_file}.\n\nValgrind output:\n#{string_io.string}")
      end
    end
  end
end
