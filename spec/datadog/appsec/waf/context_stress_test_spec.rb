# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Context, stress_tests: true do
  let(:rule) do
    {
      "version" => "2.2",
      "metadata" => {
        "rules_version" => "1.2.3"
      },
      "rules" => [
        {
          "id" => "1",
          "name" => "Rule 1",
          "tags" => {"type" => "flow1"},
          "conditions" => [
            {
              "operator" => "match_regex",
              "parameters" => {"inputs" => [{"address" => "value2"}], "regex" => "rule1"}
            }
          ],
          "action" => "record"
        }
      ]
    }
  end

  let(:passing_input) do
    {value1: [4242, "randomString"], value2: ["nope"]}
  end

  let(:matching_input) do
    {value1: [4242, "randomString"], value2: ["rule1"]}
  end

  let(:builder) do
    Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
      builder.add_or_update_config(rule, path: "some/path")
    end
  end

  let(:handle) { builder.build_handle }

  context "stress testing" do
    let(:run_count) { 500 }
    let(:thread_count) { 200 }

    it "creates a context in each thread" do
      handle

      result = {timeout_ok: 0, timeout_match: 0, ok: 0, match: 0, err_internal: 0, err_invalid_object: 0, err_invalid_argument: 0}
      start_barrier = Barrier.new(thread_count)
      mutex = Mutex.new

      threads = thread_count.times.map do
        Thread.new do
          context = handle.build_context
          start_barrier.sync
          run_count.times do |i|
            ephemeral_data = i.even? ? matching_input : passing_input
            ephemeral_data[:value3] = [i]
            waf_result = context.run({}, ephemeral_data, 10_000_000)
            mutex.synchronize do
              if waf_result.timeout
                if i.even?
                  result[:timeout_match] += 1
                else
                  result[:timeout_ok] += 1
                end
              else
                result[waf_result.status] += 1
              end
            end
          end
        end
      end

      threads.each(&:join)

      expect(result[:err_internal]).to eq 0
      expect(result[:err_invalid_object]).to eq 0
      expect(result[:err_invalid_argument]).to eq 0
      expect(result[:match]).to eq(50_000 - result[:timeout_match])
      expect(result[:ok]).to eq(50_000 - result[:timeout_ok])
    end
  end
end
