# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Evaluation do
  let(:config) do
    {
      "version" => "2.2",
      "rules_compat" => [{
        "id" => "evaluation", "name" => "Evaluation", "tags" => {"type" => "test"},
        "conditions" => [{
          "operator" => "match_regex",
          "parameters" => {"inputs" => [{"address" => "value"}], "regex" => "attack"}
        }],
        "on_match" => ["evaluation-block"],
        "output" => {
          "event" => true, "keep" => true,
          "attributes" => {
            "matched.value" => {"address" => "value"},
            "matched.count" => {"value" => 42}
          }
        }
      }],
      "actions" => [{
        "id" => "evaluation-block", "type" => "block_request",
        "parameters" => {"status_code" => "418", "grpc_status_code" => "42", "type" => "json"}
      }]
    }
  end

  around do |example|
    allocator = Datadog::AppSec::WAF::LibDDWAF.ddwaf_get_default_allocator
    builder_ptr = Datadog::AppSec::WAF::LibDDWAF.ddwaf_builder_init
    config_obj = Datadog::AppSec::WAF::Converter.ruby_to_object(config, truncate: false)
    diagnostics_obj = Datadog::AppSec::WAF::LibDDWAF::Object.new

    expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_builder_add_or_update_config(
      builder_ptr, "test", 4, config_obj, diagnostics_obj
    )).to be(true)

    handle_ptr = Datadog::AppSec::WAF::LibDDWAF.ddwaf_builder_build_instance(builder_ptr)
    @context_ptr = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle_ptr, allocator)
    expect(@context_ptr).not_to be_null

    example.run
  ensure
    Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_destroy(@context_ptr) if @context_ptr
    Datadog::AppSec::WAF::LibDDWAF.ddwaf_destroy(handle_ptr) if handle_ptr
    Datadog::AppSec::WAF::LibDDWAF.ddwaf_builder_destroy(builder_ptr) if builder_ptr
    Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(diagnostics_obj, allocator) if diagnostics_obj
    Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(config_obj, allocator) if config_obj
  end

  describe ".call" do
    it "returns an ok Result for non-matching input" do
      result = described_class.call({value: "safe"}) do |input_obj, allocator, result_obj|
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_eval(@context_ptr, input_obj, allocator, result_obj, 10_000_000)
      end

      expect(result).to be_a(Datadog::AppSec::WAF::Result)
      expect(result.to_h).to match({
        status: :ok, events: [], actions: {}, attributes: {}, duration: be >= 0,
        timeout: false, keep: false, input_truncated: false
      })
    end

    it "preserves the native match result fields" do
      result = described_class.call({value: "attack"}) do |input_obj, allocator, result_obj|
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_eval(@context_ptr, input_obj, allocator, result_obj, 10_000_000)
      end

      aggregate_failures("result") do
        expect(result.status).to eq(:match)
        expect(result.events).to contain_exactly(a_hash_including("rule" => a_hash_including("id" => "evaluation")))
        expect(result.actions.keys).to contain_exactly("block_request")
        expect(result.actions.fetch("block_request")).to include("status_code" => 418, "grpc_status_code" => 42, "type" => "json")
        expect(result.attributes).to eq({"matched.value" => "attack", "matched.count" => 42})
        expect(result.duration).to be >= 0
        expect(result).to be_keep
        expect(result).not_to be_timeout
        expect(result).not_to be_input_truncated
      end
    end

    it "returns the mapped empty Result for invalid native input" do
      result = described_class.call([]) do |input_obj, allocator, result_obj|
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_eval(@context_ptr, input_obj, allocator, result_obj, 10_000_000)
      end

      expect(result).to be_a(Datadog::AppSec::WAF::Result)
      expect(result.to_h).to eq({
        status: :err_invalid_object, events: [], actions: {}, attributes: {}, duration: 0,
        timeout: false, keep: false, input_truncated: false
      })
    end

    it "marks the Result when input is truncated" do
      data = {value: "a" * (Datadog::AppSec::WAF::Converter::MAX_STRING_LENGTH + 1)}
      result = described_class.call(data) do |input_obj, allocator, result_obj|
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_eval(@context_ptr, input_obj, allocator, result_obj, 10_000_000)
      end

      expect(result).to be_input_truncated
    end
  end
end
