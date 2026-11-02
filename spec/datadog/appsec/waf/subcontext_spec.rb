# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Subcontext do
  let(:config) do
    {
      "version" => "2.2",
      "rules" => [{
        "id" => "both-inputs",
        "name" => "Request and operation",
        "tags" => {"type" => "test"},
        "conditions" => [
          {
            "operator" => "match_regex",
            "parameters" => {"inputs" => [{"address" => "request"}], "regex" => "attack"}
          },
          {
            "operator" => "match_regex",
            "parameters" => {"inputs" => [{"address" => "operation"}], "regex" => "execute"}
          }
        ]
      }]
    }
  end

  let(:builder) do
    Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
      builder.add_or_update_config(config, path: "test")
    end
  end

  let(:handle) { builder.build_handle }
  let(:context) { handle.build_context }

  describe "#eval" do
    it "combines parent data with limited child input and returns an independent result" do
      context.eval({request: "attack"}, 10_000_000)

      result = context.build_subcontext do |subcontext|
        subcontext.eval({operation: "execute" + "a" * Datadog::AppSec::WAF::Converter::MAX_STRING_LENGTH}, 10_000_000)
      end

      expect(result.status).to eq(:match)
      expect(result).to be_input_truncated
      expect(result.events.first.dig("rule", "id")).to eq("both-inputs")
      expect(context.eval({}, 10_000_000).status).to eq(:ok)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "keeps the family usable after an internal error in the child" do
      subcontext = context.build_subcontext
      sibling = context.build_subcontext
      codes = %i[ddwaf_err_internal ddwaf_err_internal]
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_eval).and_wrap_original do |original, *args|
        code = original.call(*args)
        codes.shift || code
      end
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).and_call_original

      expect(subcontext.eval({operation: "execute"}, 10_000_000).to_h).to eq({
        status: :err_internal, events: [], actions: {}, attributes: {}, duration: 0,
        timeout: false, keep: false, input_truncated: false
      })
      expect(subcontext.eval({}, 10_000_000).status).to eq(:err_internal)
      expect(subcontext.eval({}, 10_000_000).status).to eq(:ok)
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_eval).exactly(3).times
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_object_destroy).exactly(3).times
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_subcontext_destroy)
      expect(context.eval({}, 10_000_000).status).to eq(:ok)
      expect(sibling.eval({}, 10_000_000).status).to eq(:ok)
      expect(context.build_subcontext { |new_subcontext| new_subcontext.eval({}, 10_000_000) }.status).to eq(:ok)
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_context_destroy)
    ensure
      subcontext&.finalize!
      sibling&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "frees untransferred input and keeps the family usable after an invalid-argument error in the child" do
      subcontext = context.build_subcontext
      sibling = context.build_subcontext
      calls = 0
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_eval).and_wrap_original do |original, pointer, *args|
        calls += 1
        original.call((calls <= 2) ? FFI::Pointer::NULL : pointer, *args)
      end
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).and_call_original

      expect(subcontext.eval({operation: "execute"}, 10_000_000).to_h).to eq({
        status: :err_invalid_argument, events: [], actions: {}, attributes: {}, duration: 0,
        timeout: false, keep: false, input_truncated: false
      })
      expect(subcontext.eval({}, 10_000_000).status).to eq(:err_invalid_argument)
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_eval).twice
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_object_destroy).exactly(4).times
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_subcontext_destroy)
      expect(context.eval({}, 10_000_000).status).to eq(:ok)
      expect(sibling.eval({}, 10_000_000).status).to eq(:ok)
      expect(context.build_subcontext { |new_subcontext| new_subcontext.eval({}, 10_000_000) }.status).to eq(:ok)
      expect(subcontext.eval({}, 10_000_000).status).to eq(:ok)
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_eval).exactly(5).times
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_context_destroy)

      subcontext.finalize!
      subcontext.finalize!
      sibling.finalize!
      sibling.finalize!
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_destroy).exactly(3).times
    ensure
      subcontext&.finalize!
      sibling&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "keeps the family usable after native input rejection in the child" do
      subcontext = context.build_subcontext
      sibling = context.build_subcontext
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_eval).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).and_call_original

      expect(subcontext.eval([], 10_000_000).to_h).to eq({
        status: :err_invalid_object, events: [], actions: {}, attributes: {}, duration: 0,
        timeout: false, keep: false, input_truncated: false
      })
      expect(subcontext.eval([], 10_000_000).status).to eq(:err_invalid_object)
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_object_destroy).twice
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_subcontext_destroy)
      expect(context.eval({}, 10_000_000).status).to eq(:ok)
      expect(sibling.eval({}, 10_000_000).status).to eq(:ok)
      expect(context.build_subcontext { |new_subcontext| new_subcontext.eval({}, 10_000_000) }.status).to eq(:ok)
      expect(subcontext.eval({}, 10_000_000).status).to eq(:ok)
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_eval).exactly(5).times
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_context_destroy)
    ensure
      subcontext&.finalize!
      sibling&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end
end
