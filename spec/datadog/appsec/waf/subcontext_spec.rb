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
    Datadog::AppSec::WAF::HandleBuilder.new(limits: {max_string_length: 7}).tap do |builder|
      builder.add_or_update_config(config, path: "test")
    end
  end

  let(:handle) { builder.build_handle }
  let(:context) { handle.build_context }

  describe "#eval" do
    it "combines parent data with limited child input and returns an independent result" do
      context.eval({request: "attack"})

      result = context.build_subcontext do |subcontext|
        subcontext.eval({operation: "execute trailing text"})
      end

      expect(result.status).to eq(:match)
      expect(result).to be_input_truncated
      expect(result.events.first.dig("rule", "id")).to eq("both-inputs")
      expect(context.eval({}).status).to eq(:ok)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "fails the family and closes only the faulted child on internal error" do
      subcontext = context.build_subcontext
      sibling = context.build_subcontext
      independent_context = handle.build_context
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_eval).and_wrap_original do |original, *args|
        original.call(*args)
        :ddwaf_err_internal
      end
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).and_call_original
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).and_call_original

      expect(subcontext.eval({operation: "execute"}).status).to eq(:err_internal)
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_destroy).once
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_context_destroy)
      expect { context.eval({}) }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)
      expect { context.build_subcontext }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)
      expect { sibling.eval({}) }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)
      expect(independent_context.eval({}).status).to eq(:ok)
    ensure
      subcontext&.finalize!
      sibling&.finalize!
      independent_context&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "keeps the parent usable after an invalid-argument error in the child" do
      subcontext = context.build_subcontext
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_eval).and_wrap_original do |original, _pointer, *args|
        original.call(FFI::Pointer::NULL, *args)
      end

      expect(subcontext.eval({operation: "execute"}).status).to eq(:err_invalid_argument)
      expect(context.eval({}).status).to eq(:ok)
    ensure
      subcontext&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end
end
