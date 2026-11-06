# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Context do
  let(:builder) do
    Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
      builder.add_or_update_config(JSON.parse(File.read("spec/fixtures/valid_config.json")), path: "test")
    end
  end

  let(:handle) { builder.build_handle }
  let(:context) { handle.build_context }

  describe "#finalize!" do
    it "finalizes once and rejects subsequent evaluation" do
      waf_context = context
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).once.and_call_original

      waf_context.finalize!
      waf_context.finalize!

      expect { waf_context.eval({}) }.to raise_error(
        Datadog::AppSec::WAF::InstanceFinalizedError, "Cannot use WAF context after it has been finalized"
      )
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end

  describe "#build_subcontext" do
    it "returns the block value and finalizes the child" do
      subcontext = nil
      waf_context = context
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).once.and_call_original

      result = waf_context.build_subcontext do |child|
        subcontext = child
        :block_value
      end

      expect(result).to eq(:block_value)
      expect { subcontext.eval({}) }.to raise_error(
        Datadog::AppSec::WAF::InstanceFinalizedError, "Cannot use WAF subcontext after it has been finalized"
      )
    ensure
      subcontext&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end
end
