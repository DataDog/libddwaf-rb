# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Subcontext do
  let(:builder) do
    Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
      builder.add_or_update_config(JSON.parse(File.read("spec/fixtures/valid_config.json")), path: "test")
    end
  end

  let(:handle) { builder.build_handle }
  let(:context) { handle.build_context }

  describe "#finalize!" do
    it "finalizes once and rejects subsequent evaluation" do
      subcontext = context.build_subcontext
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).once.and_call_original

      subcontext.finalize!
      subcontext.finalize!

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
