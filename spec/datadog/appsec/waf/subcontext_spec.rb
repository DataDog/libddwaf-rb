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
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).once.and_call_original

      context.build_subcontext do |subcontext|
        subcontext.finalize!
        subcontext.finalize!

        expect { subcontext.eval({}) }.to raise_error(
          Datadog::AppSec::WAF::InstanceFinalizedError, "Cannot use WAF subcontext after it has been finalized"
        )
      end
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end

  describe "#eval" do
    it "matches ephemeral data against data inherited from the context" do
      context.eval({"server.request.query" => {"id" => "1 OR 1=1"}})
      input = {"server.db.statement" => "SELECT * FROM users WHERE id = 1 OR 1=1", "server.db.system" => "mysql"}

      results = 2.times.map { context.build_subcontext { |subcontext| subcontext.eval(input, 10_000_000) } }

      expect(results.map(&:status)).to eq([:match, :match])
      expect(results.map { |result| result.events.dig(0, "rule", "id") }).to eq(["rasp-003-001", "rasp-003-001"])
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end
end
