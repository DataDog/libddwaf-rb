# frozen_string_literal:true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Handle do
  let(:valid_config) do
    JSON.parse(File.read("spec/fixtures/valid_config.json"))
  end

  subject(:handle) do
    builder = Datadog::AppSec::WAF::HandleBuilder.new
    builder.add_or_update_config(config: valid_config, path: "some/path")
    builder.build_handle
  end

  describe "#build_context" do
    it "returns a Datadog::AppSec::WAF::Context instance" do
      expect(handle.build_context).to be_a(Datadog::AppSec::WAF::Context)
    end

    it "raises LibDDWAF::Error when handle has been finalized" do
      handle.finalize!

      expect do
        handle.build_context
      end.to raise_error(Datadog::AppSec::WAF::HandleFinalizedError, /Cannot use WAF handle after it has been finalized/)
    end
  end

  describe "#known_addresses" do
    it "returns a list of known addresses based on loaded rules" do
      expect(handle.known_addresses).to match_array(["server.request.query", "server.db.statement", "server.db.system"])
    end

    it "raises LibDDWAF::Error when handle has been finalized" do
      handle.finalize!

      expect do
        handle.known_addresses
      end.to raise_error(Datadog::AppSec::WAF::HandleFinalizedError, /Cannot use WAF handle after it has been finalized/)
    end
  end
end
