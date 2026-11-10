# frozen_string_literal:true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::HandleBuilder do
  subject(:builder) { described_class.new }

  after { builder.finalize! }

  let(:valid_config) do
    JSON.parse(File.read("spec/fixtures/valid_config.json"))
  end

  describe "#build_handle" do
    it "raises LibDDWAF::Error when no valid rule has been loaded" do
      expect { builder.build_handle }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /Could not create handle/)
    end

    it "raises LibDDWAF::Error when builder has been finalized" do
      builder.finalize!

      expect do
        builder.build_handle
      end.to raise_error(Datadog::AppSec::WAF::InstanceFinalizedError, /Cannot use WAF handle builder after it has been finalized/)
    end

    context "when at least one valid rule has been loaded" do
      before do
        builder.add_or_update_config(valid_config, path: "some/path")
      end

      it "returns a Datadog::AppSec::WAF::Handle instance" do
        handle = builder.build_handle
        expect(handle).to be_a(Datadog::AppSec::WAF::Handle)
      ensure
        handle&.finalize!
      end
    end
  end

  describe "#add_or_update_config" do
    it "returns success and diagnostics hash when adding valid config" do
      result = builder.add_or_update_config(valid_config, path: "some/path")

      expect(result).to be_a(Datadog::AppSec::WAF::ConfigurationResult)
      expect(result.success?).to be(true)
      expect(result.diagnostics.dig("rules", "loaded")).to eq(["rasp-003-001"])
      expect(result.diagnostics.dig("rules", "errors")).to be_empty

      result = builder.add_or_update_config(valid_config, path: "some/path")
      expect(result.success?).to be(true)
    end

    it "returns failure and diagnostics hash with errors when adding invalid config" do
      result = builder.add_or_update_config({"rules" => [{"id" => "foo", "name" => "Banana"}]}, path: "some/path")

      expect(result.success?).to be(false)
      expect(result.diagnostics.dig("rules", "loaded")).to be_empty
      expect(result.diagnostics.dig("rules", "failed")).to eq(["foo"])
    end

    it "raises LibDDWAF::Error when builder has been finalized" do
      builder.finalize!

      expect do
        builder.add_or_update_config({}, path: "some/path")
      end.to raise_error(Datadog::AppSec::WAF::InstanceFinalizedError, /Cannot use WAF handle builder after it has been finalized/)
    end
  end

  describe "#remove_config_at_path" do
    it "returns true when removing previously added config" do
      builder.add_or_update_config(valid_config, path: "some/path")

      expect(builder.remove_config_at_path("some/path")).to eq(true)
    end

    it "returns false when attempting to remove config that was not added before" do
      expect(builder.remove_config_at_path("another/path")).to eq(false)
    end

    it "raises LibDDWAF::Error when builder has been finalized" do
      builder.finalize!

      expect do
        builder.remove_config_at_path("any/path")
      end.to raise_error(Datadog::AppSec::WAF::InstanceFinalizedError, /Cannot use WAF handle builder after it has been finalized/)
    end
  end
end
