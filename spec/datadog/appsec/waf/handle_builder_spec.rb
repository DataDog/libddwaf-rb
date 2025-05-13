# frozen_string_literal:true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::HandleBuilder do
  subject(:builder) { described_class.new }

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

      after do
        builder.remove_config_at_path("some/path")
      end

      it "returns a Datadog::AppSec::WAF::Handle instance" do
        expect(builder.build_handle).to be_a(Datadog::AppSec::WAF::Handle)
      end
    end
  end

  describe "#add_or_update_configuration" do
    it "returns diagnostics hash when adding valid config" do
      diagnostics = builder.add_or_update_config(valid_config, path: "some/path")

      aggregate_failures("diagnostics data") do
        expect(diagnostics.fetch("ruleset_version")).to eq("1.13.0")

        expect(diagnostics).to have_key("rules")
        expect(diagnostics.dig("rules", "loaded")).to eq(["rasp-003-001"])
        expect(diagnostics.dig("rules", "errors")).to be_empty

        expect(diagnostics).to have_key("actions")
        expect(diagnostics.dig("actions", "loaded")).to eq(["block-sqli"])
        expect(diagnostics.dig("actions", "errors")).to be_empty
      end
    end

    it "returns diagnostics hash with errors when adding invalid config" do
      diagnostics = builder.add_or_update_config({"rules" => [{"id" => "foo", "name" => "Banana"}]}, path: "some/path")

      expect(diagnostics).to be_a(Hash)

      aggregate_failures("diagnostics data") do
        expect(diagnostics).to have_key("rules")
        expect(diagnostics.dig("rules", "loaded")).to be_empty
        expect(diagnostics.dig("rules", "failed")).to eq(["foo"])
      end
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
