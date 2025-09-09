# frozen_string_literal: true

require "spec_helper"
require "datadog/appsec/waf/result"

RSpec.describe Datadog::AppSec::WAF::Result do
  describe "#to_h" do
    let(:actions) do
      {"block_request" => {"status_code" => "403", "type" => "auto", "grpc_status_code" => "10"}}
    end

    let(:events) do
      [
        {
          "rule" => {
            "id" => "rasp-003-001",
            "name" => "SQL Injection",
            "tags" => {},
            "on_match" => ["block"]
          },
          "rule_matches" => [
            {
              "operator" => "sqli_detector",
              "operator_value" => "",
              "parameters" => [
                {"resource" => {}, "params" => {}, "db_type" => {}, "highlight" => []}
              ]
            }
          ]
        }
      ]
    end

    let(:result) { described_class.new(:match, events, actions, {}, 286_125, false, true) }

    it "converts to Hash" do
      expect(result.to_h).to eq({
        status: :match,
        events: events,
        actions: actions,
        attributes: {},
        duration: 286_125,
        timeout: false,
        keep: true,
        input_truncated: false
      })
    end
  end

  describe "#input_truncated?" do
    subject(:result) { described_class.new(:ok, [], {}, {}, 0, false, false) }

    context "when input was not truncated" do
      it { expect(result).not_to be_input_truncated }
    end

    context "when input was truncated" do
      before { result.mark_input_truncated! }

      it { expect(result).to be_input_truncated }
    end
  end
end
