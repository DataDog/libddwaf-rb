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

    let(:result) do
      described_class.new(
        status: :match,
        events: events,
        actions: actions,
        attributes: {},
        duration: 286_125,
        timeout: false,
        keep: true
      )
    end

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
    let(:result) do
      described_class.new(
        status: :ok,
        events: [],
        actions: {},
        attributes: {},
        duration: 0,
        timeout: false,
        keep: false
      )
    end

    context "when input was not truncated" do
      it { expect(result).not_to be_input_truncated }
    end

    context "when input was truncated" do
      before { result.mark_input_truncated! }

      it { expect(result).to be_input_truncated }
    end
  end
end
