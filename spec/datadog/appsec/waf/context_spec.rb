# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Context do
  describe "#run" do
    let(:config) do
      {
        "version" => "2.2",
        "metadata" => {
          "rules_version" => "1.2.3"
        },
        "rules" => [
          {
            "id" => "1",
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {
                "operator" => "match_regex",
                "parameters" => {"inputs" => [{"address" => "value2"}], "regex" => "rule1"}
              }
            ],
            "on_match" => ["block"]
          }
        ]
      }
    end

    let(:builder) do
      Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
        builder.add_or_update_config(config, path: "some/path")
      end
    end

    let(:handle) { builder.build_handle }
    let(:context) { handle.build_context }

    it "passes non-matching persistent data" do
      result = context.run({value1: ["rule1"]}, {})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:ok)
        expect(result.events).to eq([])
        expect(result.total_runtime).to be >= 0
        expect(result.actions).to eq({})
        expect(result.derivatives).to eq({})
      end
    end

    it "passes non-matching ephemeral data" do
      result = context.run({}, {value1: ["rule1"]})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:ok)
        expect(result.events).to eq([])
        expect(result.total_runtime).to be >= 0
        expect(result.actions).to eq({})
        expect(result.derivatives).to eq({})
      end
    end

    it "catches a match on persistent data" do
      result = context.run({value2: ["rule1"]}, {})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:match)
        expect(result.events).to match_array([{"rule" => anything, "rule_matches" => anything}])
        expect(result.total_runtime).to be >= 0
        expect(result.actions).to eq({"block_request" => {"grpc_status_code" => "10", "status_code" => "403", "type" => "auto"}})
        expect(result.derivatives).to eq({})
      end
    end

    it "catches a match on ephemeral data" do
      result = context.run({}, {value2: ["rule1"]})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:match)
        expect(result.events).to match_array([{"rule" => anything, "rule_matches" => anything}])
        expect(result.total_runtime).to be >= 0
        expect(result.actions).to eq({"block_request" => {"grpc_status_code" => "10", "status_code" => "403", "type" => "auto"}})
        expect(result.derivatives).to eq({})
      end
    end

    it "defines result input as non-truncated" do
      result = context.run({value2: ["rule1"]}, {value2: ["rule1"]})
      expect(result).not_to be_input_truncated
    end

    it "raises LibDDWAF::Error when context has been finalized" do
      context.finalize!

      expect do
        context.run({}, {value2: ["rule1"]})
      end.to raise_error(Datadog::AppSec::WAF::InstanceFinalizedError, /Cannot use WAF context after it has been finalized/)
    end

    it "catches a match with a non UTF-8 string" do
      result = context.run({value2: ["rule1".dup.force_encoding("ASCII-8BIT")]}, {})

      expect(result.status).to eq(:match)
    end

    context "with incorrectly encoded string" do
      it "returns valid UTF-8" do
        result = context.run({value2: ["rule1\xE2".dup.force_encoding("ASCII-8BIT")]}, {})

        first_match_parameters = result.events.dig(0, "rule_matches", 0, "parameters", 0)

        expect(first_match_parameters.fetch("value")).to be_valid_encoding
        expect(first_match_parameters.dig("highlight", 0)).to be_valid_encoding
      end

      it "catches a match" do
        result = context.run({value2: ["rule1\xE2".dup.force_encoding("ASCII-8BIT")]}, {})

        expect(result.status).to eq(:match)
      end
    end

    context "when input was marked as truncated" do
      before { stub_const("Datadog::AppSec::WAF::LibDDWAF::DDWAF_MAX_STRING_LENGTH", 10) }

      it "sets result input as truncated when persistent data is truncated" do
        result = context.run({value2: "a" * 11}, {})

        expect(result).to be_input_truncated
      end

      it "sets result input as truncated when ephemeral data is truncated" do
        result = context.run({}, {value2: "a" * 11})

        expect(result).to be_input_truncated
      end
    end

    context "with processors" do
      let(:config) do
        {
          "version" => "2.2",
          "metadata" => {
            "rules_version" => "1.2.3"
          },
          "processors" => [
            {
              "id" => "processor-001",
              "generator" => "extract_schema",
              "conditions" => [
                {
                  "operator" => "equals",
                  "parameters" => {
                    "inputs" => [
                      {
                        "address" => "waf.context.processor",
                        "key_path" => [
                          "extract-schema"
                        ]
                      }
                    ],
                    "type" => "boolean",
                    "value" => true
                  }
                }
              ],
              "parameters" => {
                "mappings" => [
                  {
                    "inputs" => [
                      {
                        "address" => "server.request.query"
                      }
                    ],
                    "output" => "_dd.appsec.s.req.query"
                  }
                ]
              },
              "evaluate" => false,
              "output" => true
            }
          ]
        }
      end

      context "with schema extraction" do
        it "populates derivatives" do
          waf_args = {
            "server.request.query" => {
              "hello" => "EMBED"
            },
            "waf.context.processor" => {
              "extract-schema" => true
            }
          }

          result = context.run(waf_args, {})

          aggregate_failures("result") do
            expect(result.status).to eq :ok
            expect(result.derivatives).to eq({"_dd.appsec.s.req.query" => [{"hello" => [8]}]})
          end
        end
      end

      context "without schema extraction" do
        it "populates derivatives" do
          waf_args = {
            "server.request.query" => {
              "hello" => "EMBED"
            },
            "waf.context.processor" => {
              "extract-schema" => false
            }
          }

          result = context.run(waf_args, {})

          aggregate_failures("result") do
            expect(result.status).to eq :ok
            expect(result.derivatives).to be_empty
          end
        end
      end
    end
  end
end
