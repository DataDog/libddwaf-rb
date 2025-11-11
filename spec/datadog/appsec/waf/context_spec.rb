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
        ],
        "rules_compat" => [
          {
            "id" => "2",
            "name" => "Rule 2",
            "tags" => {"type" => "flow2"},
            "conditions" => [
              {
                "operator" => "match_regex",
                "parameters" => {
                  "inputs" => [{"address" => "headers", "key_path" => ["user"]}],
                  "regex" => "^Attack"
                }
              }
            ],
            "output" => {
              "event" => false,
              "keep" => true,
              "attributes" => {
                "out.integer" => {"value" => 42},
                "out.string" => {"value" => "forty two"},
                "out.by_path" => {"address" => "headers", "key_path" => ["user"]}
              }
            },
            "on_match" => []
          }
        ]
      }
    end

    let(:builder) do
      Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
        diagnostics = builder.add_or_update_config(config, path: "some/path")

        aggregate_failures("config") do
          expect(diagnostics&.dig("rules", "failed").to_a).to be_empty
          expect(diagnostics&.dig("rules_compat", "failed").to_a).to be_empty
        end
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
        expect(result.duration).to be >= 0
        expect(result.actions).to eq({})
        expect(result.attributes).to eq({})
      end
    end

    it "passes non-matching ephemeral data" do
      result = context.run({}, {value1: ["rule1"]})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:ok)
        expect(result.events).to eq([])
        expect(result.duration).to be >= 0
        expect(result.actions).to eq({})
        expect(result.attributes).to eq({})
      end
    end

    it "catches a match on persistent data" do
      result = context.run({value2: ["rule1"]}, {})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:match)
        expect(result.events).to match_array([{"rule" => anything, "rule_matches" => anything, "security_response_id" => anything}])
        expect(result.duration).to be >= 0
        expect(result.attributes).to eq({})
      end

      aggregate_failures("result actions") do
        expect(result.actions.keys).to contain_exactly("block_request")

        expect(result.actions.dig("block_request", "security_response_id")).not_to be_empty

        expect(result.actions.dig("block_request", "type")).to eq("auto")
        expect(result.actions.dig("block_request", "status_code")).to eq(403)
        expect(result.actions.dig("block_request", "grpc_status_code")).to eq(10)
      end
    end

    it "catches a match on ephemeral data" do
      result = context.run({}, {value2: ["rule1"]})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:match)
        expect(result.events).to match_array([{"rule" => anything, "rule_matches" => anything, "security_response_id" => anything}])
        expect(result.duration).to be >= 0
        expect(result.attributes).to eq({})
      end

      aggregate_failures("result actions") do
        expect(result.actions.keys).to contain_exactly("block_request")

        expect(result.actions.dig("block_request", "security_response_id")).not_to be_empty

        expect(result.actions.dig("block_request", "type")).to eq("auto")
        expect(result.actions.dig("block_request", "status_code")).to eq(403)
        expect(result.actions.dig("block_request", "grpc_status_code")).to eq(10)
      end
    end

    it "returns output of a rule with correct types" do
      result = context.run({headers: {user: "Attack"}}, {})

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result.status).to eq(:match)
        expect(result.events).to eq([])
        expect(result.duration).to be >= 0
        expect(result.actions).to eq({})
        expect(result.attributes).to eq({
          "out.integer" => 42, "out.string" => "forty two", "out.by_path" => "Attack"
        })
      end
    end

    it "defines result input as non-truncated" do
      result = context.run({value2: ["rule1"]}, {value2: ["rule1"]})
      expect(result).not_to be_input_truncated
    end

    it "raises LibDDWAF::Error when context has been finalized" do
      context.finalize!

      expect { context.run({}, {value2: ["rule1"]}) }.to raise_error(
        Datadog::AppSec::WAF::InstanceFinalizedError, /Cannot use WAF context after it has been finalized/
      )
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
        it "populates attributes" do
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
            expect(result.attributes).to eq({"_dd.appsec.s.req.query" => [{"hello" => [8]}]})
          end
        end
      end

      context "without schema extraction" do
        it "populates attributes" do
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
            expect(result.attributes).to be_empty
          end
        end
      end
    end

    context "when result conversion failed" do
      before do
        allow(Datadog::AppSec::WAF::Converter).to receive(:object_to_ruby)
          .and_return(nil)
      end

      it "raises exception" do
        expect { context.run({}, {}) }.to raise_error(
          Datadog::AppSec::WAF::ConversionError, /Could not convert result into object/
        )
      end
    end

    context "when result is an error" do
      before do
        allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_run)
          .and_return(:ddwaf_err_internal)
      end

      let(:result) { context.run({}, {}) }

      it "returns empty result with an error status code" do
        aggregate_failures("result") do
          expect(result).not_to be_timeout
          expect(result).not_to be_keep
          expect(result).not_to be_input_truncated

          expect(result.status).to eq(:err_internal)
          expect(result.events).to eq([])
          expect(result.actions).to eq({})
          expect(result.attributes).to eq({})
          expect(result.duration).to be_zero
        end
      end
    end
  end
end
