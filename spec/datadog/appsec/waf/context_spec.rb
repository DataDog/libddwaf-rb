# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Context do
  describe "#eval" do
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

    it "passes non-matching input" do
      result = context.eval({value1: ["rule1"]}, 10_000_000)

      aggregate_failures("result") do
        expect(result).not_to be_timeout
        expect(result).not_to be_input_truncated
        expect(result.status).to eq(:ok)
        expect(result.events).to eq([])
        expect(result.duration).to be >= 0
        expect(result.actions).to eq({})
        expect(result.attributes).to eq({})
      end
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "catches a match" do
      result = context.eval({value2: ["rule1"]}, 10_000_000)

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
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "returns output of a rule with correct types" do
      result = context.eval({headers: {user: "Attack"}}, 10_000_000)

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
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "returns rule output for a JSON address value" do
      result = context.eval({headers: Datadog::AppSec::WAF::JSONString.new('{"user":"Attack"}')}, 10_000_000)

      expect(result.status).to eq(:match)
      expect(result.attributes).to eq({
        "out.integer" => 42, "out.string" => "forty two", "out.by_path" => "Attack"
      })
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "finalizes once and rejects subsequent evaluation" do
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).once.and_call_original
      context.finalize!
      context.finalize!

      expect { context.eval({value2: ["rule1"]}, 10_000_000) }.to raise_error(
        Datadog::AppSec::WAF::InstanceFinalizedError, /Cannot use WAF context after it has been finalized/
      )
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "catches a match with a non UTF-8 string" do
      result = context.eval({value2: ["rule1".dup.force_encoding("ASCII-8BIT")]}, 10_000_000)

      expect(result.status).to eq(:match)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    context "with incorrectly encoded string" do
      it "returns valid UTF-8" do
        result = context.eval({value2: ["rule1\xE2".dup.force_encoding("ASCII-8BIT")]}, 10_000_000)

        first_match_parameters = result.events.dig(0, "rule_matches", 0, "parameters", 0)

        expect(first_match_parameters.fetch("value")).to be_valid_encoding
        expect(first_match_parameters.dig("highlight", 0)).to be_valid_encoding
      ensure
        context.finalize!
        handle.finalize!
        builder.finalize!
      end
    end

    context "when input was marked as truncated" do
      before { stub_const("Datadog::AppSec::WAF::LibDDWAF::DDWAF_MAX_STRING_LENGTH", 10) }

      it "sets result input as truncated when input is truncated" do
        result = context.eval({value2: "a" * 11}, 10_000_000)

        expect(result).to be_input_truncated
      ensure
        context.finalize!
        handle.finalize!
        builder.finalize!
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

          result = context.eval(waf_args, 10_000_000)

          aggregate_failures("result") do
            expect(result.status).to eq :match
            expect(result.attributes).to eq({"_dd.appsec.s.req.query" => [{"hello" => [8]}]})
          end
        ensure
          context.finalize!
          handle.finalize!
          builder.finalize!
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

          result = context.eval(waf_args, 10_000_000)

          aggregate_failures("result") do
            expect(result.status).to eq :ok
            expect(result.attributes).to be_empty
          end
        ensure
          context.finalize!
          handle.finalize!
          builder.finalize!
        end
      end
    end

    context "when result conversion failed" do
      before do
        allow(Datadog::AppSec::WAF::Converter).to receive(:object_to_ruby)
          .and_return(nil)
      end

      it "destroys the result when decoding fails" do
        waf_context = context
        expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).once.and_call_original
        expect { waf_context.eval({}, 10_000_000) }.to raise_error(
          Datadog::AppSec::WAF::ConversionError, /Could not convert result into object/
        )
      ensure
        context.finalize!
        handle.finalize!
        builder.finalize!
      end
    end

    it "returns an empty error result and closes the context on internal error" do
      waf_context = context
      subcontext = waf_context.build_subcontext
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_eval).and_wrap_original do |original, *args|
        original.call(*args)
        :ddwaf_err_internal
      end
      expect(Datadog::AppSec::WAF::Converter).not_to receive(:object_to_ruby)
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).once.and_call_original
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).once.and_call_original

      result = waf_context.eval({value1: "retained native input"}, 10_000_000)

      expect(result.to_h).to eq({
        status: :err_internal, events: [], actions: {}, attributes: {}, duration: 0,
        timeout: false, keep: false, input_truncated: false
      })
      expect { waf_context.eval({}, 10_000_000) }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)
      expect { waf_context.build_subcontext }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)

      waf_context.finalize!
      expect { subcontext.eval({}, 10_000_000) }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)
    ensure
      subcontext&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "rejects a non-Hash input before native evaluation" do
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_context_eval)

      expect { context.eval([], 10_000_000) }.to raise_error(TypeError, "WAF input must be a Hash")
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "remains usable after input conversion fails" do
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_eval).once.and_call_original

      expect do
        context.eval({value1: Datadog::AppSec::WAF::JSONString.new("{")}, 10_000_000)
      end.to raise_error(Datadog::AppSec::WAF::ConversionError)
      expect(context.eval({}, 10_000_000).status).to eq(:ok)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "frees untransferred input and closes the context on invalid argument" do
      waf_context = context
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_eval).and_wrap_original do |original, _pointer, *args|
        original.call(FFI::Pointer::NULL, *args)
      end
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).twice.and_call_original
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_destroy).once.and_call_original

      expect(waf_context.eval({value1: "binding-owned input"}, 10_000_000).status).to eq(:err_invalid_argument)
      expect { waf_context.eval({}, 10_000_000) }.to raise_error(Datadog::AppSec::WAF::LibDDWAFError, /native error/)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "keeps the context usable after native input rejection" do
      waf_context = context
      invalid_input = Datadog::AppSec::WAF::Converter.ruby_to_object([], coerce: false)
      allow(Datadog::AppSec::WAF::Converter).to receive(:ruby_to_object).and_return(invalid_input)

      expect(waf_context.eval({}, 10_000_000).status).to eq(:err_invalid_object)

      allow(Datadog::AppSec::WAF::Converter).to receive(:ruby_to_object).and_call_original
      expect(waf_context.eval({}, 10_000_000).status).to eq(:ok)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "retains input across evaluations" do
      config["rules"][0]["conditions"] << {
        "operator" => "match_regex",
        "parameters" => {"inputs" => [{"address" => "value3"}], "regex" => "rule3"}
      }

      expect(context.eval({value2: "rule1"}, 10_000_000).status).to eq(:ok)
      expect(context.eval({value3: "rule3"}, 10_000_000).status).to eq(:match)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "finishes ownership bookkeeping and result cleanup before delivering an interruption" do
      waf_context = context
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_context_eval).and_wrap_original do |original, *args|
        code = original.call(*args)
        Thread.current.raise(RuntimeError, "interrupted")
        code
      end
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy).once.and_call_original

      expect { waf_context.eval({value1: "native-owned input"}, 10_000_000) }.to raise_error(RuntimeError, "interrupted")
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "contains logger errors during native evaluation" do
      previous_logger = Datadog::AppSec::WAF.logger
      waf_context = context
      logger = double("logger")
      expect(logger).to receive(:debug).at_least(:once).and_raise(RuntimeError, "logger failed")
      Datadog::AppSec::WAF.logger = logger

      expect(waf_context.eval({value2: "rule1"}, 10_000_000).status).to eq(:match)
    ensure
      Datadog::AppSec::WAF.logger = previous_logger
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end

  describe "#build_subcontext" do
    let(:builder) do
      Datadog::AppSec::WAF::HandleBuilder.new.tap do |builder|
        config = JSON.parse(File.read("spec/fixtures/valid_config.json"))
        builder.add_or_update_config(config, path: "test")
      end
    end

    let(:handle) { builder.build_handle }
    let(:context) { handle.build_context }

    it "returns a child with independent, idempotent finalization" do
      subcontext = context.build_subcontext
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).and_call_original

      context.finalize!
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to have_received(:ddwaf_subcontext_destroy)

      expect(subcontext.eval({}, 10_000_000).status).to eq(:ok)

      subcontext.finalize!
      subcontext.finalize!
      expect(Datadog::AppSec::WAF::LibDDWAF).to have_received(:ddwaf_subcontext_destroy).once
      expect { subcontext.eval({}, 10_000_000) }.to raise_error(Datadog::AppSec::WAF::InstanceFinalizedError)
    ensure
      subcontext&.finalize!
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "returns the block value and finalizes the child" do
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).once.and_call_original

      result = context.build_subcontext do |subcontext|
        expect(subcontext).to be_a(Datadog::AppSec::WAF::Subcontext)
        :block_result
      end

      expect(result).to eq(:block_result)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "finalizes the child when the block raises" do
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).once.and_call_original

      expect do
        context.build_subcontext { raise "block failed" }
      end.to raise_error(RuntimeError, "block failed")
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "raises when native initialization fails" do
      allow(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_init).and_return(FFI::Pointer::NULL)

      expect { context.build_subcontext }.to raise_error(
        Datadog::AppSec::WAF::LibDDWAFError, "Could not create subcontext"
      )
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "destroys the native child when Ruby wrapper construction fails" do
      allow(Datadog::AppSec::WAF::Subcontext).to receive(:new).and_raise(RuntimeError, "wrapper failed")
      expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_subcontext_destroy).once.and_call_original

      expect { context.build_subcontext }.to raise_error(RuntimeError, "wrapper failed")
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end

    it "rejects creation after parent finalization" do
      context.finalize!
      expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_subcontext_init)

      expect { context.build_subcontext }.to raise_error(Datadog::AppSec::WAF::InstanceFinalizedError)
    ensure
      context.finalize!
      handle.finalize!
      builder.finalize!
    end
  end
end
