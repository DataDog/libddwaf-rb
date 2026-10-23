# frozen_string_literal: true

require "spec_helper"
require "datadog/appsec/waf/lib_ddwaf"
require "datadog/appsec/waf/converter"
require "datadog/appsec/waf/version"

RSpec.describe Datadog::AppSec::WAF::LibDDWAF do
  it "provides the internally stored version" do
    expect(described_class.ddwaf_get_version).to eq Datadog::AppSec::WAF::VERSION::BASE_STRING
  end

  context "Object" do
    let(:allocator) { described_class.ddwaf_get_default_allocator }
    let(:object) { described_class::Object.new }

    around do |example|
      raise "Could not obtain the native allocator" if allocator.null?

      described_class.ddwaf_object_set_invalid(object)
      begin
        example.run
      ensure
        described_class.ddwaf_object_destroy(object, allocator)
      end
    end

    it "passes and returns signed 64-bit integers through an Object reference" do
      value = -0x1_0000_0001

      result = described_class.ddwaf_object_set_signed(object, value)

      expect(result).to be_a(described_class::Object)
      expect(result.to_ptr).to eq(object.to_ptr)
      expect(described_class.ddwaf_object_get_type(object)).to eq(:ddwaf_obj_signed)
      expect(described_class.ddwaf_object_get_signed(object)).to eql(value)
    end

    it "passes and returns unsigned 64-bit integers" do
      value = 0x8000_0000_0000_0001

      described_class.ddwaf_object_set_unsigned(object, value)

      expect(described_class.ddwaf_object_get_unsigned(object)).to eql(value)
    end

    it "passes and returns Ruby true" do
      described_class.ddwaf_object_set_bool(object, true)

      expect(described_class.ddwaf_object_get_bool(object)).to be(true)
    end

    it "passes and returns Ruby false" do
      described_class.ddwaf_object_set_bool(object, false)

      expect(described_class.ddwaf_object_get_bool(object)).to be(false)
    end

    it "passes and returns double-precision floats" do
      value = 1.0000000000000002

      described_class.ddwaf_object_set_float(object, value)

      expect(described_class.ddwaf_object_get_float(object)).to eql(value)
    end

    it "passes string bytes and reads a pointer with a size_t output length" do
      bytes = "caf\u00e9\0tail".b
      length = described_class::SizeTPtr.new
      described_class.ddwaf_object_set_string(object, bytes, bytes.bytesize, allocator)

      pointer = described_class.ddwaf_object_get_string(object, length)

      expect(pointer).not_to be_null
      expect(length[:value]).to eql(bytes.bytesize)
      expect(pointer.read_bytes(length[:value])).to eq(bytes)
      expect(described_class.ddwaf_object_get_length(object)).to eql(bytes.bytesize)
    end

    it "passes array slots as Object references and returns an integer size" do
      described_class.ddwaf_object_set_array(object, 1, allocator)
      slot = described_class.ddwaf_object_insert(object, allocator)
      expect(slot.to_ptr).not_to be_null
      described_class.ddwaf_object_set_signed(slot, 42)

      value = described_class.ddwaf_object_at_value(object, 0)

      expect(value.to_ptr).not_to be_null
      expect(described_class.ddwaf_object_get_signed(value)).to eql(42)
      expect(described_class.ddwaf_object_get_size(object)).to eql(1)
    end

    it "passes map keys with a byte length and returns key and value Object references" do
      bytes = "key\0\u00e9".b
      described_class.ddwaf_object_set_map(object, 1, allocator)
      slot = described_class.ddwaf_object_insert_key(object, bytes, bytes.bytesize, allocator)
      expect(slot.to_ptr).not_to be_null
      described_class.ddwaf_object_set_signed(slot, 42)

      key = described_class.ddwaf_object_at_key(object, 0)
      value = described_class.ddwaf_object_at_value(object, 0)

      expect(key.to_ptr).not_to be_null
      expect(value.to_ptr).not_to be_null
      length = described_class::SizeTPtr.new
      pointer = described_class.ddwaf_object_get_string(key, length)
      expect(pointer).not_to be_null
      expect(length[:value]).to eql(bytes.bytesize)
      expect(pointer.read_bytes(length[:value])).to eq(bytes)
      expect(described_class.ddwaf_object_get_signed(value)).to eql(42)
    end
  end

  context "run" do
    let(:data1) do
      {
        "version" => "1.0",
        "events" => [
          {
            "id" => 1,
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value1", "value2"], "regex" => "rule1"}}
            ],
            "action" => "record"
          },
          {
            "id" => 2,
            "name" => "Rule 2",
            "tags" => {"type" => "flow2"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value1"], "regex" => "rule2"}}
            ],
            "action" => "record"
          },
          {
            "id" => 3,
            "name" => "Rule 3",
            "tags" => {"type" => "flow2"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value2"], "regex" => "rule3"}}
            ],
            "action" => "record"
          }
        ]
      }
    end

    let(:data2) do
      {
        "version" => "1.0",
        "events" => [
          {
            "id" => 1,
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value1"], "regex" => "rule2"}},
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value2"], "regex" => "rule3"}}
            ],
            "action" => "record"
          }
        ]
      }
    end

    let(:data3) do
      require "json"

      JSON.parse(File.read(File.expand_path("../../../fixtures/waf_rules.json", __dir__)))
    end

    let(:data4) do
      {
        "version" => "2.2",
        "metadata" => {
          "rules_version" => "0.1.2"
        },
        "rules" => [
          {
            "id" => 1,
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {"operator" => "match_regex", "parameters" => {"inputs" => [{"address" => "value1"}], "regex" => "rule2"}}
            ],
            "action" => "record"
          }
        ]
      }
    end

    let(:data5) do
      {
        "version" => "2.2",
        "metadata" => {
          "rules_version" => "0.1.2"
        },
        "rules" => [
          {
            "id" => 1,
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {"operator" => "match_regex", "parameters" => {"inputs" => [{"address" => "value1"}], "regex" => "rule2"}}
            ],
            "on_match" => ["action1", "action2", "action3", "action4"]
          }
        ],
        "actions" => [
          {
            "id" => "action1",
            "type" => "block",
            "parameters" => {"status_code" => "401", "grpc_status_code" => "41", "type" => "auto"}
          },
          {
            "id" => "action2",
            "type" => "extract_schema",
            "parameters" => {"status_code" => "402", "grpc_status_code" => "42", "type" => "auto"}
          },
          {
            "id" => "action3",
            "type" => "stacktrace",
            "parameters" => {"status_code" => "403", "grpc_status_code" => "43", "type" => "auto"}
          },
          {
            "id" => "action4",
            "type" => "unblock",
            "parameters" => {"status_code" => "404", "grpc_status_code" => "44", "type" => "auto"}
          }
        ]
      }
    end

    let(:bad_data) do
      {
        "version" => "1.0",
        "events" => [
          {
            "id" => 1,
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value1", "value2"], "regex" => "rule1"}}
            ],
            "action" => "record"
          },
          {
            "id" => 2,
            "badname" => "Rule 2",
            "tags" => {"type" => "flow2"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value1"], "regex" => "rule2"}}
            ],
            "action" => "record"
          },
          {
            "id" => 3,
            "name" => "Rule 3",
            "tags" => {"type" => "flow2"},
            "conditions" => [
              {"operation" => "match_regex", "parameters" => {"inputs" => ["value2"], "regex" => "rule3"}}
            ],
            "action" => "record"
          }
        ]
      }
    end

    let(:invalid_action_data) do
      {
        "version" => "2.2",
        "metadata" => {
          "rules_version" => "0.1.2"
        },
        "rules" => [
          {
            "id" => 1,
            "name" => "Rule 1",
            "tags" => {"type" => "flow1"},
            "conditions" => [
              {"operator" => "match_regex", "parameters" => {"inputs" => [{"address" => "value1"}], "regex" => "rule2"}}
            ],
            "on_match" => ["invalid-action", "valid-action-1", "valid-action-2", "unknown-action"]
          }
        ],
        "actions" => [
          {
            "id" => "valid-action-1",
            "type" => "block",
            "parameters" => {"status_code" => "401", "grpc_status_code" => "41", "type" => "auto"}
          },
          {
            "id" => "valid-action-2",
            "type" => "unblock",
            "parameters" => {"status_code" => "402", "grpc_status_code" => "42", "type" => "auto"}
          },
          {
            "id" => "invalid-action",
            "parameters" => {"status" => "500", "grpc_status" => "??", "type" => "invalid"}
          }
        ]
      }
    end

    let(:rule1) { Datadog::AppSec::WAF::Converter.ruby_to_object(data1) }
    let(:rule2) { Datadog::AppSec::WAF::Converter.ruby_to_object(data2) }
    let(:rule3) { Datadog::AppSec::WAF::Converter.ruby_to_object(data3) }
    let(:rule4) { Datadog::AppSec::WAF::Converter.ruby_to_object(data4) }
    let(:rule5) { Datadog::AppSec::WAF::Converter.ruby_to_object(data5) }
    let(:bad_rule) { Datadog::AppSec::WAF::Converter.ruby_to_object(bad_data) }
    let(:invalid_action_rule) { Datadog::AppSec::WAF::Converter.ruby_to_object(invalid_action_data) }

    let(:log_store) { [] }

    let(:log_cb) do
      proc do |level, func, file, line, message, len|
        log_store << {level: level, func: func, file: file, line: line, message: message.read_bytes(len)}
      end
    end

    let(:config) { described_class::HandleBuilderConfig.new }

    let(:input) do
      Datadog::AppSec::WAF::Converter.ruby_to_object({value1: [4242, "randomString"], value2: ["rule1"]})
    end

    let(:empty_input) { Datadog::AppSec::WAF::Converter.ruby_to_object({}) }

    let(:attack) do
      Datadog::AppSec::WAF::Converter.ruby_to_object({"server.request.headers.no_cookies" => {"user-agent" => "Nessus SOAP"}})
    end

    let(:block) { Datadog::AppSec::WAF::Converter.ruby_to_object({value1: "rule2"}) }

    let(:timeout_usec) { 10_000_000 }
    let(:diagnostics_obj) { described_class::Object.new }

    let(:builder) { described_class.ddwaf_builder_init(config) }

    before(:each) do
      expect(log_store).to eq([])
      described_class.ddwaf_set_log_cb(log_cb, :ddwaf_log_trace)
      expect(log_store.size).to eq 1
      expect(log_store.select { |log| log[:message] =~ /Sending log messages to binding/ })
    end

    after(:each) do |example|
      if example.exception
        puts "\n== #{example.full_description}"
        log_store.each do |log|
          puts log.inspect
        end
        puts "== #{example.full_description}"
      end
    end

    after do
      described_class.ddwaf_set_log_cb(nil, :ddwaf_log_off)
    end

    it "logs via the log callback" do
      expect(log_store.select { |log| log[:message] == "Sending log messages to binding, min level trace" }).to_not be_empty
    end

    context "with diagnostics" do
      it "records successful old diagnostics" do
        described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule1, diagnostics_obj)
        handle = described_class.ddwaf_builder_build_instance(builder)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF::Converter.object_to_ruby(diagnostics_obj)

        expect(diagnostics["rules"]["loaded"].size).to eq(3)
        expect(diagnostics["rules"]["failed"].size).to eq(0)
        expect(diagnostics["rules"]["errors"]).to be_empty
      end

      it "records successful new diagnostics" do
        described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule4, diagnostics_obj)
        handle = described_class.ddwaf_builder_build_instance(builder)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF::Converter.object_to_ruby(diagnostics_obj)

        expect(diagnostics["rules"]["loaded"].size).to eq(1)
        expect(diagnostics["rules"]["failed"].size).to eq(0)
        expect(diagnostics["rules"]["errors"]).to be_empty
        expect(diagnostics["ruleset_version"]).to eq("0.1.2")
      end

      it "records failing diagnostics" do
        described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, bad_rule, diagnostics_obj)
        handle = described_class.ddwaf_builder_build_instance(builder)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF::Converter.object_to_ruby(diagnostics_obj)

        expect(diagnostics["rules"]["loaded"].size).to eq(2)
        expect(diagnostics["rules"]["failed"].size).to eq(1)
        expect(diagnostics["rules"]["errors"]).to_not be_empty
        expect(diagnostics["ruleset_version"]).to be_nil
      end
    end

    it "lists required addresses" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule1, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      count = described_class::UInt32Ptr.new
      list = described_class.ddwaf_known_addresses(handle, count)
      expect(list.get_array_of_string(0, count[:value]).sort).to eq(["value1", "value2"])
    end

    it "triggers a monitoring rule" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule1, diagnostics_obj)

      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle).not_to be_null

      context = described_class.ddwaf_context_init(handle)
      expect(context).not_to be_null

      result = described_class::Object.new
      code = described_class.ddwaf_run(context, input, empty_input, result, timeout_usec)

      expect(code).to eq :ddwaf_match
      expect(result).to be_a(described_class::Object)

      result = Datadog::AppSec::WAF::Converter.object_to_ruby(result)
      expect(result["events"]).to be_a(Array)
      expect(result["actions"]).to be_a(Hash)
      expect(result["timeout"]).to eq(false)

      expect(result["actions"].size).to be_zero
    end

    it "does not trigger" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule2, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle).not_to be_null

      context = described_class.ddwaf_context_init(handle)
      expect(context).not_to be_null

      result = described_class::Object.new
      code = described_class.ddwaf_run(context, input, empty_input, result, timeout_usec)

      expect(code).to eq :ddwaf_ok
      expect(result).to be_a(described_class::Object)

      result = Datadog::AppSec::WAF::Converter.object_to_ruby(result)
      expect(result["events"]).to be_a(Array)
      expect(result["actions"]).to be_a(Hash)
      expect(result["timeout"]).to eq(false)
      expect(result["actions"].size).to be_zero
    end

    it "does not trigger a monitoring rule due to timeout" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule1, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle).not_to be_null

      context = described_class.ddwaf_context_init(handle)
      expect(context).not_to be_null

      result = described_class::Object.new
      code = described_class.ddwaf_run(context, input, empty_input, result, 1)

      expect(code).to eq :ddwaf_ok
      expect(result).to be_a(described_class::Object)

      result = Datadog::AppSec::WAF::Converter.object_to_ruby(result)
      expect(result["events"]).to be_a(Array)
      expect(result["actions"]).to be_a(Hash)
      expect(result["timeout"]).to eq(true)
      expect(result["actions"].size).to be_zero
    end

    it "triggers a known attack" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule3, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle).not_to be_null

      context = described_class.ddwaf_context_init(handle)
      expect(context).not_to be_null

      result = described_class::Object.new
      code = described_class.ddwaf_run(context, attack, empty_input, result, timeout_usec)

      expect(code).to eq :ddwaf_match
      expect(result).to be_a(described_class::Object)

      result = Datadog::AppSec::WAF::Converter.object_to_ruby(result)
      expect(result["events"]).to be_a(Array)
      expect(result["actions"]).to be_a(Hash)
      expect(result["timeout"]).to eq(false)
      expect(result["actions"].size).to be_zero
    end

    it "triggers a known actionable attack" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, rule5, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle).not_to be_null

      context = described_class.ddwaf_context_init(handle)
      expect(context).not_to be_null

      result = described_class::Object.new
      code = described_class.ddwaf_run(context, block, empty_input, result, timeout_usec)

      expect(code).to eq :ddwaf_match
      expect(result).to be_a(described_class::Object)

      result = Datadog::AppSec::WAF::Converter.object_to_ruby(result)
      expect(result["events"]).to be_a(Array)
      expect(result["actions"]).to be_a(Hash)
      expect(result["timeout"]).to eq(false)
      expect(result["actions"].size).to eq(4)
      expect(result["actions"].keys).to eq(["unblock", "stacktrace", "extract_schema", "block"])
    end

    it "silently drops invalid or unknown actions on actionable attack" do
      described_class.ddwaf_builder_add_or_update_config(builder, "some/path", 9, invalid_action_rule, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle).not_to be_null

      context = described_class.ddwaf_context_init(handle)
      expect(context).not_to be_null

      result = described_class::Object.new
      code = described_class.ddwaf_run(context, block, empty_input, result, timeout_usec)

      expect(code).to eq :ddwaf_match
      expect(result).to be_a(described_class::Object)

      result = Datadog::AppSec::WAF::Converter.object_to_ruby(result)
      expect(result["events"]).to be_a(Array)
      expect(result["actions"]).to be_a(Hash)
      expect(result["timeout"]).to eq(false)
      expect(result["actions"].size).to eq(2)
      expect(result["actions"].keys).to eq(["unblock", "block"])
    end
  end
end
