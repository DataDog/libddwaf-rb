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

  it "passes log callback arguments and returns a boolean" do
    previous_callback = Datadog::AppSec::WAF.instance_variable_get(:@log_callback)
    received_log = nil
    callback = proc do |level, function, file, line, message, length|
      received_log = {
        level: level,
        function: function,
        file: file,
        line: line,
        message: message.read_bytes(length)
      }
    end

    expect(described_class.ddwaf_set_log_cb(callback, :ddwaf_log_trace)).to be(true)
    expect(received_log).to match(
      level: :ddwaf_log_info,
      function: a_string_including("ddwaf_set_log_cb"),
      file: a_string_ending_with("interface.cpp"),
      line: a_kind_of(Integer),
      message: "Sending log messages to binding, min level trace"
    )
  ensure
    level = previous_callback ? :ddwaf_log_trace : :ddwaf_log_off
    described_class.ddwaf_set_log_cb(previous_callback, level)
  end

  it "passes allocator and object pointers through context and subcontext evaluation" do
    parent_input_transferred = false
    child_input_transferred = false
    allocator = described_class.ddwaf_get_default_allocator
    expect(allocator).not_to be_null

    configuration = Datadog::AppSec::WAF::Converter.ruby_to_object(
      JSON.parse(File.read("spec/fixtures/valid_config.json")), coerce: false
    )
    diagnostics = described_class::Object.new
    builder = described_class.ddwaf_builder_init
    expect(builder).not_to be_null
    expect(described_class.ddwaf_builder_add_or_update_config(builder, "test", 4, configuration, diagnostics)).to be(true)
    expect(described_class.ddwaf_object_get_type(diagnostics)).to eq(:ddwaf_obj_map)

    handle = described_class.ddwaf_builder_build_instance(builder)
    expect(handle).not_to be_null
    context = described_class.ddwaf_context_init(handle, allocator)
    expect(context).not_to be_null

    parent_input = Datadog::AppSec::WAF::Converter.ruby_to_object({}, coerce: false)
    parent_result = described_class::Object.new
    code = described_class.ddwaf_context_eval(context, parent_input, allocator, parent_result, 10_000_000)
    parent_input_transferred = code != :ddwaf_err_invalid_argument

    expect(code).to eq(:ddwaf_ok)
    expect(described_class.ddwaf_object_get_type(parent_result)).to eq(:ddwaf_obj_map)

    subcontext = described_class.ddwaf_subcontext_init(context)
    expect(subcontext).not_to be_null
    child_input = Datadog::AppSec::WAF::Converter.ruby_to_object(
      {"server.request.headers.no_cookies" => {"user-agent" => "TraceTagging/v1"}}, coerce: false
    )
    child_result = described_class::Object.new
    code = described_class.ddwaf_subcontext_eval(subcontext, child_input, allocator, child_result, 10_000_000)
    child_input_transferred = code != :ddwaf_err_invalid_argument

    expect(code).to eq(:ddwaf_match)
    expect(described_class.ddwaf_object_get_type(child_result)).to eq(:ddwaf_obj_map)
  ensure
    described_class.ddwaf_object_destroy(child_result, allocator) if child_result
    described_class.ddwaf_object_destroy(parent_result, allocator) if parent_result
    described_class.ddwaf_subcontext_destroy(subcontext) if subcontext
    described_class.ddwaf_context_destroy(context) if context
    described_class.ddwaf_object_destroy(child_input, allocator) if child_input && !child_input_transferred
    described_class.ddwaf_object_destroy(parent_input, allocator) if parent_input && !parent_input_transferred
    described_class.ddwaf_destroy(handle) if handle
    described_class.ddwaf_builder_destroy(builder) if builder
    described_class.ddwaf_object_destroy(diagnostics, allocator) if diagnostics
    described_class.ddwaf_object_destroy(configuration, allocator) if configuration
  end
end
