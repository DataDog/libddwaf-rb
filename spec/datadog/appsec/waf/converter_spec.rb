# frozen_string_literal: true

require "spec_helper"
require "datadog/appsec/waf/lib_ddwaf"
require "datadog/appsec/waf/converter"

RSpec.describe Datadog::AppSec::WAF::Converter do
  let(:allocator) { Datadog::AppSec::WAF::LibDDWAF.ddwaf_get_default_allocator }

  describe ".ruby_to_object" do
    context "with coercion to string" do
      it "converts nil" do
        object = described_class.ruby_to_object(nil)
        expect(described_class.object_to_ruby(object)).to eq ""
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts an unhandled object" do
        object = described_class.ruby_to_object(Object.new)
        expect(described_class.object_to_ruby(object)).to eq ""
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a boolean" do
        true_object = described_class.ruby_to_object(true)
        expect(described_class.object_to_ruby(true_object)).to eq "true"
        false_object = described_class.ruby_to_object(false)
        expect(described_class.object_to_ruby(false_object)).to eq "false"
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(true_object, allocator) if true_object
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(false_object, allocator) if false_object
      end

      it "converts a symbol" do
        object = described_class.ruby_to_object(:foo)
        expect(described_class.object_to_ruby(object)).to eq "foo"
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a positive integer" do
        object = described_class.ruby_to_object(42)
        expect(described_class.object_to_ruby(object)).to eq "42"
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a float" do
        object = described_class.ruby_to_object(Math::PI)
        expect(described_class.object_to_ruby(object)).to eq "3.141592653589793"
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "propagates coercion through nested arrays and hashes" do
        object = described_class.ruby_to_object([1, {foo: [2, true]}])

        expect(described_class.object_to_ruby(object)).to eq(["1", {"foo" => ["2", "true"]}])
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    context "without coercion to string" do
      it "converts nil" do
        object = described_class.ruby_to_object(nil, coerce: false)
        expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_get_type(object)).to eq :ddwaf_obj_null
        expect(described_class.object_to_ruby(object)).to be_nil
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a boolean" do
        true_object = described_class.ruby_to_object(true, coerce: false)
        expect(described_class.object_to_ruby(true_object)).to eq true
        false_object = described_class.ruby_to_object(false, coerce: false)
        expect(described_class.object_to_ruby(false_object)).to eq false
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(true_object, allocator) if true_object
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(false_object, allocator) if false_object
      end

      it "converts a positive integer" do
        object = described_class.ruby_to_object(42, coerce: false)
        expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_get_type(object)).to eq :ddwaf_obj_unsigned
        expect(described_class.object_to_ruby(object)).to eq 42
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a negative integer" do
        object = described_class.ruby_to_object(-42, coerce: false)
        expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_get_type(object)).to eq :ddwaf_obj_signed
        expect(described_class.object_to_ruby(object)).to eq(-42)
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "clamps a positive integer bigger than 2^64 - 1" do
        object = described_class.ruby_to_object(2**65, coerce: false)
        expect(described_class.object_to_ruby(object)).to eq 2**64 - 1
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "clamps a negative integer smaller than -2^63" do
        object = described_class.ruby_to_object(-(2**65), coerce: false)
        expect(described_class.object_to_ruby(object)).to eq(-(2**63))
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a float" do
        object = described_class.ruby_to_object(Math::PI, coerce: false)
        expect(described_class.object_to_ruby(object)).to eq Math::PI
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    it "does not mark an empty array as truncated at the depth limit" do
      object = described_class.ruby_to_object([], max_container_depth: 0, coerce: false)

      expect(described_class.object_to_ruby(object)).to eq([])
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "does not mark an empty hash as truncated at the depth limit" do
      object = described_class.ruby_to_object({}, max_container_depth: 0, coerce: false)

      expect(described_class.object_to_ruby(object)).to eq({})
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    context "with JSON strings" do
      it "parses frozen JSONString values natively while preserving ordinary strings" do
        json = '{"value":[1,true,null,"é"]}'
        expect(JSON).not_to receive(:parse)

        object = described_class.ruby_to_object({
          "decoded" => Datadog::AppSec::WAF::JSONString.new(json).freeze,
          "literal" => json
        })

        expect(described_class.object_to_ruby(object)).to eq({
          "decoded" => {"value" => [1, true, nil, "é"]},
          "literal" => json
        })
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "destroys only the root when nested JSON parsing fails" do
        object = nil

        expect(Datadog::AppSec::WAF::LibDDWAF).to receive(:ddwaf_object_destroy)
          .with(an_instance_of(Datadog::AppSec::WAF::LibDDWAF::Object), allocator).once.and_wrap_original do |original, root, alloc|
            begin
              expect(described_class.object_to_ruby(root)).to eq({"safe" => "outer", "nested" => ["inner", nil]})
            ensure
              original.call(root, alloc)
            end
          end

        expect do
          object = described_class.ruby_to_object({"safe" => "outer", "nested" => ["inner", Datadog::AppSec::WAF::JSONString.new("{")]}, coerce: false)
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "Could not convert JSON string")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "rejects JSON exceeding the uint32 byte length before calling native code" do
        object = nil
        json_string = Datadog::AppSec::WAF::JSONString.new("null")
        allow(json_string).to receive(:bytesize).and_return(0x1_0000_0000)
        expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_object_from_json)

        expect do
          object = described_class.ruby_to_object(json_string, coerce: false)
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "JSON string exceeds the native length limit")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    context "with native width limits" do
      it "rejects strings exceeding the uint32 byte length before calling native code" do
        object = nil
        string = +"value"
        encoded_string = +"value"
        allow(string).to receive(:encode).with(Encoding::UTF_8, invalid: :replace, undef: :replace).and_return(encoded_string)
        allow(encoded_string).to receive(:bytesize).and_return(0x1_0000_0000)
        expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_object_set_string)

        expect do
          object = described_class.ruby_to_object(string)
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "String exceeds the native length limit")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "rejects map keys exceeding the uint32 byte length before inserting them" do
        object = nil
        key = +"key"
        # Preserve the stubbed key instead of letting Hash copy and freeze it.
        input = {}.compare_by_identity
        input[key] = 1
        allow(key).to receive(:bytesize).and_return(0x1_0000_0000)
        expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_object_insert_key)

        expect do
          object = described_class.ruby_to_object(input, coerce: false)
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "Map key exceeds the native length limit")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "rejects containers exceeding the uint16 capacity before calling native code" do
        object = nil
        expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_object_set_array)

        expect do
          object = described_class.ruby_to_object(Array.new(0x1_0000))
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "Container exceeds the native size limit")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    context "with container size limit" do
      it "marks nested arrays exceeding limit as input truncated" do
        object = described_class.ruby_to_object([(1..6).to_a], max_container_size: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq([[1, 2, 3]])
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "does not mark arrays at the limit as truncated" do
        object = described_class.ruby_to_object([1, 2, 3], max_container_size: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq([1, 2, 3])
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "marks nested hashes exceeding limit as input truncated" do
        object = described_class.ruby_to_object({some_key: {foo: 1, bar: 2, baz: 3, qux: 4}}, max_container_size: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({"some_key" => {"foo" => 1, "bar" => 2, "baz" => 3}})
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "does not mark hashes at the limit as truncated" do
        object = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3}, max_container_size: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({"foo" => 1, "bar" => 2, "baz" => 3})
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    context "with container depth limit" do
      it "converts nested arrays up to the limit" do
        object = described_class.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq([1, [2, [3, []]]])
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "does not mark nested arrays within limit as truncated" do
        object = described_class.ruby_to_object([1, [2, [3]]], max_container_depth: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq([1, [2, [3]]])
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts nested hashes up to the limit" do
        object = described_class.ruby_to_object({foo: {bar: {baz: {qux: 4}}}}, max_container_depth: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({"foo" => {"bar" => {"baz" => {}}}})
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "does not mark nested hashes within limit as truncated" do
        object = described_class.ruby_to_object({foo: {bar: {baz: :qux}}}, max_container_depth: 3, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({"foo" => {"bar" => {"baz" => "qux"}}})
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    context "with string length limit" do
      it "truncates nested strings by character count and marks the root" do
        object = described_class.ruby_to_object(["é\0尾😀tail"], max_string_length: 4, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq(["é\0尾😀"])
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "does not mark a string at the limit as truncated" do
        object = described_class.ruby_to_object("a" * 10, max_string_length: 10, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq("a" * 10)
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "truncates nested symbol values and marks the root" do
        object = described_class.ruby_to_object({foo: :abcdefghijk}, max_string_length: 10, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({"foo" => "abcdefghij"})
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "truncates nested hash keys after string conversion and marks the root" do
        object = described_class.ruby_to_object({foo: {abcdefghijk: 42}}, max_string_length: 10, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({"foo" => {"abcdefghij" => 42}})
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end
  end

  describe ".object_to_ruby" do
    it "converts nested arrays and maps with stringified keys" do
      object = described_class.ruby_to_object({"é" => [{bar: [42]}], 21 => 10.5}, coerce: false)

      expect(described_class.object_to_ruby(object)).to eq({"é" => [{"bar" => [42]}], "21" => 10.5})
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "preserves ASCII strings with binary encoding" do
      object = described_class.ruby_to_object("Hello, world!")

      result = described_class.object_to_ruby(object)

      expect(result).to eq("Hello, world!")
      expect(result.encoding).to eq(Encoding::ASCII_8BIT)
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "restores UTF-8 encoding for non-ASCII strings, preserving embedded NULs" do
      object = described_class.ruby_to_object("é\0尾😀")

      result = described_class.object_to_ruby(object)

      expect(result).to eq("é\0尾😀")
      expect(result.encoding).to eq(Encoding::UTF_8)
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end
  end
end
