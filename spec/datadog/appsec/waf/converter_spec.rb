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

    context "with request limits" do
      let(:limits) do
        {max_container_size: 256, max_container_depth: 20, max_string_length: 16_384}.freeze
      end

      it "rejects a non-Hash input before allocating native objects" do
        object = nil
        expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_get_default_allocator)

        expect do
          object = described_class.ruby_to_object([], limits: limits, coerce: false)
        end.to raise_error(TypeError, "WAF input must be a Hash")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "accepts an empty input without marking it as truncated" do
        object = described_class.ruby_to_object({}, limits: limits, coerce: false)

        expect(described_class.object_to_ruby(object)).to eq({})
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "limits payload containers and text while preserving complete addresses" do
        object = described_class.ruby_to_object(
          {
            :"server.request.body" => ["ééé", "discarded"],
            "server.request.query" => {"ééé".encode(Encoding::UTF_16LE) => :"😀😀", "discarded" => 1}
          },
          limits: limits.merge(max_container_size: 1, max_string_length: 5), coerce: false
        )

        expect(described_class.object_to_ruby(object)).to eq({
          "server.request.body" => ["éé"],
          "server.request.query" => {"éé" => "😀"}
        })
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "does not mark payloads at the limits or empty nested containers as truncated" do
        object = described_class.ruby_to_object(
          {"server.request.body" => {"éé" => ["éé", {}], "arr" => [[], nil]}},
          limits: limits.merge(max_container_size: 2, max_container_depth: 2, max_string_length: 4), coerce: false
        )

        expect(described_class.object_to_ruby(object)).to eq({"server.request.body" => {"éé" => ["éé", {}], "arr" => [[], nil]}})
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "counts custom depth from the first payload container" do
        object = described_class.ruby_to_object(
          {"server.request.body" => {"array" => [1], "map" => {"key" => 2}}},
          limits: limits.merge(max_container_depth: 1), coerce: false
        )

        expect(described_class.object_to_ruby(object)).to eq({"server.request.body" => {"array" => [], "map" => {}}})
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "keeps the Ruby safety caps when custom limits are larger" do
        deep_value = "leaf"
        20.times { deep_value = [deep_value] }
        limited_depth = []
        19.times { limited_depth = [limited_depth] }

        object = described_class.ruby_to_object(
          {"array" => Array.new(257, 0), "string" => "a" * 4097, "depth" => deep_value},
          limits: {max_container_size: 1000, max_container_depth: 1000, max_string_length: 100_000}, coerce: false
        )

        expect(described_class.object_to_ruby(object)).to eq({
          "array" => Array.new(256, 0), "string" => "a" * 4096, "depth" => limited_depth
        })
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "omits oversized addresses and counts them within the first 256 source entries" do
        input = {("😀" * 4097) => "discarded"}
        256.times { |index| input["address#{index}"] = "value" }
        object = described_class.ruby_to_object(input, limits: limits, coerce: false)

        expect(described_class.object_to_ruby(object).keys).to eq((0...255).map { |index| "address#{index}" })
        expect(object).to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "parses JSONString payloads without applying request limits" do
        json = Datadog::AppSec::WAF::JSONString.new('{"items":["value","other"]}')
        object = described_class.ruby_to_object(
          {"body" => json},
          limits: limits.merge(max_container_size: 1, max_container_depth: 1, max_string_length: 1),
          coerce: false
        )

        expect(described_class.object_to_ruby(object)).to eq({"body" => {"items" => ["value", "other"]}})
        expect(object).not_to be_truncated
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end
  end

  describe ".truncate_string_bytes" do
    it "keeps a string at the byte limit without marking the root as truncated" do
      root = Datadog::AppSec::WAF::LibDDWAF::Object.new

      result = described_class.truncate_string_bytes("éé", max_bytes: 4, top_obj: root)

      expect(result).to eq("éé")
      expect(root).not_to be_truncated
    end

    it "drops an incomplete trailing character and marks the root as truncated" do
      root = Datadog::AppSec::WAF::LibDDWAF::Object.new

      result = described_class.truncate_string_bytes("ééé", max_bytes: 5, top_obj: root)

      expect(result).to eq("éé")
      expect(root).to be_truncated
    end

    it "returns an empty string when the first character does not fit" do
      root = Datadog::AppSec::WAF::LibDDWAF::Object.new

      result = described_class.truncate_string_bytes("é", max_bytes: 1, top_obj: root)

      expect(result).to eq("")
      expect(root).to be_truncated
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
