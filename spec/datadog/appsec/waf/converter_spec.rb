# frozen_string_literal: true

require "spec_helper"
require "datadog/appsec/waf/lib_ddwaf"
require "datadog/appsec/waf/converter"

RSpec.describe Datadog::AppSec::WAF::Converter do
  let(:allocator) { Datadog::AppSec::WAF::LibDDWAF.ddwaf_get_default_allocator }

  describe ".ruby_to_object" do
    context "with values converted to strings" do
      it "converts an unhandled object" do
        object = described_class.ruby_to_object(Object.new)
        expect(described_class.object_to_ruby(object)).to eq ""
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a symbol" do
        object = described_class.ruby_to_object(:foo)
        expect(described_class.object_to_ruby(object)).to eq "foo"
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    context "with native scalar types" do
      it "converts nil" do
        object = described_class.ruby_to_object(nil)
        expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_get_type(object)).to eq :ddwaf_obj_null
        expect(described_class.object_to_ruby(object)).to be_nil
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a boolean" do
        true_object = described_class.ruby_to_object(true)
        expect(described_class.object_to_ruby(true_object)).to eq true
        false_object = described_class.ruby_to_object(false)
        expect(described_class.object_to_ruby(false_object)).to eq false
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(true_object, allocator) if true_object
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(false_object, allocator) if false_object
      end

      it "converts a positive integer" do
        object = described_class.ruby_to_object(42)
        expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_get_type(object)).to eq :ddwaf_obj_unsigned
        expect(described_class.object_to_ruby(object)).to eq 42
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a negative integer" do
        object = described_class.ruby_to_object(-42)
        expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_get_type(object)).to eq :ddwaf_obj_signed
        expect(described_class.object_to_ruby(object)).to eq(-42)
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "clamps a positive integer bigger than 2^64 - 1" do
        object = described_class.ruby_to_object(2**65)
        expect(described_class.object_to_ruby(object)).to eq 2**64 - 1
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "clamps a negative integer smaller than -2^63" do
        object = described_class.ruby_to_object(-(2**65))
        expect(described_class.object_to_ruby(object)).to eq(-(2**63))
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "converts a float" do
        object = described_class.ruby_to_object(Math::PI)
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
          object = described_class.ruby_to_object({"safe" => "outer", "nested" => ["inner", Datadog::AppSec::WAF::JSONString.new("{")]})
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
          object = described_class.ruby_to_object(json_string)
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
          object = described_class.ruby_to_object(string, truncate: false)
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
          object = described_class.ruby_to_object(input, truncate: false)
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "Map key exceeds the native length limit")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "rejects containers exceeding the uint16 capacity before calling native code" do
        object = nil
        expect(Datadog::AppSec::WAF::LibDDWAF).not_to receive(:ddwaf_object_set_array)

        expect do
          object = described_class.ruby_to_object(Array.new(0x1_0000), truncate: false)
        end.to raise_error(Datadog::AppSec::WAF::ConversionError, "Container exceeds the native size limit")
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end
    end

    it "does not apply request limits when truncation is disabled" do
      deep_value = "leaf"
      (described_class::MAX_CONTAINER_DEPTH + 1).times { deep_value = [deep_value] }
      input = {
        "string" => "a" * (described_class::MAX_STRING_LENGTH + 1),
        "array" => Array.new(described_class::MAX_CONTAINER_SIZE + 1, 0),
        "depth" => deep_value
      }
      object = described_class.ruby_to_object(input, truncate: false)

      expect(described_class.object_to_ruby(object)).to eq(input)
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end
  end

  describe ".ruby_to_object with truncation" do
    it "accepts an empty input without marking it as truncated" do
      object = described_class.ruby_to_object({})

      expect(described_class.object_to_ruby(object)).to eq({})
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "preserves scalar types and stringifies symbols and map keys" do
      object = described_class.ruby_to_object({body: [1, -2, 1.5, true, false, nil, :symbol, {42 => "value"}]})

      expect(described_class.object_to_ruby(object)).to eq({"body" => [1, -2, 1.5, true, false, nil, "symbol", {"42" => "value"}]})
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    [0, 1].each do |overflow|
      it "#{overflow.zero? ? "preserves" : "truncates"} multibyte strings and keys #{overflow.zero? ? "at" : "above"} the character limit" do
        key = ("é" * (described_class::MAX_STRING_LENGTH + overflow)).encode(Encoding::UTF_16LE)
        value = ("😀" * (described_class::MAX_STRING_LENGTH + overflow)).to_sym
        object = described_class.ruby_to_object({key => {key => value}})

        expected_key = "é" * described_class::MAX_STRING_LENGTH
        expect(described_class.object_to_ruby(object)).to eq({expected_key => {expected_key => "😀" * described_class::MAX_STRING_LENGTH}})
        expect(object.truncated?).to eq(overflow.positive?)
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      it "#{overflow.zero? ? "preserves" : "truncates"} arrays and maps #{overflow.zero? ? "at" : "above"} the container size limit" do
        size = described_class::MAX_CONTAINER_SIZE
        entries = (size + overflow).times.map { |i| [i.to_s, i] }
        object = described_class.ruby_to_object({"array" => entries.map(&:last), "map" => entries.to_h})

        expect(described_class.object_to_ruby(object)).to eq({"array" => (0...size).to_a, "map" => entries.first(size).to_h})
        expect(object.truncated?).to eq(overflow.positive?)
      ensure
        Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
      end

      [:array, :map].each do |kind|
        it "#{overflow.zero? ? "preserves" : "truncates"} #{kind} containers #{overflow.zero? ? "at" : "above"} the depth limit below the address map" do
          input = "leaf"
          expected = (kind == :array) ? [] : {}
          expected = "leaf" if overflow.zero?
          (described_class::MAX_CONTAINER_DEPTH + overflow).times { input = (kind == :array) ? [input] : {"key" => input} }
          described_class::MAX_CONTAINER_DEPTH.times { expected = (kind == :array) ? [expected] : {"key" => expected} }
          object = described_class.ruby_to_object({"body" => input})

          expect(described_class.object_to_ruby(object)).to eq({"body" => expected})
          expect(object.truncated?).to eq(overflow.positive?)
        ensure
          Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
        end
      end
    end

    it "does not mark empty containers beyond the depth limit as truncated" do
      value = {"array" => [], "map" => {}}
      (described_class::MAX_CONTAINER_DEPTH - 1).times { value = [value] }
      object = described_class.ruby_to_object({"body" => value})

      expect(described_class.object_to_ruby(object)).to eq({"body" => value})
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "keeps all addresses when the top-level map exceeds the payload container size limit" do
      input = (described_class::MAX_CONTAINER_SIZE + 1).times.map { |i| ["address#{i}", i] }.to_h
      object = described_class.ruby_to_object(input)

      expect(described_class.object_to_ruby(object)).to eq(input)
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "truncates an address map exceeding native capacity instead of raising" do
      input = (described_class::UINT16_MAX + 1).times.map { |i| ["address#{i}", i] }.to_h
      object = described_class.ruby_to_object(input)
      result = described_class.object_to_ruby(object)

      expect(result.size).to eq(described_class::UINT16_MAX)
      expect(result).not_to have_key("address#{described_class::UINT16_MAX}")
      expect(object).to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end

    it "parses JSONString payloads without applying request limits" do
      payload = {"items" => Array.new(described_class::MAX_CONTAINER_SIZE + 1, "a" * (described_class::MAX_STRING_LENGTH + 1))}
      json = Datadog::AppSec::WAF::JSONString.new(JSON.generate(payload))
      object = described_class.ruby_to_object({"body" => json})

      expect(described_class.object_to_ruby(object)).to eq({"body" => payload})
      expect(object).not_to be_truncated
    ensure
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_destroy(object, allocator) if object
    end
  end

  describe ".object_to_ruby" do
    it "converts nested arrays and maps with stringified keys" do
      object = described_class.ruby_to_object({"é" => [{bar: [42]}], 21 => 10.5})

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
