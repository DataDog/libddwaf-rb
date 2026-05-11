# frozen_string_literal: true

require "spec_helper"

RSpec.describe Datadog::AppSec::WAF::Converter do
  describe ".ruby_to_object" do
    context "with coercion to string" do
      it "converts nil" do
        obj = described_class.ruby_to_object(nil)
        expect(obj.type).to eq :ddwaf_obj_string
        expect(obj.nb_entries).to eq 0
        expect(obj.string_bytes).to eq ""
        expect(obj).not_to be_truncated
      end

      it "converts an unhandled object" do
        obj = described_class.ruby_to_object(Object.new)
        expect(obj.type).to eq :ddwaf_obj_string
        expect(obj.nb_entries).to eq 0
        expect(obj.string_bytes).to eq ""
      end

      it "converts a boolean" do
        obj = described_class.ruby_to_object(true)
        expect(obj.type).to eq :ddwaf_obj_string
        expect(obj.string_bytes).to eq "true"

        obj = described_class.ruby_to_object(false)
        expect(obj.string_bytes).to eq "false"
      end

      it "converts a string" do
        obj = described_class.ruby_to_object("foo")
        expect(obj.type).to eq :ddwaf_obj_string
        expect(obj.string_bytes).to eq "foo"
      end

      it "converts a binary string" do
        obj = described_class.ruby_to_object("foo\x00bar")
        expect(obj.nb_entries).to eq 7
        expect(obj.string_bytes).to eq "foo\x00bar"
      end

      it "converts a symbol" do
        obj = described_class.ruby_to_object(:foo)
        expect(obj.string_bytes).to eq "foo"
      end

      it "converts a positive integer" do
        obj = described_class.ruby_to_object(42)
        expect(obj.string_bytes).to eq "42"
      end

      it "converts a negative integer" do
        obj = described_class.ruby_to_object(-42)
        expect(obj.string_bytes).to eq "-42"
      end

      it "converts a float" do
        obj = described_class.ruby_to_object(Math::PI)
        expect(obj.string_bytes).to eq "3.141592653589793"
      end

      it "converts an empty array" do
        obj = described_class.ruby_to_object([])
        expect(obj.type).to eq :ddwaf_obj_array
        expect(obj.nb_entries).to eq 0
      end

      it "converts a non-empty array" do
        obj = described_class.ruby_to_object((1..6).to_a)
        expect(obj.type).to eq :ddwaf_obj_array
        expect(obj.nb_entries).to eq 6
        values = (0...obj.nb_entries).map { |i| obj.array_index(i).string_bytes }
        expect(values).to eq ("1".."6").to_a
      end

      it "converts an empty hash" do
        obj = described_class.ruby_to_object({})
        expect(obj.type).to eq :ddwaf_obj_map
        expect(obj.nb_entries).to eq 0
      end

      it "converts a non-empty hash" do
        obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3})
        expect(obj.type).to eq :ddwaf_obj_map
        hash = (0...obj.nb_entries).each.with_object({}) do |i, h|
          entry = obj.array_index(i)
          h[entry.key_bytes] = entry.string_bytes
        end
        expect(hash).to eq({"foo" => "1", "bar" => "2", "baz" => "3"})
      end

      it "converts a big value" do
        require "json"
        data = JSON.parse(File.read(File.expand_path("../../../fixtures/waf_rules.json", __dir__)))
        described_class.ruby_to_object(data)
      end

      context "with limits" do
        it "truncates arrays at container size limit" do
          obj = described_class.ruby_to_object((1..6).to_a, max_container_size: 3)
          expect(obj.nb_entries).to eq 3
          expect(obj).to be_truncated
        end

        it "does not mark arrays within the limit as truncated" do
          obj = described_class.ruby_to_object([1, 2, 3], max_container_size: 3)
          expect(obj).not_to be_truncated
        end

        it "truncates hashes at container size limit" do
          obj = described_class.ruby_to_object({a: 1, b: 2, c: 3, d: 4}, max_container_size: 3)
          expect(obj.nb_entries).to eq 3
          expect(obj).to be_truncated
        end

        it "truncates at container depth limit" do
          obj = described_class.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: 3)
          expect(obj).to be_truncated
        end

        it "truncates strings at length limit" do
          obj = described_class.ruby_to_object("a" * 80, max_string_length: 10)
          expect(obj.nb_entries).to eq 10
          expect(obj).to be_truncated
        end

        it "truncates hash keys at length limit" do
          obj = described_class.ruby_to_object({("a" * 80) => 1}, max_string_length: 10)
          expect(obj).to be_truncated
          expect(obj.array_index(0).key_bytes.bytesize).to eq 10
        end
      end
    end

    context "without coercion to string" do
      it "converts nil to ddwaf_obj_null" do
        obj = described_class.ruby_to_object(nil, coerce: false)
        expect(obj.type).to eq :ddwaf_obj_null
      end

      it "converts a boolean" do
        obj = described_class.ruby_to_object(true, coerce: false)
        expect(obj.type).to eq :ddwaf_obj_bool
        expect(obj.bool_value).to be true
      end

      it "converts a positive integer to unsigned" do
        obj = described_class.ruby_to_object(42, coerce: false)
        expect(obj.type).to eq :ddwaf_obj_unsigned
        expect(obj.unsigned_value).to eq 42
      end

      it "converts a negative integer to signed" do
        obj = described_class.ruby_to_object(-42, coerce: false)
        expect(obj.type).to eq :ddwaf_obj_signed
        expect(obj.signed_value).to eq(-42)
      end

      it "clamps a positive integer bigger than 2^64 - 1" do
        obj = described_class.ruby_to_object(2**65, coerce: false)
        expect(obj.unsigned_value).to eq 2**64 - 1
      end

      it "clamps a negative integer smaller than -2^63" do
        obj = described_class.ruby_to_object(-(2**65), coerce: false)
        expect(obj.signed_value).to eq(-(2**63))
      end

      it "converts a float to ddwaf_obj_float" do
        obj = described_class.ruby_to_object(Math::PI, coerce: false)
        expect(obj.type).to eq :ddwaf_obj_float
        expect(obj.float_value).to eq Math::PI
      end

      it "converts a non-empty array" do
        obj = described_class.ruby_to_object((1..6).to_a, coerce: false)
        values = (0...obj.nb_entries).map { |i| obj.array_index(i).unsigned_value }
        expect(values).to eq (1..6).to_a
      end

      it "converts a non-empty hash" do
        obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3}, coerce: false)
        hash = (0...obj.nb_entries).each.with_object({}) do |i, h|
          entry = obj.array_index(i)
          h[entry.key_bytes] = entry.unsigned_value
        end
        expect(hash).to eq({"foo" => 1, "bar" => 2, "baz" => 3})
      end
    end
  end

  describe ".object_to_ruby" do
    it "round-trips a boolean" do
      expect(described_class.object_to_ruby(described_class.ruby_to_object(true, coerce: false))).to be true
      expect(described_class.object_to_ruby(described_class.ruby_to_object(false, coerce: false))).to be false
    end

    it "round-trips an array recursively" do
      obj = described_class.ruby_to_object(["a", 1, :foo, {bar: [42]}], coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(["a", 1, "foo", {"bar" => [42]}])
    end

    it "round-trips a map recursively" do
      obj = described_class.ruby_to_object({:foo => [{bar: [42]}], 21 => 10.5}, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq({"foo" => [{"bar" => [42]}], "21" => 10.5})
    end

    context "with string values" do
      it "returns ASCII as ASCII_8BIT" do
        s = "Hello, world!"
        result = described_class.object_to_ruby(described_class.ruby_to_object(s))
        expect(result).to eq(s)
        expect(result.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it "returns UTF-8 with non-ASCII bytes force-encoded UTF-8" do
        s = "UTF-8: é à ö"
        result = described_class.object_to_ruby(described_class.ruby_to_object(s))
        expect(result).to eq(s)
        expect(result.encoding).to eq(Encoding::UTF_8)
      end

      it "preserves complex Unicode round-trips" do
        s = "😀🌍 Unicode"
        result = described_class.object_to_ruby(described_class.ruby_to_object(s))
        expect(result).to eq(s)
        expect(result.valid_encoding?).to be true
      end
    end
  end
end
