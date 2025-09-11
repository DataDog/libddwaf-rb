# frozen_string_literal: true

require "spec_helper"
require "datadog/appsec/waf/lib_ddwaf"
require "datadog/appsec/waf/converter"

RSpec.describe Datadog::AppSec::WAF::Converter do
  describe ".ruby_to_object" do
    context "with coercion to string" do
      it "converts nil" do
        obj = described_class.ruby_to_object(nil)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ""
        expect(obj).not_to be_truncated
      end

      it "converts an unhandled object" do
        obj = described_class.ruby_to_object(Object.new)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ""
        expect(obj).not_to be_truncated
      end

      it "converts a boolean" do
        obj = described_class.ruby_to_object(true)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 4
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "true"
        obj = described_class.ruby_to_object(false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 5
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "false"
        expect(obj).not_to be_truncated
      end

      it "converts a string" do
        obj = described_class.ruby_to_object("foo")
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo"
        expect(obj).not_to be_truncated
      end

      it "converts a binary string" do
        obj = described_class.ruby_to_object("foo\x00bar")
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 7
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
        expect(obj).not_to be_truncated
      end

      it "converts a symbol" do
        obj = described_class.ruby_to_object(:foo)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo"
        expect(obj).not_to be_truncated
      end

      it "converts a positive integer" do
        obj = described_class.ruby_to_object(42)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 2
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "42"
        expect(obj).not_to be_truncated
      end

      it "converts a negative integer" do
        obj = described_class.ruby_to_object(-42)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "-42"
        expect(obj).not_to be_truncated
      end

      it "converts a float" do
        obj = described_class.ruby_to_object(Math::PI)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 17
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "3.141592653589793"
        expect(obj).not_to be_truncated
      end

      it "converts an empty array" do
        obj = described_class.ruby_to_object([])
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
        expect(obj).not_to be_truncated
      end

      it "converts a non-empty array" do
        obj = described_class.ruby_to_object((1..6).to_a)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 6
        expect(obj).not_to be_truncated
        array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
          ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
          o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
          l = o[:nbEntries]
          v = o[:valueUnion][:stringValue].read_bytes(l)
          a << v
        end
        expect(array).to eq ("1".."6").to_a
      end

      it "converts an empty hash" do
        obj = described_class.ruby_to_object({})
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
        expect(obj).not_to be_truncated
      end

      it "converts a non-empty hash" do
        obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3})
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 3
        expect(obj).not_to be_truncated
        hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
          ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
          o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
          l = o[:parameterNameLength]
          k = o[:parameterName].read_bytes(l)
          l = o[:nbEntries]
          v = o[:valueUnion][:stringValue].read_bytes(l)
          h[k] = v
        end
        expect(hash).to eq({"foo" => "1", "bar" => "2", "baz" => "3"})
      end

      it "converts a big value" do
        require "json"

        data = JSON.parse(File.read(File.expand_path("../../../fixtures/waf_rules.json", __dir__)))
        described_class.ruby_to_object(data)
      end

      context "with limits" do
        context "with container size limit" do
          it "converts an array up to the limit" do
            obj = described_class.ruby_to_object((1..6).to_a, max_container_size: 3)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 3
            expect(obj).to be_truncated

            array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              l = o[:nbEntries]
              v = o[:valueUnion][:stringValue].read_bytes(l)
              a << v
            end
            expect(array).to eq ("1".."3").to_a
          end

          it "does not mark arrays within the limit as truncated" do
            obj = described_class.ruby_to_object((1..3).to_a, max_container_size: 3)
            expect(obj[:type]).to eq(:ddwaf_obj_array)
            expect(obj[:nbEntries]).to eq(3)
            expect(obj).not_to be_truncated
          end

          it "converts a hash up to the limit" do
            obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3, qux: 4}, max_container_size: 3)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 3
            expect(obj).to be_truncated

            hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              l = o[:parameterNameLength]
              k = o[:parameterName].read_bytes(l)
              l = o[:nbEntries]
              v = o[:valueUnion][:stringValue].read_bytes(l)
              h[k] = v
            end
            expect(hash).to eq({"foo" => "1", "bar" => "2", "baz" => "3"})
          end

          it "does not mark hashes within the limit as truncated" do
            obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3}, max_container_size: 3)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 3
            expect(obj).not_to be_truncated
          end
        end

        context "with container depth limit" do
          it "converts nested arrays up to the limit" do
            obj = described_class.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: 3)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 2
            expect(obj).to be_truncated

            ptr1 = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = obj[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq "1"

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq "2"

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq "3"

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 0
          end

          it "does not mark nested arrays within limit as truncated" do
            obj = described_class.ruby_to_object([1, [2, [3]]], max_container_depth: 3)
            expect(obj[:type]).to eq(:ddwaf_obj_array)
            expect(obj).not_to be_truncated
          end

          it "converts nested hashes up to the limit" do
            obj = described_class.ruby_to_object({foo: {bar: {baz: {qux: 4}}}}, max_container_depth: 3)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1
            expect(obj).to be_truncated

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq "foo"

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq "bar"

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq "baz"

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 0
          end

          it "does not mark nested hashes within limit as truncated" do
            obj = described_class.ruby_to_object({foo: {bar: {baz: :qux}}}, max_container_depth: 3)
            expect(obj[:type]).to eq(:ddwaf_obj_map)
            expect(obj).not_to be_truncated
          end
        end

        context "with string length limit" do
          it "converts a string up to the limit" do
            obj = described_class.ruby_to_object(+"foo" << "o" * 80, max_string_length: 10)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "fooooooooo"
            expect(obj).to be_truncated
          end

          it "does not mark a string as truncated if it is withing the length limit" do
            obj = described_class.ruby_to_object("a" * 10, max_string_length: 10)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj).not_to be_truncated
          end

          it "converts a binary string up to the limit" do
            obj = described_class.ruby_to_object(+"foo\x00bar" << "r" * 80, max_string_length: 10)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00barrrr"
            expect(obj).to be_truncated
          end

          it "converts a symbol up to the limit" do
            obj = described_class.ruby_to_object((+"foo" << "o" * 80).to_sym, max_string_length: 10)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "fooooooooo"
            expect(obj).to be_truncated
          end

          it "converts hash keys up to the limit" do
            obj = described_class.ruby_to_object({(+"foo" << "o" * 80) => 42}, max_string_length: 10)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(l).to eq 10
            expect(k).to eq "fooooooooo"
            expect(obj).to be_truncated
          end

          it "converts hash with a nil key" do
            obj = described_class.ruby_to_object({nil => :foo}, max_string_length: 10)
            expect(obj[:type]).to eq(:ddwaf_obj_map)
            expect(obj[:nbEntries]).to eq(1)
            expect(obj).not_to be_truncated
          end
        end
      end
    end

    context "without coercion to string" do
      it "converts nil" do
        obj = described_class.ruby_to_object(nil, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_null
        expect(obj[:nbEntries]).to eq 0
      end

      it "converts an unhandled object" do
        # TODO: coerced because of arrays and maps

        obj = described_class.ruby_to_object(Object.new, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ""
      end

      it "converts a boolean" do
        obj = described_class.ruby_to_object(true, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_bool
        expect(obj[:valueUnion][:boolean]).to eq true
        obj = described_class.ruby_to_object(false, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_bool
        expect(obj[:valueUnion][:boolean]).to eq false
      end

      it "converts a string" do
        obj = described_class.ruby_to_object("foo", coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo"
      end

      it "converts a binary string" do
        obj = described_class.ruby_to_object("foo\x00bar", coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 7
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
      end

      it "converts a symbol" do
        obj = described_class.ruby_to_object(:foo, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo"
      end

      it "converts a positive integer" do
        obj = described_class.ruby_to_object(42, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_unsigned
        expect(obj[:valueUnion][:uintValue]).to eq 42
      end

      it "converts a negative integer" do
        obj = described_class.ruby_to_object(-42, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_signed
        expect(obj[:valueUnion][:intValue]).to eq(-42)
      end

      it "converts a float" do
        obj = described_class.ruby_to_object(Math::PI, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_float
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:f64]).to eq Math::PI
      end

      it "converts an empty array" do
        obj = described_class.ruby_to_object([], coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it "converts a non-empty array" do
        obj = described_class.ruby_to_object((1..6).to_a, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 6
        array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
          ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
          o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
          v = o[:valueUnion][:uintValue]
          a << v
        end
        expect(array).to eq (1..6).to_a
      end

      it "converts an empty hash" do
        obj = described_class.ruby_to_object({}, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it "converts a non-empty hash" do
        obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3}, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 3
        hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
          ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
          o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
          l = o[:parameterNameLength]
          k = o[:parameterName].read_bytes(l)
          v = o[:valueUnion][:uintValue]
          h[k] = v
        end
        expect(hash).to eq({"foo" => 1, "bar" => 2, "baz" => 3})
      end

      it "converts a big value" do
        data = JSON.parse(File.read(File.expand_path("../../../fixtures/waf_rules.json", __dir__)))
        described_class.ruby_to_object(data)
      end

      context "with limits" do
        context "with container size limit" do
          it "converts an array up to the limit" do
            obj = described_class.ruby_to_object((1..6).to_a, max_container_size: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 3
            expect(obj).to be_truncated

            array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              v = o[:valueUnion][:uintValue]
              a << v
            end
            expect(array).to eq (1..3).to_a
          end

          it "marks nested arrays exceeding limit as input truncated" do
            obj = described_class.ruby_to_object([(1..6).to_a], max_container_size: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj).to be_truncated
          end

          it "does not mark arrays within the limit as truncated" do
            obj = described_class.ruby_to_object((1..3).to_a, max_container_size: 3, coerce: false)
            expect(obj[:type]).to eq(:ddwaf_obj_array)
            expect(obj[:nbEntries]).to eq(3)
            expect(obj).not_to be_truncated
          end

          it "converts a hash up to the limit" do
            obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3, qux: 4}, max_container_size: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 3
            expect(obj).to be_truncated

            hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              l = o[:parameterNameLength]
              k = o[:parameterName].read_bytes(l)
              v = o[:valueUnion][:uintValue]
              h[k] = v
            end
            expect(hash).to eq({"foo" => 1, "bar" => 2, "baz" => 3})
          end

          it "marks nested hashes exceeding limit as input truncated" do
            obj = described_class.ruby_to_object({some_key: {foo: 1, bar: 2, baz: 3, qux: 4}}, max_container_size: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj).to be_truncated
          end

          it "does not mark hashes within the limit as truncated" do
            obj = described_class.ruby_to_object({foo: 1, bar: 2, baz: 3}, max_container_size: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 3
            expect(obj).not_to be_truncated
          end

          it "marks hash with symbol keys exceeding length limit as input truncated" do
            hash = { foo: { ("a" * 20).to_sym => :bar } }
            obj = described_class.ruby_to_object(hash, max_string_length: 10)

            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1
            expect(obj).to be_truncated
          end

          it "marks hash with string values exceeding length limit as input truncated" do
            hash = { foo: "a" * 20 }
            obj = described_class.ruby_to_object(hash, max_string_length: 10)

            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1
            expect(obj).to be_truncated
          end

          it "marks hash symbol values exceeding length limit as input truncated" do
            hash = { foo: ("a" * 20).to_sym }
            obj = described_class.ruby_to_object(hash, max_string_length: 10)

            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1
            expect(obj).to be_truncated
          end
        end

        context "with container depth limit" do
          it "converts nested arrays up to the limit" do
            obj = described_class.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 2

            ptr1 = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = obj[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_unsigned
            v = o1[:valueUnion][:uintValue]
            expect(v).to eq 1

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_unsigned
            v = o1[:valueUnion][:uintValue]
            expect(v).to eq 2

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_unsigned
            v = o1[:valueUnion][:uintValue]
            expect(v).to eq 3

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 0
          end

          it "does not mark nested arrays within limit as truncated" do
            obj = described_class.ruby_to_object([1, [2, [3]]], max_container_depth: 3, coerce: false)
            expect(obj[:type]).to eq(:ddwaf_obj_array)
            expect(obj).not_to be_truncated
          end

          it "converts nested hashes up to the limit" do
            obj = described_class.ruby_to_object({foo: {bar: {baz: {qux: 4}}}}, max_container_depth: 3, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq "foo"

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq "bar"

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq "baz"

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 0
          end

          it "does not mark nested hashes within limit as truncated" do
            obj = described_class.ruby_to_object({foo: {bar: {baz: :qux}}}, max_container_depth: 3, coerce: false)
            expect(obj[:type]).to eq(:ddwaf_obj_map)
            expect(obj).not_to be_truncated
          end
        end

        context "with string length limit" do
          it "converts a string up to the limit" do
            obj = described_class.ruby_to_object(+"foo" << "o" * 80, max_string_length: 10, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "fooooooooo"
          end

          it "does not mark a string as truncated if it is withing the length limit" do
            obj = described_class.ruby_to_object("a" * 10, max_string_length: 10, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj).not_to be_truncated
          end

          it "converts a binary string up to the limit" do
            obj = described_class.ruby_to_object(+"foo\x00bar" << "r" * 80, max_string_length: 10, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00barrrr"
          end

          it "converts a symbol up to the limit" do
            obj = described_class.ruby_to_object((+"foo" << "o" * 80).to_sym, max_string_length: 10, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "fooooooooo"
          end

          it "marks arrays with string values exceeding length limit as input truncated" do
            arr = ["a" * 20, "b"]
            obj = described_class.ruby_to_object(arr, max_string_length: 10)

            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 2
          end

          it "converts hash keys up to the limit" do
            obj = described_class.ruby_to_object({(+"foo" << "o" * 80) => 42}, max_string_length: 10, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(l).to eq 10
            expect(k).to eq "fooooooooo"
          end
        end
      end
    end
  end

  describe ".object_to_ruby" do
    it "converts a boolean" do
      obj = described_class.ruby_to_object(true, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(true)
      obj = described_class.ruby_to_object(false, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(false)
    end

    it "converts a string" do
      obj = described_class.ruby_to_object("foo")
      expect(described_class.object_to_ruby(obj)).to eq("foo")
    end

    it "converts a nil" do
      obj = described_class.ruby_to_object(nil, coerce: false)
      expect(described_class.object_to_ruby(obj)).to be_nil
    end

    it "converts an array" do
      obj = described_class.ruby_to_object(("a".."f").to_a)
      expect(described_class.object_to_ruby(obj)).to eq(("a".."f").to_a)
    end

    it "converts objects in an array recursively" do
      obj = described_class.ruby_to_object(["a", 1, :foo, {bar: [42]}], coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(["a", 1, "foo", {"bar" => [42]}])
    end

    it "converts objects in a map recursively" do
      obj = described_class.ruby_to_object({:foo => [{bar: [42]}], 21 => 10.5}, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq({"foo" => [{"bar" => [42]}], "21" => 10.5})
    end

    context "with string values" do
      it "correctly handles ASCII strings" do
        ascii_string = "Hello, world!"
        obj = described_class.ruby_to_object(ascii_string)

        result = described_class.object_to_ruby(obj)

        expect(result).to eq(ascii_string)
        expect(result.encoding).to eq(Encoding::ASCII_8BIT)
        expect(result.ascii_only?).to be(true)
      end

      it "correctly handles UTF-8 strings" do
        utf8_string = "UTF-8 string with some non-ASCII: é à ö"
        obj = described_class.ruby_to_object(utf8_string)

        result = described_class.object_to_ruby(obj)

        expect(result).to eq(utf8_string)
        expect(result.encoding).to eq(Encoding::UTF_8)
        expect(result.valid_encoding?).to be(true)
      end

      it "correctly handles strings with complex Unicode characters" do
        complex_string = "😀🌍👋🚀💻 Unicode test"
        obj = described_class.ruby_to_object(complex_string)

        result = described_class.object_to_ruby(obj)

        expect(result).to eq(complex_string)
        expect(result.encoding).to eq(Encoding::UTF_8)
        expect(result.valid_encoding?).to be(true)
      end

      it "returns correctly encoded strings when nested in arrays" do
        mixed_array = ["ASCII string", "UTF-8 string: é à ö", "😀 emoji"]
        obj = described_class.ruby_to_object(mixed_array)

        result = described_class.object_to_ruby(obj)

        expect(result[0]).to eq("ASCII string")
        expect(result[0].encoding).to eq(Encoding::ASCII_8BIT)

        expect(result[1]).to eq("UTF-8 string: é à ö")
        expect(result[1].encoding).to eq(Encoding::UTF_8)
        expect(result[1].valid_encoding?).to be(true)

        expect(result[2]).to eq("😀 emoji")
        expect(result[2].encoding).to eq(Encoding::UTF_8)
        expect(result[2].valid_encoding?).to be(true)
      end

      it "returns correctly encoded strings when nested in hashes" do
        mixed_hash = {
          "ascii_key" => "ASCII string",
          "utf8_key" => "UTF-8 string: é à ö",
          "emoji_key" => "😀 emoji"
        }
        obj = described_class.ruby_to_object(mixed_hash)

        result = described_class.object_to_ruby(obj)

        expect(result["ascii_key"]).to eq("ASCII string")
        expect(result["ascii_key"].encoding).to eq(Encoding::ASCII_8BIT)

        expect(result["utf8_key"]).to eq("UTF-8 string: é à ö")
        expect(result["utf8_key"].encoding).to eq(Encoding::UTF_8)
        expect(result["utf8_key"].valid_encoding?).to be(true)

        expect(result["emoji_key"]).to eq("😀 emoji")
        expect(result["emoji_key"].encoding).to eq(Encoding::UTF_8)
        expect(result["emoji_key"].valid_encoding?).to be(true)
      end
    end
  end
end
