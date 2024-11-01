# frozen_string_literal: true

require 'spec_helper'
require 'datadog/appsec/waf/lib_ddwaf'
require 'datadog/appsec/waf/converter'

RSpec.describe Datadog::AppSec::WAF::Converter do
  describe '.ruby_to_object' do
    context 'with coercion to string' do
      it 'converts nil' do
        obj = described_class.ruby_to_object(nil)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ''
      end

      it 'converts an unhandled object' do
        obj = described_class.ruby_to_object(Object.new)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ''
      end

      it 'converts a boolean' do
        obj = described_class.ruby_to_object(true)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 4
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'true'
        obj = described_class.ruby_to_object(false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 5
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'false'
      end

      it 'converts a string' do
        obj = described_class.ruby_to_object('foo')
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a binary string' do
        obj = described_class.ruby_to_object("foo\x00bar")
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 7
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
      end

      it 'converts a symbol' do
        obj = described_class.ruby_to_object(:foo)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a positive integer' do
        obj = described_class.ruby_to_object(42)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 2
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '42'
      end

      it 'converts a negative integer' do
        obj = described_class.ruby_to_object(-42)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '-42'
      end

      it 'converts a float' do
        obj = described_class.ruby_to_object(Math::PI)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 17
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '3.141592653589793'
      end

      it 'converts an empty array' do
        obj = described_class.ruby_to_object([])
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty array' do
        obj = described_class.ruby_to_object((1..6).to_a)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 6
        array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
          ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
          o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
          l = o[:nbEntries]
          v = o[:valueUnion][:stringValue].read_bytes(l)
          a << v
        end
        expect(array).to eq ('1'..'6').to_a
      end

      it 'converts an empty hash' do
        obj = described_class.ruby_to_object({})
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty hash' do
        obj = described_class.ruby_to_object({ foo: 1, bar: 2, baz: 3 })
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 3
        hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
          ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
          o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
          l = o[:parameterNameLength]
          k = o[:parameterName].read_bytes(l)
          l = o[:nbEntries]
          v = o[:valueUnion][:stringValue].read_bytes(l)
          h[k] = v
        end
        expect(hash).to eq({ 'foo' => '1', 'bar' => '2', 'baz' => '3' })
      end

      it 'converts a big value' do
        require 'json'

        data = JSON.parse(File.read(File.expand_path('../../../fixtures/waf_rules.json', __dir__)))
        described_class.ruby_to_object(data)
      end

      context 'with limits' do
        let(:max_container_size)  { 3 }
        let(:max_container_depth) { 3 }
        let(:max_string_length)   { 10 }

        context 'with container size limit' do
          it 'converts an array up to the limit' do
            obj = described_class.ruby_to_object((1..6).to_a, max_container_size: max_container_size)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 3
            array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              l = o[:nbEntries]
              v = o[:valueUnion][:stringValue].read_bytes(l)
              a << v
            end
            expect(array).to eq ('1'..'3').to_a
          end

          it 'converts a hash up to the limit' do
            obj = described_class.ruby_to_object({ foo: 1, bar: 2, baz: 3, qux: 4 }, max_container_size: max_container_size)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 3
            hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              l = o[:parameterNameLength]
              k = o[:parameterName].read_bytes(l)
              l = o[:nbEntries]
              v = o[:valueUnion][:stringValue].read_bytes(l)
              h[k] = v
            end
            expect(hash).to eq({ 'foo' => '1', 'bar' => '2', 'baz' => '3' })
          end
        end

        context 'with container depth limit' do
          it 'converts nested arrays up to the limit' do
            obj = described_class.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: max_container_depth)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 2

            ptr1 = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = obj[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq '1'

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq '2'

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o1 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr1)
            o2 = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq '3'

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 0
          end

          it 'converts nested hashes up to the limit' do
            obj = described_class.ruby_to_object({ foo: { bar: { baz: { qux: 4 } } } }, max_container_depth: max_container_depth)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'foo'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'bar'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'baz'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 0
          end
        end

        context 'with string length limit' do
          it 'converts a string up to the limit' do
            obj = described_class.ruby_to_object(+'foo' << 'o' * 80, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts a binary string up to the limit' do
            obj = described_class.ruby_to_object(+"foo\x00bar" << 'r' * 80, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00barrrr"
          end

          it 'converts a symbol up to the limit' do
            obj = described_class.ruby_to_object((+'foo' << 'o' * 80).to_sym, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts hash keys up to the limit' do
            obj = described_class.ruby_to_object({ (+'foo' << 'o' * 80) => 42 }, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(l).to eq 10
            expect(k).to eq 'fooooooooo'
          end
        end
      end
    end

    context 'without coercion to string' do
      it 'converts nil' do
        obj = described_class.ruby_to_object(nil, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_null
        expect(obj[:nbEntries]).to eq 0
      end

      it 'converts an unhandled object' do
        # TODO: coerced because of arrays and maps

        obj = described_class.ruby_to_object(Object.new, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ''
      end

      it 'converts a boolean' do
        obj = described_class.ruby_to_object(true, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_bool
        expect(obj[:valueUnion][:boolean]).to eq true
        obj = described_class.ruby_to_object(false, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_bool
        expect(obj[:valueUnion][:boolean]).to eq false
      end

      it 'converts a string' do
        obj = described_class.ruby_to_object('foo', coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a binary string' do
        obj = described_class.ruby_to_object("foo\x00bar", coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 7
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
      end

      it 'converts a symbol' do
        obj = described_class.ruby_to_object(:foo, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a positive integer' do
        obj = described_class.ruby_to_object(42, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_unsigned
        expect(obj[:valueUnion][:uintValue]).to eq 42
      end

      it 'converts a negative integer' do
        obj = described_class.ruby_to_object(-42, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_signed
        expect(obj[:valueUnion][:intValue]).to eq(-42)
      end

      it 'converts a float' do
        obj = described_class.ruby_to_object(Math::PI, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_float
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:f64]).to eq Math::PI
      end

      it 'converts an empty array' do
        obj = described_class.ruby_to_object([], coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty array' do
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

      it 'converts an empty hash' do
        obj = described_class.ruby_to_object({}, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty hash' do
        obj = described_class.ruby_to_object({ foo: 1, bar: 2, baz: 3 }, coerce: false)
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
        expect(hash).to eq({ 'foo' => 1, 'bar' => 2, 'baz' => 3 })
      end

      it 'converts a big value' do
        data = JSON.parse(File.read(File.expand_path('../../../fixtures/waf_rules.json', __dir__)))
        described_class.ruby_to_object(data)
      end

      context 'with limits' do
        let(:max_container_size)  { 3 }
        let(:max_container_depth) { 3 }
        let(:max_string_length)   { 10 }

        context 'with container size limit' do
          it 'converts an array up to the limit' do
            obj = described_class.ruby_to_object((1..6).to_a, max_container_size: max_container_size, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 3
            array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * Datadog::AppSec::WAF::LibDDWAF::Object.size
              o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)
              v = o[:valueUnion][:uintValue]
              a << v
            end
            expect(array).to eq (1..3).to_a
          end

          it 'converts a hash up to the limit' do
            obj = described_class.ruby_to_object({ foo: 1, bar: 2, baz: 3, qux: 4 }, max_container_size: max_container_size, coerce: false)
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
            expect(hash).to eq({ 'foo' => 1, 'bar' => 2, 'baz' => 3 })
          end
        end

        context 'with container depth limit' do
          it 'converts nested arrays up to the limit' do
            obj = described_class.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: max_container_depth, coerce: false)
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

          it 'converts nested hashes up to the limit' do
            obj = described_class.ruby_to_object({ foo: { bar: { baz: { qux: 4 } } } }, max_container_depth: max_container_depth,
                                                                                             coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'foo'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'bar'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'baz'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 0
          end
        end

        context 'with string length limit' do
          it 'converts a string up to the limit' do
            obj = described_class.ruby_to_object(+'foo' << 'o' * 80, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts a binary string up to the limit' do
            obj = described_class.ruby_to_object(+"foo\x00bar" << 'r' * 80, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00barrrr"
          end

          it 'converts a symbol up to the limit' do
            obj = described_class.ruby_to_object((+'foo' << 'o' * 80).to_sym, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts hash keys up to the limit' do
            obj = described_class.ruby_to_object({ (+'foo' << 'o' * 80) => 42 }, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * Datadog::AppSec::WAF::LibDDWAF::Object.size
            o = Datadog::AppSec::WAF::LibDDWAF::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(l).to eq 10
            expect(k).to eq 'fooooooooo'
          end
        end
      end
    end
  end

  describe '.object_to_ruby' do
    it 'converts a boolean' do
      obj = described_class.ruby_to_object(true, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(true)
      obj = described_class.ruby_to_object(false, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(false)
    end

    it 'converts a string' do
      obj = described_class.ruby_to_object('foo')
      expect(described_class.object_to_ruby(obj)).to eq('foo')
    end

    it 'converts a nil' do
      obj = described_class.ruby_to_object(nil, coerce: false)
      expect(described_class.object_to_ruby(obj)).to be_nil
    end

    it 'converts an array' do
      obj = described_class.ruby_to_object(('a'..'f').to_a)
      expect(described_class.object_to_ruby(obj)).to eq(('a'..'f').to_a)
    end

    it 'converts objects in an array recursively' do
      obj = described_class.ruby_to_object(['a', 1, :foo, { bar: [42] }], coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq(['a', 1, 'foo', { 'bar' => [42] }])
    end

    it 'converts objects in a map recursively' do
      obj = described_class.ruby_to_object({ foo: [{ bar: [42] }], 21 => 10.5 }, coerce: false)
      expect(described_class.object_to_ruby(obj)).to eq({ 'foo' => [{ 'bar' => [42] }], '21' => 10.5 })
    end
  end
end
