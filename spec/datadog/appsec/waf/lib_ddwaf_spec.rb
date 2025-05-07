# frozen_string_literal: true

require 'spec_helper'
require 'datadog/appsec/waf/lib_ddwaf'
require 'datadog/appsec/waf/converter'
require 'datadog/appsec/waf/version'

RSpec.describe Datadog::AppSec::WAF::LibDDWAF do
  it 'provides the internally stored version' do
    expect(described_class.ddwaf_get_version).to eq Datadog::AppSec::WAF::VERSION::BASE_STRING
  end

  context 'Object' do
    it 'creates ddwaf_object_invalid' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_invalid(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_invalid
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_bool with true' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_bool(object, true)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_bool
      expect(object[:valueUnion][:boolean]).to be true
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_bool with false' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_bool(object, false)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_bool
      expect(object[:valueUnion][:boolean]).to be false
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_string(object, 'foobar')
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq 'foobar'
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string with binary data' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_stringl(object, "foo\x00bar", 7)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 7
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq "foo\x00bar"
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string with zero-copy binary data' do
      s = "foo\x00bar"
      buf = FFI::MemoryPointer.from_string(s)
      buf.autorelease = false
      object = described_class::Object.new
      r = described_class.ddwaf_object_stringl_nc(object, buf, s.size)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 7
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq "foo\x00bar"
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string from unsigned' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_string_from_unsigned(object, 42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 2
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq '42'
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string from signed' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_string_from_signed(object, -42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 3
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq '-42'
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_unsigned' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_unsigned(object, 42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_unsigned
      expect(object[:valueUnion][:uintValue]).to be 42
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_signed' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_signed(object, -42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_signed
      expect(object[:valueUnion][:intValue]).to be(-42)
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_array' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_array(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_array
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each do |c|
        o = described_class::Object.new
        o = described_class.ddwaf_object_string(o, c)
        r = described_class.ddwaf_object_array_add(object, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * described_class::Object.size
        o = described_class::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(('a'.bytes.first + i).chr)
      end
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_map' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_map(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_map
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each.with_index do |c, i|
        o = described_class::Object.new
        o = described_class.ddwaf_object_string_from_unsigned(o, i)
        r = described_class.ddwaf_object_map_add(object, c, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * described_class::Object.size
        o = described_class::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:parameterNameLength]).to eq 1
        expect(o[:parameterName].read_bytes(o[:parameterNameLength])).to eq(('a'.bytes.first + i).chr)
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(i.to_s)
      end
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_map with binary keys' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_map(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_map
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each.with_index do |c, i|
        o = described_class::Object.new
        o = described_class.ddwaf_object_string_from_unsigned(o, i)
        r = described_class.ddwaf_object_map_addl(object, c << "\x00foo", 5, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * described_class::Object.size
        o = described_class::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:parameterNameLength]).to eq 5
        expect(o[:parameterName].read_bytes(o[:parameterNameLength])).to eq(('a'.bytes.first + i).chr << "\x00foo")
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(i.to_s)
      end
      described_class.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_map with zero-copy binary keys' do
      object = described_class::Object.new
      r = described_class.ddwaf_object_map(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_map
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each.with_index do |c, i|
        s = c << "\x00foo"
        buf = FFI::MemoryPointer.from_string(s)
        buf.autorelease = false
        o = described_class::Object.new
        o = described_class.ddwaf_object_string_from_unsigned(o, i)
        r = described_class.ddwaf_object_map_addl_nc(object, buf, s.size, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * described_class::Object.size
        o = described_class::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:parameterNameLength]).to eq 5
        expect(o[:parameterName].read_bytes(o[:parameterNameLength])).to eq(('a'.bytes.first + i).chr << "\x00foo")
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(i.to_s)
      end
      described_class.ddwaf_object_free(object)
    end

    context 'getters' do
      let(:ddwaf_object) { described_class::Object.new }

      after do
        described_class.ddwaf_object_free(ddwaf_object)
      end

      describe '.ddwaf_object_type' do
        [
          ['for array object', :ddwaf_object_array, nil, :ddwaf_obj_array],
          ['for map object', :ddwaf_object_map, nil, :ddwaf_obj_map],
          ['for signed object', :ddwaf_object_signed, -12, :ddwaf_obj_signed],
          ['for unsigened object', :ddwaf_object_unsigned, 12, :ddwaf_obj_unsigned],
          ['for string object', :ddwaf_object_string, 'Hello World', :ddwaf_obj_string],
          ['for boolean object', :ddwaf_object_bool, true, :ddwaf_obj_bool]
        ].each do |message, method, value, expected_object_type|
          context message do
            it "returns object type #{expected_object_type.inspect}" do
              if value
                described_class.send(method, ddwaf_object, value)
              else
                described_class.send(method, ddwaf_object)
              end
              object_type = described_class.ddwaf_object_type(ddwaf_object)
              expect(object_type).to eq(expected_object_type)
            end
          end
        end
      end

      describe '.ddwaf_object_size' do
        context 'for array object' do
          it 'returns size' do
            described_class.ddwaf_object_array(ddwaf_object)
            member_object = described_class::Object.new
            described_class.ddwaf_object_string(member_object, 'Hello World')
            described_class.ddwaf_object_array_add(ddwaf_object, member_object)

            size = described_class.ddwaf_object_size(ddwaf_object)
            expect(size).to eq(1)
          end
        end

        context 'for map object' do
          it 'returns size' do
            key = 'foo'
            described_class.ddwaf_object_map(ddwaf_object)
            member_object = described_class::Object.new
            described_class.ddwaf_object_string(member_object, 'bar')
            described_class.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)

            size = described_class.ddwaf_object_size(ddwaf_object)
            expect(size).to eq(1)
          end
        end

        context 'for non container objects' do
          it 'returns 0' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            size = described_class.ddwaf_object_size(ddwaf_object)
            expect(size).to eq(0)
          end
        end
      end

      describe '.ddwaf_object_get_string' do
        context 'for string object' do
          it 'returns string' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            string = described_class.ddwaf_object_get_string(ddwaf_object, described_class::SizeTPtr.new)
            expect(string.get_string(0)).to eq('Hello World')
          end
        end

        context 'non string object' do
          it 'returns null' do
            described_class.ddwaf_object_map(ddwaf_object)
            string = described_class.ddwaf_object_get_string(ddwaf_object, described_class::SizeTPtr.new)
            expect(string).to be_null
          end
        end
      end

      describe '.ddwaf_object_get_index' do
        context 'for map object' do
          before do
            key = 'foo'
            described_class.ddwaf_object_map(ddwaf_object)
            member_object = described_class::Object.new
            described_class.ddwaf_object_string(member_object, 'bar')
            described_class.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)
          end

          context 'with index in range' do
            it 'returns object' do
              object = described_class.ddwaf_object_get_index(ddwaf_object, 0)
              expect(object).to_not be_null
            end
          end

          context 'with index out of range' do
            it 'returns null' do
              object = described_class.ddwaf_object_get_index(ddwaf_object, 1)
              expect(object).to be_null
            end
          end
        end

        context 'for array object' do
          before do
            described_class.ddwaf_object_array(ddwaf_object)
            member_object = described_class::Object.new
            described_class.ddwaf_object_string(member_object, 'Hello World')
            described_class.ddwaf_object_array_add(ddwaf_object, member_object)
          end

          context 'with index in range' do
            it 'returns object' do
              object = described_class.ddwaf_object_get_index(ddwaf_object, 0)
              expect(object).to_not be_null
            end
          end

          context 'with index out of range' do
            it 'returns null' do
              object = described_class.ddwaf_object_get_index(ddwaf_object, 1)
              expect(object).to be_null
            end
          end
        end

        context 'non container object' do
          it 'returns null' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            object = described_class.ddwaf_object_get_index(ddwaf_object, 0)
            expect(object).to be_null
          end
        end
      end

      describe '.ddwaf_object_get_key' do
        context 'for map object' do
          it 'returns object key' do
            key = 'foo'
            described_class.ddwaf_object_map(ddwaf_object)
            member_object = described_class::Object.new
            described_class.ddwaf_object_string(member_object, 'bar')
            described_class.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)

            object = described_class.ddwaf_object_get_index(ddwaf_object, 0)
            key_object = described_class.ddwaf_object_get_key(object, described_class::SizeTPtr.new)

            expect(key_object.get_string(0)).to eq('foo')
          end

          it 'returns key length' do
            key = 'foo'
            described_class.ddwaf_object_map(ddwaf_object)
            member_object = described_class::Object.new
            described_class.ddwaf_object_string(member_object, 'bar')
            described_class.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)

            object = described_class.ddwaf_object_get_index(ddwaf_object, 0)
            length = described_class::SizeTPtr.new

            expect(length.pointer.get_int(0)).to eq(0)
            described_class.ddwaf_object_get_key(object, length)
            expect(length.pointer.get_int(0)).to eq(3)
          end

          context 'for non map object' do
            it 'returns nulls' do
              described_class.ddwaf_object_string(ddwaf_object, 'bar')
              key_object = described_class.ddwaf_object_get_key(ddwaf_object, described_class::SizeTPtr.new)

              expect(key_object).to be_null
            end
          end
        end

        context 'non map objects' do
          it 'returns nulll' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            object = described_class.ddwaf_object_get_key(ddwaf_object, described_class::SizeTPtr.new)
            expect(object).to be_null
          end
        end
      end

      describe '.ddwaf_object_get_signed' do
        context 'for signed object' do
          it 'returns value' do
            described_class.ddwaf_object_signed(ddwaf_object, -12)
            value = described_class.ddwaf_object_get_signed(ddwaf_object)
            expect(value).to eq(-12)
          end
        end

        context 'for non signed object' do
          it 'returns 0' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = described_class.ddwaf_object_get_signed(ddwaf_object)
            expect(value).to eq(0)
          end
        end
      end

      describe '.ddwaf_object_get_unsigned' do
        context 'for unsigned object' do
          it 'returns value' do
            described_class.ddwaf_object_unsigned(ddwaf_object, 12)
            value = described_class.ddwaf_object_get_unsigned(ddwaf_object)
            expect(value).to eq(12)
          end
        end

        context 'for non unsigned object' do
          it 'returns 0' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = described_class.ddwaf_object_get_unsigned(ddwaf_object)
            expect(value).to eq(0)
          end
        end
      end

      describe '.ddwaf_object_get_bool' do
        context 'for boolean object' do
          context 'true' do
            it 'returns value' do
              described_class.ddwaf_object_bool(ddwaf_object, true)
              value = described_class.ddwaf_object_get_bool(ddwaf_object)
              expect(value).to eq(true)
            end
          end

          context 'false' do
            it 'returns value' do
              described_class.ddwaf_object_bool(ddwaf_object, false)
              value = described_class.ddwaf_object_get_bool(ddwaf_object)
              expect(value).to eq(false)
            end
          end
        end

        context 'for non boolean object' do
          it 'returns false' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = described_class.ddwaf_object_get_bool(ddwaf_object)
            expect(value).to eq(false)
          end
        end
      end

      describe '.ddwaf_object_get_float' do
        context 'for float object' do
          it 'returns value' do
            described_class.ddwaf_object_float(ddwaf_object, 12.5)
            value = described_class.ddwaf_object_get_float(ddwaf_object)
            expect(value).to eq(12.5)
          end
        end

        context 'for non float object' do
          it 'returns value' do
            described_class.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = described_class.ddwaf_object_get_float(ddwaf_object)
            expect(value).to eq(0.0)
          end
        end
      end
    end
  end

  context 'run' do
    let(:data1) do
      {
        'version' => '1.0',
        'events' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1', 'value2'], 'regex' => 'rule1' } }
            ],
            'action' => 'record'
          },
          {
            'id' => 2,
            'name' => 'Rule 2',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1'], 'regex' => 'rule2' } }
            ],
            'action' => 'record'
          },
          {
            'id' => 3,
            'name' => 'Rule 3',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule3' } }
            ],
            'action' => 'record'
          }
        ]
      }
    end

    let(:data2) do
      {
        'version' => '1.0',
        'events' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1'], 'regex' => 'rule2' } },
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule3' } }
            ],
            'action' => 'record'
          }
        ]
      }
    end

    let(:data3) do
      require 'json'

      JSON.parse(File.read(File.expand_path('../../../fixtures/waf_rules.json', __dir__)))
    end

    let(:data4) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '0.1.2'
        },
        'rules' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operator' => 'match_regex', 'parameters' => { 'inputs' => [{ 'address' => 'value1' }], 'regex' => 'rule2' } }
            ],
            'action' => 'record'
          }
        ]
      }
    end

    let(:data5) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '0.1.2'
        },
        'rules' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operator' => 'match_regex', 'parameters' => { 'inputs' => [{ 'address' => 'value1' }], 'regex' => 'rule2' } }
            ],
            'on_match' => ['action1', 'action2', 'action3', 'action4']
          }
        ],
        'actions' => [
          {
            'id' => 'action1',
            'type' => 'block',
            'parameters' => { 'status_code' => '401', 'grpc_status_code' => '41', 'type' => 'auto' }
          },
          {
            'id' => 'action2',
            'type' => 'extract_schema',
            'parameters' => { 'status_code' => '402', 'grpc_status_code' => '42', 'type' => 'auto' }
          },
          {
            'id' => 'action3',
            'type' => 'stacktrace',
            'parameters' => { 'status_code' => '403', 'grpc_status_code' => '43', 'type' => 'auto' }
          },
          {
            'id' => 'action4',
            'type' => 'unblock',
            'parameters' => { 'status_code' => '404', 'grpc_status_code' => '44', 'type' => 'auto' }
          }
        ]
      }
    end

    let(:bad_data) do
      {
        'version' => '1.0',
        'events' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1', 'value2'], 'regex' => 'rule1' } }
            ],
            'action' => 'record'
          },
          {
            'id' => 2,
            'badname' => 'Rule 2',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1'], 'regex' => 'rule2' } }
            ],
            'action' => 'record'
          },
          {
            'id' => 3,
            'name' => 'Rule 3',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule3' } }
            ],
            'action' => 'record'
          }
        ]
      }
    end

    let(:invalid_action_data) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '0.1.2'
        },
        'rules' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operator' => 'match_regex', 'parameters' => { 'inputs' => [{ 'address' => 'value1' }], 'regex' => 'rule2' } }
            ],
            'on_match' => ['invalid-action', 'valid-action-1', 'valid-action-2', 'unknown-action']
          }
        ],
        'actions' => [
          {
            'id' => 'valid-action-1',
            'type' => 'block',
            'parameters' => { 'status_code' => '401', 'grpc_status_code' => '41', 'type' => 'auto' }
          },
          {
            'id' => 'valid-action-2',
            'type' => 'unblock',
            'parameters' => { 'status_code' => '402', 'grpc_status_code' => '42', 'type' => 'auto' }
          },
          {
            'id' => 'invalid-action',
            'parameters' => { 'status' => '500', 'grpc_status' => '??', 'type' => 'invalid' }
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
        log_store << { level: level, func: func, file: file, line: line, message: message.read_bytes(len) }
      end
    end

    let(:config) { described_class::HandleBuilderConfig.new }

    let(:input) do
      Datadog::AppSec::WAF::Converter.ruby_to_object({ value1: [4242, 'randomString'], value2: ['rule1'] })
    end

    let(:empty_input) { Datadog::AppSec::WAF::Converter.ruby_to_object({}) }

    let(:attack) do
      Datadog::AppSec::WAF::Converter.ruby_to_object({ 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } })
    end

    let(:block) { Datadog::AppSec::WAF::Converter.ruby_to_object({ value1: 'rule2' }) }

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

    it 'logs via the log callback' do
      expect(log_store.select { |log| log[:message] == 'Sending log messages to binding, min level trace' }).to_not be_empty
    end

    context 'with diagnostics' do
      it 'records successful old diagnostics' do
        described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule1, diagnostics_obj)
        handle = described_class.ddwaf_builder_build_instance(builder)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF::Converter.object_to_ruby(diagnostics_obj)

        expect(diagnostics['rules']['loaded'].size).to eq(3)
        expect(diagnostics['rules']['failed'].size).to eq(0)
        expect(diagnostics['rules']['errors']).to be_empty
      end

      it 'records successful new diagnostics' do
        described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule4, diagnostics_obj)
        handle = described_class.ddwaf_builder_build_instance(builder)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF::Converter.object_to_ruby(diagnostics_obj)

        expect(diagnostics['rules']['loaded'].size).to eq(1)
        expect(diagnostics['rules']['failed'].size).to eq(0)
        expect(diagnostics['rules']['errors']).to be_empty
        expect(diagnostics['ruleset_version']).to eq('0.1.2')
      end

      it 'records failing diagnostics' do
        described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, bad_rule, diagnostics_obj)
        handle = described_class.ddwaf_builder_build_instance(builder)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF::Converter.object_to_ruby(diagnostics_obj)

        expect(diagnostics['rules']['loaded'].size).to eq(2)
        expect(diagnostics['rules']['failed'].size).to eq(1)
        expect(diagnostics['rules']['errors']).to_not be_empty
        expect(diagnostics['ruleset_version']).to be_nil
      end
    end

    it 'lists required addresses' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule1, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      count = described_class::UInt32Ptr.new
      list = described_class.ddwaf_known_addresses(handle, count)
      expect(list.get_array_of_string(0, count[:value]).sort).to eq(['value1', 'value2'])
    end

    it 'triggers a monitoring rule' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule1, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      context = described_class.ddwaf_context_init(handle)
      expect(context.null?).to be false

      result = described_class::Result.new
      code = described_class.ddwaf_run(context, input, empty_input, result, timeout_usec)

      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a described_class::Object
      expect(result[:actions]).to be_a described_class::Object
      expect(described_class.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'does not trigger' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule2, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      context = described_class.ddwaf_context_init(handle)
      result = described_class::Result.new
      code = described_class.ddwaf_run(context, input, empty_input, result, timeout_usec)
      expect(code).to eq :ddwaf_ok
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a described_class::Object
      expect(result[:actions]).to be_a described_class::Object
      expect(described_class.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'does not trigger a monitoring rule due to timeout' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule1, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      context = described_class.ddwaf_context_init(handle)
      expect(context.null?).to be false

      result = described_class::Result.new
      code = described_class.ddwaf_run(context, input, empty_input, result, 1)

      expect(code).to eq :ddwaf_ok
      expect(result[:timeout]).to eq true
      expect(result[:events]).to be_a described_class::Object
      expect(result[:actions]).to be_a described_class::Object
      expect(described_class.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'triggers a known attack' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule3, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      context = described_class.ddwaf_context_init(handle)
      result = described_class::Result.new
      code = described_class.ddwaf_run(context, attack, empty_input, result, timeout_usec)
      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a described_class::Object
      expect(result[:actions]).to be_a described_class::Object
      expect(described_class.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'triggers a known actionable attack' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, rule5, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      context = described_class.ddwaf_context_init(handle)
      result = described_class::Result.new
      code = described_class.ddwaf_run(context, block, empty_input, result, timeout_usec)
      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a described_class::Object
      expect(result[:actions]).to be_a described_class::Object
      expect(described_class.ddwaf_object_size(result[:actions])).to eq 4
      # TODO: not sure why libddwaf reverses actions
      actions = Datadog::AppSec::WAF::Converter.object_to_ruby(result[:actions]).keys
      expect(actions).to eq ['block', 'extract_schema', 'stacktrace', 'unblock'].reverse
    end

    it 'silently drops invalid or unknown actions on actionable attack' do
      described_class.ddwaf_builder_add_or_update_config(builder, 'some/path', 9, invalid_action_rule, diagnostics_obj)
      handle = described_class.ddwaf_builder_build_instance(builder)
      expect(handle.null?).to be false

      context = described_class.ddwaf_context_init(handle)
      result = described_class::Result.new
      code = described_class.ddwaf_run(context, block, empty_input, result, timeout_usec)
      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a described_class::Object
      expect(result[:actions]).to be_a described_class::Object
      expect(described_class.ddwaf_object_size(result[:actions])).to eq 2

      actions = Datadog::AppSec::WAF::Converter.object_to_ruby(result[:actions]).keys
      expect(actions).to eq ['unblock', 'block']
    end
  end
end
