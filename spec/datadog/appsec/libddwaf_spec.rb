require 'spec_helper'
require 'datadog/appsec/waf'

RSpec.describe Datadog::AppSec::WAF::LibDDWAF do
  let(:libddwaf) { Datadog::AppSec::WAF::LibDDWAF }

  it 'provides the internally stored version' do
    version = libddwaf.ddwaf_get_version

    expect(version).to eq Datadog::AppSec::WAF::VERSION::BASE_STRING
  end

  context 'Object' do
    it 'creates ddwaf_object_invalid' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_invalid(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_invalid
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_bool with true' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_bool(object, true)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_bool
      expect(object[:valueUnion][:boolean]).to be true
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_bool with false' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_bool(object, false)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_bool
      expect(object[:valueUnion][:boolean]).to be false
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_string(object, 'foobar')
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq 'foobar'
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string with binary data' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_stringl(object, "foo\x00bar", 7)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 7
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq "foo\x00bar"
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string with zero-copy binary data' do
      s = "foo\x00bar"
      buf = FFI::MemoryPointer.from_string(s)
      buf.autorelease = false
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_stringl_nc(object, buf, s.size)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 7
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq "foo\x00bar"
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string from unsigned' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_string_from_unsigned(object, 42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 2
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq '42'
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_string from signed' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_string_from_signed(object, -42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_string
      expect(object[:nbEntries]).to eq 3
      expect(object[:valueUnion][:stringValue].null?).to be false
      expect(object[:valueUnion][:stringValue].read_bytes(object[:nbEntries])).to eq '-42'
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_unsigned' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_unsigned(object, 42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_unsigned
      expect(object[:valueUnion][:uintValue]).to be 42
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_signed' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_signed(object, -42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_signed
      expect(object[:valueUnion][:intValue]).to be(-42)
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_array' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_array(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_array
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each do |c|
        o = libddwaf::Object.new
        o = libddwaf.ddwaf_object_string(o, c)
        r = libddwaf.ddwaf_object_array_add(object, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * libddwaf::Object.size
        o = libddwaf::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(('a'.bytes.first + i).chr)
      end
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_map' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_map(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_map
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each.with_index do |c, i|
        o = libddwaf::Object.new
        o = libddwaf.ddwaf_object_string_from_unsigned(o, i)
        r = libddwaf.ddwaf_object_map_add(object, c, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * libddwaf::Object.size
        o = libddwaf::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:parameterNameLength]).to eq 1
        expect(o[:parameterName].read_bytes(o[:parameterNameLength])).to eq(('a'.bytes.first + i).chr)
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(i.to_s)
      end
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_map with binary keys' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_map(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_map
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each.with_index do |c, i|
        o = libddwaf::Object.new
        o = libddwaf.ddwaf_object_string_from_unsigned(o, i)
        r = libddwaf.ddwaf_object_map_addl(object, c << "\x00foo", 5, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * libddwaf::Object.size
        o = libddwaf::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:parameterNameLength]).to eq 5
        expect(o[:parameterName].read_bytes(o[:parameterNameLength])).to eq(('a'.bytes.first + i).chr << "\x00foo")
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(i.to_s)
      end
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_map with zero-copy binary keys' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_map(object)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_map
      expect(object[:nbEntries]).to eq 0
      expect(object[:valueUnion][:array].null?).to be(true)
      ('a'..'f').each.with_index do |c, i|
        s = c << "\x00foo"
        buf = FFI::MemoryPointer.from_string(s)
        buf.autorelease = false
        o = libddwaf::Object.new
        o = libddwaf.ddwaf_object_string_from_unsigned(o, i)
        r = libddwaf.ddwaf_object_map_addl_nc(object, buf, s.size, o)
      end
      expect(object[:nbEntries]).to eq 6
      expect(object[:valueUnion][:array].null?).to be(false)
      (0...object[:nbEntries]).each do |i|
        ptr = object[:valueUnion][:array] + i * libddwaf::Object.size
        o = libddwaf::Object.new(ptr)
        expect(o[:type]).to be :ddwaf_obj_string
        expect(o[:parameterNameLength]).to eq 5
        expect(o[:parameterName].read_bytes(o[:parameterNameLength])).to eq(('a'.bytes.first + i).chr << "\x00foo")
        expect(o[:nbEntries]).to eq 1
        expect(o[:valueUnion][:stringValue].read_bytes(o[:nbEntries])).to eq(i.to_s)
      end
      libddwaf.ddwaf_object_free(object)
    end

    context 'getters' do
      let(:ddwaf_object) { libddwaf::Object.new }

      after do
        libddwaf.ddwaf_object_free(ddwaf_object)
      end

      describe '.ddwaf_object_type' do
        [
          ['for array object', :ddwaf_object_array, nil, :ddwaf_obj_array],
          ['for map object', :ddwaf_object_map, nil, :ddwaf_obj_map],
          ['for signed object', :ddwaf_object_signed, -12, :ddwaf_obj_signed,],
          ['for unsigened object', :ddwaf_object_unsigned, 12, :ddwaf_obj_unsigned],
          ['for string object', :ddwaf_object_string, "Hello World", :ddwaf_obj_string],
          ['for boolean object', :ddwaf_object_bool, true, :ddwaf_obj_bool]
        ].each do |message, method, value, expected_object_type|
          context message do
            it "returns object type #{expected_object_type.inspect}" do
              if value
                libddwaf.send(method, ddwaf_object, value)
              else
                libddwaf.send(method, ddwaf_object)
              end
              object_type = libddwaf.ddwaf_object_type(ddwaf_object)
              expect(object_type).to eq(expected_object_type)
            end
          end
        end
      end

      describe '.ddwaf_object_size' do
        context 'for array object' do
          it 'returns size' do
            libddwaf.ddwaf_object_array(ddwaf_object)
            member_object = libddwaf::Object.new
            libddwaf.ddwaf_object_string(member_object, 'Hello World')
            libddwaf.ddwaf_object_array_add(ddwaf_object, member_object)

            size = libddwaf.ddwaf_object_size(ddwaf_object)
            expect(size).to eq(1)
          end
        end

        context 'for map object' do
          it 'returns size' do
            key = 'foo'
            libddwaf.ddwaf_object_map(ddwaf_object)
            member_object = libddwaf::Object.new
            libddwaf.ddwaf_object_string(member_object, 'bar')
            libddwaf.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)

            size = libddwaf.ddwaf_object_size(ddwaf_object)
            expect(size).to eq(1)
          end
        end

        context 'for non container objects' do
          it 'returns 0' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            size = libddwaf.ddwaf_object_size(ddwaf_object)
            expect(size).to eq(0)
          end
        end
      end

      describe '.ddwaf_object_get_string' do
        context 'for string object' do
          it 'returns string' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            string = libddwaf.ddwaf_object_get_string(ddwaf_object, libddwaf::SizeTPtr.new)
            expect(string.get_string(0)).to eq('Hello World')
          end
        end

        context 'non string object' do
          it 'returns null' do
            libddwaf.ddwaf_object_map(ddwaf_object)
            string = libddwaf.ddwaf_object_get_string(ddwaf_object, libddwaf::SizeTPtr.new)
            expect(string).to be_null
          end
        end
      end

      describe '.ddwaf_object_get_index' do
        context 'for map object' do
          before do
            key = 'foo'
            libddwaf.ddwaf_object_map(ddwaf_object)
            member_object = libddwaf::Object.new
            libddwaf.ddwaf_object_string(member_object, 'bar')
            libddwaf.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)
          end

          context 'with index in range' do
            it 'returns object' do
              object = libddwaf.ddwaf_object_get_index(ddwaf_object, 0)
              expect(object).to_not be_null
            end
          end

          context 'with index out of range' do
            it 'returns null' do
              object = libddwaf.ddwaf_object_get_index(ddwaf_object, 1)
              expect(object).to be_null
            end
          end
        end

        context 'for array object' do
          before do
            libddwaf.ddwaf_object_array(ddwaf_object)
            member_object = libddwaf::Object.new
            libddwaf.ddwaf_object_string(member_object, 'Hello World')
            libddwaf.ddwaf_object_array_add(ddwaf_object, member_object)
          end

          context 'with index in range' do
            it 'returns object' do
              object = libddwaf.ddwaf_object_get_index(ddwaf_object, 0)
              expect(object).to_not be_null
            end
          end

          context 'with index out of range' do
            it 'returns null' do
              object = libddwaf.ddwaf_object_get_index(ddwaf_object, 1)
              expect(object).to be_null
            end
          end
        end

        context 'non container object' do
          it 'returns null' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            object = libddwaf.ddwaf_object_get_index(ddwaf_object, 0)
            expect(object).to be_null
          end
        end
      end

      describe '.ddwaf_object_get_key' do
        context 'for map object' do
          it 'returns object key' do
            key = 'foo'
            libddwaf.ddwaf_object_map(ddwaf_object)
            member_object = libddwaf::Object.new
            libddwaf.ddwaf_object_string(member_object, 'bar')
            libddwaf.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)

            object = libddwaf.ddwaf_object_get_index(ddwaf_object, 0)
            key_object = libddwaf.ddwaf_object_get_key(object, libddwaf::SizeTPtr.new)

            expect(key_object.get_string(0)).to eq('foo')
          end

          it 'returns key length' do
            key = 'foo'
            libddwaf.ddwaf_object_map(ddwaf_object)
            member_object = libddwaf::Object.new
            libddwaf.ddwaf_object_string(member_object, 'bar')
            libddwaf.ddwaf_object_map_addl(ddwaf_object, key, key.bytesize, member_object)

            object = libddwaf.ddwaf_object_get_index(ddwaf_object, 0)
            length = libddwaf::SizeTPtr.new

            expect(length.pointer.get_int(0)).to eq(0)
            libddwaf.ddwaf_object_get_key(object, length)
            expect(length.pointer.get_int(0)).to eq(3)
          end

          context 'for non map object' do
            it 'returns nulls' do
              libddwaf.ddwaf_object_string(ddwaf_object, 'bar')
              key_object = libddwaf.ddwaf_object_get_key(ddwaf_object, libddwaf::SizeTPtr.new)

              expect(key_object).to be_null
            end
          end
        end

        context 'non map objects' do
          it 'returns nulll' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            object = libddwaf.ddwaf_object_get_key(ddwaf_object, libddwaf::SizeTPtr.new)
            expect(object).to be_null
          end
        end
      end

      describe '.ddwaf_object_get_signed' do
        context 'for signed object' do
          it 'returns value' do
            libddwaf.ddwaf_object_signed(ddwaf_object, -12)
            value = libddwaf.ddwaf_object_get_signed(ddwaf_object)
            expect(value).to eq(-12)
          end
        end

        context 'for non signed object' do
          it 'returns 0' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = libddwaf.ddwaf_object_get_signed(ddwaf_object)
            expect(value).to eq(0)
          end
        end
      end

      describe '.ddwaf_object_get_unsigned' do
        context 'for unsigned object' do
          it 'returns value' do
            libddwaf.ddwaf_object_unsigned(ddwaf_object, 12)
            value = libddwaf.ddwaf_object_get_unsigned(ddwaf_object)
            expect(value).to eq(12)
          end
        end

        context 'for non unsigned object' do
          it 'returns 0' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = libddwaf.ddwaf_object_get_unsigned(ddwaf_object)
            expect(value).to eq(0)
          end
        end
      end

      describe '.ddwaf_object_get_bool' do
        context 'for boolean object' do
          context 'true' do
            it 'returns value' do
              libddwaf.ddwaf_object_bool(ddwaf_object, true)
              value = libddwaf.ddwaf_object_get_bool(ddwaf_object)
              expect(value).to eq(true)
            end
          end

          context 'false' do
            it 'returns value' do
              libddwaf.ddwaf_object_bool(ddwaf_object, false)
              value = libddwaf.ddwaf_object_get_bool(ddwaf_object)
              expect(value).to eq(false)
            end
          end
        end

        context 'for non boolean object' do
          it 'returns false' do
            libddwaf.ddwaf_object_string(ddwaf_object, 'Hello World')
            value = libddwaf.ddwaf_object_get_bool(ddwaf_object)
            expect(value).to eq(false)
          end
        end
      end

      describe '.ddwaf_object_get_float' do
        context 'for float object' do
          it 'returns value' do
            libddwaf.ddwaf_object_float(ddwaf_object, 12.5)
            value = libddwaf.ddwaf_object_get_float(ddwaf_object)
            expect(value).to eq(12.5)
          end
        end

        context 'for non float object' do
          it 'returns value' do
            libddwaf.ddwaf_object_string(ddwaf_object, "Hello World")
            value = libddwaf.ddwaf_object_get_float(ddwaf_object)
            expect(value).to eq(0.0)
          end
        end
      end
    end
  end

  context 'ruby_to_object' do
    context 'with coercion to string' do
      it 'converts nil' do
        obj = Datadog::AppSec::WAF.ruby_to_object(nil)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ''
      end

      it 'converts an unhandled object' do
        obj = Datadog::AppSec::WAF.ruby_to_object(Object.new)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ''
      end

      it 'converts a boolean' do
        obj = Datadog::AppSec::WAF.ruby_to_object(true)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 4
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'true'
        obj = Datadog::AppSec::WAF.ruby_to_object(false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 5
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'false'
      end

      it 'converts a string' do
        obj = Datadog::AppSec::WAF.ruby_to_object('foo')
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a binary string' do
        obj = Datadog::AppSec::WAF.ruby_to_object("foo\x00bar")
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 7
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
      end

      it 'converts a symbol' do
        obj = Datadog::AppSec::WAF.ruby_to_object(:foo)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a positive integer' do
        obj = Datadog::AppSec::WAF.ruby_to_object(42)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 2
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '42'
      end

      it 'converts a negative integer' do
        obj = Datadog::AppSec::WAF.ruby_to_object(-42)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '-42'
      end

      it 'converts a float' do
        obj = Datadog::AppSec::WAF.ruby_to_object(Math::PI)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 17
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '3.141592653589793'
      end

      it 'converts an empty array' do
        obj = Datadog::AppSec::WAF.ruby_to_object([])
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty array' do
        obj = Datadog::AppSec::WAF.ruby_to_object((1..6).to_a)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 6
        array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
          ptr = obj[:valueUnion][:array] + i * libddwaf::Object.size
          o = libddwaf::Object.new(ptr)
          l = o[:nbEntries]
          v = o[:valueUnion][:stringValue].read_bytes(l)
          a << v
        end
        expect(array).to eq ('1'..'6').to_a
      end

      it 'converts an empty hash' do
        obj = Datadog::AppSec::WAF.ruby_to_object({})
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty hash' do
        obj = Datadog::AppSec::WAF.ruby_to_object({foo: 1, bar: 2, baz: 3})
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
        data = JSON.parse(File.read(File.join(__dir__, '../../fixtures/waf_rules.json')))
        Datadog::AppSec::WAF.ruby_to_object(data)
      end

      context 'with limits' do
        let(:max_container_size)  { 3 }
        let(:max_container_depth) { 3 }
        let(:max_string_length)   { 10 }

        context 'with container size limit' do
          it 'converts an array up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object((1..6).to_a, max_container_size: max_container_size)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 3
            array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * libddwaf::Object.size
              o = libddwaf::Object.new(ptr)
              l = o[:nbEntries]
              v = o[:valueUnion][:stringValue].read_bytes(l)
              a << v
            end
            expect(array).to eq ('1'..'3').to_a
          end

          it 'converts a hash up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object({foo: 1, bar: 2, baz: 3, qux: 4}, max_container_size: max_container_size)
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
            obj = Datadog::AppSec::WAF.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: max_container_depth)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 2

            ptr1 = obj[:valueUnion][:array] + 0 * libddwaf::Object.size
            ptr2 = obj[:valueUnion][:array] + 1 * libddwaf::Object.size
            o1 = libddwaf::Object.new(ptr1)
            o2 = libddwaf::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq '1'

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * libddwaf::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * libddwaf::Object.size
            o1 = libddwaf::Object.new(ptr1)
            o2 = libddwaf::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq '2'

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * libddwaf::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * libddwaf::Object.size
            o1 = libddwaf::Object.new(ptr1)
            o2 = libddwaf::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_string
            l = o1[:nbEntries]
            v = o1[:valueUnion][:stringValue].read_bytes(l)
            expect(v).to eq '3'

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 0
          end

          it 'converts nested hashes up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object({foo: { bar: { baz: { qux: 4}}}}, max_container_depth: max_container_depth)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'foo'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'bar'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'baz'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 0
          end
        end

        context 'with string length limit' do
          it 'converts a string up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object('foo' << 'o' * 80, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts a binary string up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object("foo\x00bar" << 'r' * 80, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00barrrr"
          end

          it 'converts a symbol up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object(('foo' << 'o' * 80).to_sym, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts hash keys up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object({('foo' << 'o' * 80) => 42}, max_string_length: max_string_length)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

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
        obj = Datadog::AppSec::WAF.ruby_to_object(nil, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_null
        expect(obj[:nbEntries]).to eq 0
      end

      it 'converts an unhandled object' do
        # TODO: coerced because of arrays and maps

        obj = Datadog::AppSec::WAF.ruby_to_object(Object.new, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq ''
      end

      it 'converts a boolean' do
        obj = Datadog::AppSec::WAF.ruby_to_object(true, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_bool
        expect(obj[:valueUnion][:boolean]).to eq true
        obj = Datadog::AppSec::WAF.ruby_to_object(false, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_bool
        expect(obj[:valueUnion][:boolean]).to eq false
      end

      it 'converts a string' do
        obj = Datadog::AppSec::WAF.ruby_to_object('foo', coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a binary string' do
        obj = Datadog::AppSec::WAF.ruby_to_object("foo\x00bar", coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 7
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
      end

      it 'converts a symbol' do
        obj = Datadog::AppSec::WAF.ruby_to_object(:foo, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_string
        expect(obj[:nbEntries]).to eq 3
        expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
      end

      it 'converts a positive integer' do
        obj = Datadog::AppSec::WAF.ruby_to_object(42, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_unsigned
        expect(obj[:valueUnion][:uintValue]).to eq 42
      end

      it 'converts a negative integer' do
        obj = Datadog::AppSec::WAF.ruby_to_object(-42, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_signed
        expect(obj[:valueUnion][:intValue]).to eq -42
      end

      it 'converts a float' do
        obj = Datadog::AppSec::WAF.ruby_to_object(Math::PI, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_float
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:f64]).to eq Math::PI
      end

      it 'converts an empty array' do
        obj = Datadog::AppSec::WAF.ruby_to_object([], coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty array' do
        obj = Datadog::AppSec::WAF.ruby_to_object((1..6).to_a, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_array
        expect(obj[:nbEntries]).to eq 6
        array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
          ptr = obj[:valueUnion][:array] + i * libddwaf::Object.size
          o = libddwaf::Object.new(ptr)
          v = o[:valueUnion][:uintValue]
          a << v
        end
        expect(array).to eq (1..6).to_a
      end

      it 'converts an empty hash' do
        obj = Datadog::AppSec::WAF.ruby_to_object({}, coerce: false)
        expect(obj[:type]).to eq :ddwaf_obj_map
        expect(obj[:nbEntries]).to eq 0
        expect(obj[:valueUnion][:array].null?).to be true
      end

      it 'converts a non-empty hash' do
        obj = Datadog::AppSec::WAF.ruby_to_object({foo: 1, bar: 2, baz: 3}, coerce: false)
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
        data = JSON.parse(File.read(File.join(__dir__, '../../fixtures/waf_rules.json')))
        Datadog::AppSec::WAF.ruby_to_object(data)
      end

      context 'with limits' do
        let(:max_container_size)  { 3 }
        let(:max_container_depth) { 3 }
        let(:max_string_length)   { 10 }

        context 'with container size limit' do
          it 'converts an array up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object((1..6).to_a, max_container_size: max_container_size, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 3
            array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
              ptr = obj[:valueUnion][:array] + i * libddwaf::Object.size
              o = libddwaf::Object.new(ptr)
              v = o[:valueUnion][:uintValue]
              a << v
            end
            expect(array).to eq (1..3).to_a
          end

          it 'converts a hash up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object({foo: 1, bar: 2, baz: 3, qux: 4}, max_container_size: max_container_size, coerce: false)
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
            obj = Datadog::AppSec::WAF.ruby_to_object([1, [2, [3, [4]]]], max_container_depth: max_container_depth, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_array
            expect(obj[:nbEntries]).to eq 2

            ptr1 = obj[:valueUnion][:array] + 0 * libddwaf::Object.size
            ptr2 = obj[:valueUnion][:array] + 1 * libddwaf::Object.size
            o1 = libddwaf::Object.new(ptr1)
            o2 = libddwaf::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_unsigned
            v = o1[:valueUnion][:uintValue]
            expect(v).to eq 1

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * libddwaf::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * libddwaf::Object.size
            o1 = libddwaf::Object.new(ptr1)
            o2 = libddwaf::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_unsigned
            v = o1[:valueUnion][:uintValue]
            expect(v).to eq 2

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 2

            ptr1 = o2[:valueUnion][:array] + 0 * libddwaf::Object.size
            ptr2 = o2[:valueUnion][:array] + 1 * libddwaf::Object.size
            o1 = libddwaf::Object.new(ptr1)
            o2 = libddwaf::Object.new(ptr2)

            expect(o1[:type]).to eq :ddwaf_obj_unsigned
            v = o1[:valueUnion][:uintValue]
            expect(v).to eq 3

            expect(o2[:type]).to eq :ddwaf_obj_array
            expect(o2[:nbEntries]).to eq 0
          end

          it 'converts nested hashes up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object({foo: { bar: { baz: { qux: 4}}}}, max_container_depth: max_container_depth, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'foo'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'bar'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 1

            ptr = o[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(k).to eq 'baz'

            expect(o[:type]).to eq :ddwaf_obj_map
            expect(o[:nbEntries]).to eq 0
          end
        end

        context 'with string length limit' do
          it 'converts a string up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object('foo' << 'o' * 80, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts a binary string up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object("foo\x00bar" << 'r' * 80, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00barrrr"
          end

          it 'converts a symbol up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object(('foo' << 'o' * 80).to_sym, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_string
            expect(obj[:nbEntries]).to eq 10
            expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'fooooooooo'
          end

          it 'converts hash keys up to the limit' do
            obj = Datadog::AppSec::WAF.ruby_to_object({('foo' << 'o' * 80) => 42}, max_string_length: max_string_length, coerce: false)
            expect(obj[:type]).to eq :ddwaf_obj_map
            expect(obj[:nbEntries]).to eq 1

            ptr = obj[:valueUnion][:array] + 0 * libddwaf::Object.size
            o = libddwaf::Object.new(ptr)

            l = o[:parameterNameLength]
            k = o[:parameterName].read_bytes(l)
            expect(l).to eq 10
            expect(k).to eq 'fooooooooo'
          end
        end
      end
    end
  end

  context 'object_to_ruby' do
    it 'converts a boolean' do
      obj = Datadog::AppSec::WAF.ruby_to_object(true, coerce: false)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq(true)
      obj = Datadog::AppSec::WAF.ruby_to_object(false, coerce: false)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq(false)
    end

    it 'converts a string' do
      obj = Datadog::AppSec::WAF.ruby_to_object('foo')
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq('foo')
    end

    it 'converts a nil' do
      obj = Datadog::AppSec::WAF.ruby_to_object(nil, coerce: false)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to be_nil
    end

    it 'converts an array' do
      obj = Datadog::AppSec::WAF.ruby_to_object(('a'..'f').to_a)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq(('a'..'f').to_a)
    end

    it 'converts objects in an array recursively' do
      obj = Datadog::AppSec::WAF.ruby_to_object(['a', 1, :foo, { bar: [42] }], coerce: false)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq(['a', 1, 'foo', { 'bar' => [42] }])
    end

    it 'converts objects in a map recursively' do
      obj = Datadog::AppSec::WAF.ruby_to_object({ foo: [{ bar: [42] }], 21 => 10.5 }, coerce: false)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq({ 'foo' => [{ 'bar' => [42] }], '21' => 10.5 })
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
            'action' => 'record',
          },
          {
            'id' => 2,
            'name' => 'Rule 2',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1'], 'regex' => 'rule2' } }
            ],
            'action' => 'record',
          },
          {
            'id' => 3,
            'name' => 'Rule 3',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule3' } }
            ],
            'action' => 'record',
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
            'action' => 'record',
          }
        ]
      }
    end

    let(:data3) do
      JSON.parse(File.read(File.join(__dir__, '../../fixtures/waf_rules.json')))
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
              { 'operator' => 'match_regex', 'parameters' => { 'inputs' => [{ 'address' => 'value1'}], 'regex' => 'rule2' } }
            ],
            'action' => 'record',
          },
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
              { 'operator' => 'match_regex', 'parameters' => { 'inputs' => [{ 'address' => 'value1'}], 'regex' => 'rule2' } }
            ],
            'on_match' => ['action1', 'action2', 'action3', 'action4']
          },
        ],
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
            'action' => 'record',
          },
          {
            'id' => 2,
            'badname' => 'Rule 2',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1'], 'regex' => 'rule2' } }
            ],
            'action' => 'record',
          },
          {
            'id' => 3,
            'name' => 'Rule 3',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule3' } }
            ],
            'action' => 'record',
          }
        ]
      }
    end

    let(:rule1) do
      Datadog::AppSec::WAF.ruby_to_object(data1)
    end

    let(:rule2) do
      Datadog::AppSec::WAF.ruby_to_object(data2)
    end

    let(:rule3) do
      Datadog::AppSec::WAF.ruby_to_object(data3)
    end

    let(:rule4) do
      Datadog::AppSec::WAF.ruby_to_object(data4)
    end

    let(:rule5) do
      Datadog::AppSec::WAF.ruby_to_object(data5)
    end

    let(:bad_rule) do
      Datadog::AppSec::WAF.ruby_to_object(bad_data)
    end

    let(:log_store) do
      []
    end

    let(:log_cb) do
      proc do |level, func, file, line, message, len|
        log_store << { level: level, func: func, file: file, line: line, message: message.read_bytes(len) }
      end
    end

    let(:config) do
      Datadog::AppSec::WAF::LibDDWAF::Config.new
    end

    let(:input) do
      Datadog::AppSec::WAF.ruby_to_object({ value1: [4242, 'randomString'], value2: ['rule1'] })
    end

    let(:empty_input) do
      Datadog::AppSec::WAF.ruby_to_object({})
    end

    let(:attack) do
      Datadog::AppSec::WAF.ruby_to_object({ 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } })
    end

    let(:block) do
      Datadog::AppSec::WAF.ruby_to_object({ value1: 'rule2' })
    end

    let(:timeout) do
      10_000_000 # in us
    end

    let(:diagnostics_obj) do
      Datadog::AppSec::WAF::LibDDWAF::Object.new
    end

    before(:each) do
      expect(log_store).to eq([])
      Datadog::AppSec::WAF::LibDDWAF.ddwaf_set_log_cb(log_cb, :ddwaf_log_trace)
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
      expect(log_store.select { |log| log[:message] == "Sending log messages to binding, min level trace" }).to_not be_empty
    end

    context 'with diagnostics' do
      it 'records successful old diagnostics' do
        handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule1, config, diagnostics_obj)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF.object_to_ruby(diagnostics_obj)

        expect(diagnostics["rules"]["loaded"].size).to eq(3)
        expect(diagnostics["rules"]["failed"].size).to eq(0)
        expect(diagnostics["rules"]["errors"]).to be_empty
      end

      it 'records successful new diagnostics' do
        handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule4, config, diagnostics_obj)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF.object_to_ruby(diagnostics_obj)

        expect(diagnostics["rules"]["loaded"].size).to eq(1)
        expect(diagnostics["rules"]["failed"].size).to eq(0)
        expect(diagnostics["rules"]["errors"]).to be_empty
        expect(diagnostics["ruleset_version"]).to eq('0.1.2')
      end

      it 'records failing diagnostics' do
        handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(bad_rule, config, diagnostics_obj)
        expect(handle.null?).to be false

        diagnostics = Datadog::AppSec::WAF.object_to_ruby(diagnostics_obj)

        expect(diagnostics["rules"]["loaded"].size).to eq(2)
        expect(diagnostics["rules"]["failed"].size).to eq(1)
        expect(diagnostics["rules"]["errors"]).to_not be_empty
        expect(diagnostics["ruleset_version"]).to be_nil
      end
    end

    it 'lists required addresses' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule1, config, diagnostics_obj)
      expect(handle.null?).to be false

      count = Datadog::AppSec::WAF::LibDDWAF::UInt32Ptr.new
      list = Datadog::AppSec::WAF::LibDDWAF.ddwaf_known_addresses(handle, count)
      expect(list.get_array_of_string(0, count[:value]).sort).to eq(['value1', 'value2'])
    end

    it 'triggers a monitoring rule' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule1, config, diagnostics_obj)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle)
      expect(context.null?).to be false

      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, input, empty_input, result, timeout)

      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(result[:actions]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'does not trigger' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule2, config, diagnostics_obj)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle)
      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, input, empty_input, result, timeout)
      expect(code).to eq :ddwaf_ok
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(result[:actions]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'does not trigger a monitoring rule due to timeout' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule1, config, diagnostics_obj)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle)
      expect(context.null?).to be false

      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, input, empty_input, result, 1)

      expect(code).to eq :ddwaf_ok
      expect(result[:timeout]).to eq true
      expect(result[:events]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(result[:actions]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'triggers a known attack' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule3, config, diagnostics_obj)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle)
      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, attack, empty_input, result, timeout)
      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(result[:actions]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_size(result[:actions])).to eq 0
    end

    it 'triggers a known actionable attack' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule5, config, diagnostics_obj)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle)
      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, block, empty_input, result, timeout)
      expect(code).to eq :ddwaf_match
      expect(result[:timeout]).to eq false
      expect(result[:events]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(result[:actions]).to be_a Datadog::AppSec::WAF::LibDDWAF::Object
      expect(Datadog::AppSec::WAF::LibDDWAF.ddwaf_object_size(result[:actions])).to eq 4
      # TODO: not sure why libddwaf reverses actions
      expect(Datadog::AppSec::WAF.object_to_ruby(result[:actions])).to eq ['action1', 'action2', 'action3', 'action4'].reverse
    end
  end
end
