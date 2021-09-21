require 'datadog/waf'
require 'json'

RSpec.describe Datadog::WAF::LibDDWAF do
  let(:libddwaf) { Datadog::WAF::LibDDWAF }

  it 'provides the internally stored version' do
    version = libddwaf::Version.new
    libddwaf.ddwaf_get_version(version)

    expect([version[:major], version[:minor], version[:patch]].join('.')).to eq Datadog::WAF::VERSION::BASE_STRING
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
      r = libddwaf.ddwaf_object_unsigned(object, 42)
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
      r = libddwaf.ddwaf_object_signed(object, -42)
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
      r = libddwaf.ddwaf_object_unsigned_force(object, 42)
      expect(r.null?).to be false
      expect(r.pointer).to eq object.pointer
      expect(object[:type]).to eq :ddwaf_obj_unsigned
      expect(object[:valueUnion][:uintValue]).to be 42
      libddwaf.ddwaf_object_free(object)
    end

    it 'creates ddwaf_object_signed' do
      object = libddwaf::Object.new
      r = libddwaf.ddwaf_object_signed_force(object, -42)
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
        o = libddwaf.ddwaf_object_unsigned(o, i)
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
        o = libddwaf.ddwaf_object_unsigned(o, i)
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
        o = libddwaf.ddwaf_object_unsigned(o, i)
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
  end

  context 'ruby_to_object' do
    it 'converts nil' do
      obj = Datadog::WAF.ruby_to_object(nil)
      expect(obj[:type]).to eq :ddwaf_obj_invalid
    end

    it 'converts an unhandled object' do
      obj = Datadog::WAF.ruby_to_object(Object.new)
      expect(obj[:type]).to eq :ddwaf_obj_invalid
    end

    it 'converts a boolean' do
      obj = Datadog::WAF.ruby_to_object(true)
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 4
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'true'
      obj = Datadog::WAF.ruby_to_object(false)
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 5
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'false'
    end

    it 'converts a string' do
      obj = Datadog::WAF.ruby_to_object('foo')
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 3
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
    end

    it 'converts a binary string' do
      obj = Datadog::WAF.ruby_to_object("foo\x00bar")
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 7
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq "foo\x00bar"
    end

    it 'converts a symbol' do
      obj = Datadog::WAF.ruby_to_object(:foo)
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 3
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq 'foo'
    end

    it 'converts a positive integer' do
      obj = Datadog::WAF.ruby_to_object(42)
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 2
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '42'
    end

    it 'converts a negative integer' do
      obj = Datadog::WAF.ruby_to_object(-42)
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 3
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '-42'
    end

    it 'converts a float' do
      obj = Datadog::WAF.ruby_to_object(Math::PI)
      expect(obj[:type]).to eq :ddwaf_obj_string
      expect(obj[:nbEntries]).to eq 17
      expect(obj[:valueUnion][:stringValue].read_bytes(obj[:nbEntries])).to eq '3.141592653589793'
    end

    it 'converts an empty array' do
      obj = Datadog::WAF.ruby_to_object([])
      expect(obj[:type]).to eq :ddwaf_obj_array
      expect(obj[:nbEntries]).to eq 0
      expect(obj[:valueUnion][:array].null?).to be true
    end

    it 'converts a non-empty array' do
      obj = Datadog::WAF.ruby_to_object(('a'..'f').to_a)
      expect(obj[:type]).to eq :ddwaf_obj_array
      expect(obj[:nbEntries]).to eq 6
      array = (0...obj[:nbEntries]).each.with_object([]) do |i, a|
        ptr = obj[:valueUnion][:array] + i * libddwaf::Object.size
        o = libddwaf::Object.new(ptr)
        l = o[:nbEntries]
        v = o[:valueUnion][:stringValue].read_bytes(l)
        a << v
      end
      expect(array).to eq ('a'..'f').to_a
    end

    it 'converts an empty hash' do
      obj = Datadog::WAF.ruby_to_object({})
      expect(obj[:type]).to eq :ddwaf_obj_map
      expect(obj[:nbEntries]).to eq 0
      expect(obj[:valueUnion][:array].null?).to be true
    end

    it 'converts a non-empty hash' do
      obj = Datadog::WAF.ruby_to_object({foo: 1, bar: 2, baz: 3})
      expect(obj[:type]).to eq :ddwaf_obj_map
      expect(obj[:nbEntries]).to eq 3
      hash = (0...obj[:nbEntries]).each.with_object({}) do |i, h|
        ptr = obj[:valueUnion][:array] + i * Datadog::WAF::LibDDWAF::Object.size
        o = Datadog::WAF::LibDDWAF::Object.new(ptr)
        l = o[:parameterNameLength]
        k = o[:parameterName].read_bytes(l)
        l = o[:nbEntries]
        v = o[:valueUnion][:stringValue].read_bytes(l)
        h[k] = v
      end
      expect(hash).to eq({ 'foo' => '1', 'bar' => '2', 'baz' => '3' })
    end
  end

  context 'object_to_ruby' do
    it 'converts a string' do
      obj = Datadog::WAF.ruby_to_object('foo')
      expect(Datadog::WAF.object_to_ruby(obj)).to eq('foo')
    end

    it 'converts an array' do
      obj = Datadog::WAF.ruby_to_object(('a'..'f').to_a)
      expect(Datadog::WAF.object_to_ruby(obj)).to eq(('a'..'f').to_a)
    end

    it 'converts objects in an array recursively' do
      obj = Datadog::WAF.ruby_to_object(['a', 1, :foo, { bar: [42] }])
      expect(Datadog::WAF.object_to_ruby(obj)).to eq(['a', '1', 'foo', { 'bar' => ['42'] }])
    end

    it 'converts objects in a map recursively' do
      obj = Datadog::WAF.ruby_to_object({ foo: [{ bar: [42] }], 21 => 10.5 })
      expect(Datadog::WAF.object_to_ruby(obj)).to eq({ 'foo' => [{ 'bar' => ['42'] }], '21' => '10.5' })
    end
  end

  context 'run' do
    let(:data1) do
      {
        'version' => '1.0',
        'events' => [
          {
            'id' => 1,
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1', 'value2'], 'regex' => 'rule1' } }
            ],
            'action' => 'record',
          },
          {
            'id' => 2,
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value1'], 'regex' => 'rule2' } }
            ],
            'action' => 'record',
          },
          {
            'id' => 3,
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

    let(:rule1) do
      Datadog::WAF.ruby_to_object(data1)
    end

    let(:rule2) do
      Datadog::WAF.ruby_to_object(data2)
    end

    let(:log_store) do
      []
    end

    let(:log_cb) do
      proc do |level, func, file, line, message, len|
        log_store << message.read_bytes(len)
      end
    end

    let(:config) do
      Datadog::WAF::LibDDWAF::Config.new
    end

    let(:input) do
      Datadog::WAF.ruby_to_object({ value1: [4242, 'randomString'], value2: ['rule1'] })
    end

    let(:timeout) do
      10000000
    end

    before do
      Datadog::WAF::LibDDWAF.ddwaf_set_log_cb(log_cb, :ddwaf_log_trace)
    end

    it 'logs via the log callback' do
      expect(log_store).to include('Sending log messages to binding, min level trace')
    end

    it 'triggers a monitoring rule' do
      handle = Datadog::WAF::LibDDWAF.ddwaf_init(rule1, config)
      expect(handle.null?).to be false

      context = Datadog::WAF::LibDDWAF.ddwaf_context_init(handle, FFI::Pointer::NULL)
      expect(context.null?).to be false

      result = Datadog::WAF::LibDDWAF::Result.new
      code = Datadog::WAF::LibDDWAF.ddwaf_run(context, input, result, timeout)

      expect(code).to eq :ddwaf_monitor
      expect(result[:action]).to eq :ddwaf_monitor
      expect(result[:data]).to_not be nil
    end

    it 'does not trigger' do
      handle = Datadog::WAF::LibDDWAF.ddwaf_init(rule2, config)
      expect(handle.null?).to be false

      context = Datadog::WAF::LibDDWAF.ddwaf_context_init(handle, FFI::Pointer::NULL)
      result = Datadog::WAF::LibDDWAF::Result.new
      code = Datadog::WAF::LibDDWAF.ddwaf_run(context, input, result, timeout)
      expect(code).to eq :ddwaf_good
      expect(result[:action]).to eq :ddwaf_good
      expect(result[:data]).to be nil
    end
  end
end

RSpec.describe Datadog::WAF do
  let(:rule) do
    {
      'version' => '1.0',
      'events' => [
        {
          'id' => 1,
          'tags' => { 'type' => 'flow1' },
          'conditions' => [
            { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule1' } },
          ],
          'action' => 'record',
        }
      ]
    }
  end

  let(:handle) do
    Datadog::WAF::Handle.new(rule)
  end

  let(:context) do
    Datadog::WAF::Context.new(handle)
  end

  let(:passing_input) do
    { value1: [4242, 'randomString'], value2: ['nope'] }
  end

  let(:matching_input) do
    { value1: [4242, 'randomString'], value2: ['rule1'] }
  end

  it 'creates a valid handle' do
    expect(handle.handle_obj.null?).to be false
  end

  it 'creates a valid context' do
    expect(context.context_obj.null?).to be false
  end

  context 'run' do
    it 'passes non-matching input' do
      code, result = context.run(passing_input)
      expect(code).to eq :ddwaf_good
      expect(result.action).to eq :ddwaf_good
      expect(result.data).to be nil
      expect(result.perf_data).to be_a String
      expect(result.perf_total_runtime).to be > 0
    end

    it 'catches a match' do
      code, result = context.run(matching_input)
      expect(code).to eq :ddwaf_monitor
      expect(result.action).to eq :ddwaf_monitor
      expect(result.data).to be_a String
      expect(result.perf_data).to be_a String
      expect(result.perf_total_runtime).to be > 0
    end
  end
end
