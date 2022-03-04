require 'spec_helper'
require 'datadog/appsec/waf'
require 'json'

RSpec.describe Datadog::AppSec::WAF::LibDDWAF do
  let(:libddwaf) { Datadog::AppSec::WAF::LibDDWAF }

  it 'provides the internally stored version' do
    version = libddwaf::Version.new
    libddwaf.ddwaf_get_version(version)

    expect([version[:major], version[:minor], version[:patch]].join('.')).to eq Datadog::AppSec::WAF::VERSION::BASE_STRING
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
      obj = Datadog::AppSec::WAF.ruby_to_object(('a'..'f').to_a)
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
      Datadog::AppSec::WAF.ruby_to_object(data)
      Datadog::AppSec::WAF.ruby_to_object(data)
      Datadog::AppSec::WAF.ruby_to_object(data)
      Datadog::AppSec::WAF.ruby_to_object(data)
      Datadog::AppSec::WAF.ruby_to_object(data)
      Datadog::AppSec::WAF.ruby_to_object(data)
    end
  end

  context 'object_to_ruby' do
    it 'converts a string' do
      obj = Datadog::AppSec::WAF.ruby_to_object('foo')
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq('foo')
    end

    it 'converts an array' do
      obj = Datadog::AppSec::WAF.ruby_to_object(('a'..'f').to_a)
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq(('a'..'f').to_a)
    end

    it 'converts objects in an array recursively' do
      obj = Datadog::AppSec::WAF.ruby_to_object(['a', 1, :foo, { bar: [42] }])
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq(['a', '1', 'foo', { 'bar' => ['42'] }])
    end

    it 'converts objects in a map recursively' do
      obj = Datadog::AppSec::WAF.ruby_to_object({ foo: [{ bar: [42] }], 21 => 10.5 })
      expect(Datadog::AppSec::WAF.object_to_ruby(obj)).to eq({ 'foo' => [{ 'bar' => ['42'] }], '21' => '10.5' })
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

    let(:rule1) do
      Datadog::AppSec::WAF.ruby_to_object(data1)
    end

    let(:rule2) do
      Datadog::AppSec::WAF.ruby_to_object(data2)
    end

    let(:rule3) do
      Datadog::AppSec::WAF.ruby_to_object(data3)
    end

    let(:log_store) do
      []
    end

    let(:log_cb) do
      proc do |level, func, file, line, message, len|
        log_store << { level: level, func: func, file: file, message: message.read_bytes(len) }
      end
    end

    let(:config) do
      Datadog::AppSec::WAF::LibDDWAF::Config.new
    end

    let(:input) do
      Datadog::AppSec::WAF.ruby_to_object({ value1: [4242, 'randomString'], value2: ['rule1'] })
    end

    let(:attack) do
      Datadog::AppSec::WAF.ruby_to_object({ 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } })
    end

    let(:timeout) do
      10_000_000 # in us
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
      expect(log_store).to include({:file=>"PowerWAFInterface.cpp",
                                    :func=>"ddwaf_set_log_cb",
                                    :level=>:ddwaf_log_info,
                                    :message=>"Sending log messages to binding, min level trace"})
    end

    it 'triggers a monitoring rule' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule1, config)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle, FFI::Pointer::NULL)
      expect(context.null?).to be false

      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, input, result, timeout)

      expect(code).to eq :ddwaf_monitor
      expect(result[:action]).to eq :ddwaf_monitor
      expect(result[:data]).to_not be nil
    end

    it 'does not trigger' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule2, config)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle, FFI::Pointer::NULL)
      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, input, result, timeout)
      expect(code).to eq :ddwaf_good
      expect(result[:action]).to eq :ddwaf_good
      expect(result[:data]).to be nil
    end

    it 'triggers a known attack' do
      handle = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(rule3, config)
      expect(handle.null?).to be false

      context = Datadog::AppSec::WAF::LibDDWAF.ddwaf_context_init(handle, FFI::Pointer::NULL)
      result = Datadog::AppSec::WAF::LibDDWAF::Result.new
      code = Datadog::AppSec::WAF::LibDDWAF.ddwaf_run(context, attack, result, timeout)
      expect(code).to eq :ddwaf_monitor
      expect(result[:action]).to eq :ddwaf_monitor
      expect(result[:data]).to_not be nil
    end
  end
end

RSpec.describe Datadog::AppSec::WAF do
  let(:rule) do
    {
      'version' => '1.0',
      'events' => [
        {
          'id' => 1,
          'name' => 'Rule 1',
          'tags' => { 'type' => 'flow1' },
          'conditions' => [
            { 'operation' => 'match_regex', 'parameters' => { 'inputs' => ['value2'], 'regex' => 'rule1' } },
          ],
          'action' => 'record',
        }
      ]
    }
  end

  let(:max_time_store) do
    1024 * 1024
  end

  let(:timeout) do
    100_000 # in us
  end

  let(:handle) do
    Datadog::AppSec::WAF::Handle.new(rule, max_time_store: max_time_store)
  end

  let(:context) do
    Datadog::AppSec::WAF::Context.new(handle)
  end

  let(:passing_input) do
    { value1: [4242, 'randomString'], value2: ['nope'] }
  end

  let(:matching_input) do
    { value1: [4242, 'randomString'], value2: ['rule1'] }
  end

  let(:log_store) do
    []
  end

  let(:perf_store) do
    {
      perf_total_runtime: [],
      top_rule_runtime: [],
    }
  end

  let(:log_cb) do
    proc do |level, func, file, line, message, len|
      log_store << { level: level, func: func, file: file, message: message.read_bytes(len) }
    end
  end

  before(:each) do
    expect(perf_store).to eq({ perf_total_runtime: [], top_rule_runtime: [] })
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
      puts perf_store.inspect
      puts "== #{example.full_description}"
    end
  end

  it 'creates a valid handle' do
    expect(handle.handle_obj.null?).to be false
  end

  it 'creates a valid context' do
    expect(context.context_obj.null?).to be false
  end

  it 'raises an error when failing to create a handle' do
    invalid_rule = {}
    expect { Datadog::AppSec::WAF::Handle.new(invalid_rule, max_time_store: max_time_store) }.to raise_error Datadog::AppSec::WAF::LibDDWAF::Error
  end

  it 'raises an error when failing to create a context' do
    invalid_rule = {}
    invalid_rule_obj = Datadog::AppSec::WAF.ruby_to_object(invalid_rule)
    config_obj = Datadog::AppSec::WAF::LibDDWAF::Config.new
    invalid_handle_obj = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(invalid_rule_obj, config_obj)
    expect(invalid_handle_obj.null?).to be true
    invalid_handle = Datadog::AppSec::WAF::Handle.new(rule, max_time_store: max_time_store)
    invalid_handle.instance_eval do
      @handle_obj = invalid_handle_obj
    end
    expect(invalid_handle.handle_obj.null?).to be true
    expect { Datadog::AppSec::WAF::Context.new(invalid_handle) }.to raise_error Datadog::AppSec::WAF::LibDDWAF::Error
  end

  context 'run' do
    it 'passes non-matching input' do
      code, result = context.run(passing_input)
      perf_store[:perf_total_runtime] << result.perf_total_runtime
      expect(code).to eq :good
      expect(result.action).to eq :good
      expect(result.data).to be nil
      expect(result.perf_data).to be_a Hash
      expect(result.perf_total_runtime).to be > 0
    end

    it 'catches a match' do
      code, result = context.run(matching_input)
      perf_store[:perf_total_runtime] << result.perf_total_runtime
      expect(code).to eq :monitor
      expect(result.action).to eq :monitor
      expect(result.data).to be_a Array
      expect(result.perf_data).to be_a Hash
      expect(result.perf_total_runtime).to be > 0
    end
  end

  context 'run with a big ruleset' do
    let(:rule) do
      JSON.parse(File.read(File.join(__dir__, '../../fixtures/waf_rules.json')))
    end

    let(:passing_input) do
      { 'server.request.headers.no_cookies' => { 'user-agent' => 'Firefox' } }
    end

    let(:matching_input) do
      { 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } }
    end

    let(:matching_input_rule) do
      'ua0-600-10x'
    end

    it 'passes non-matching input' do
      code, result = context.run(passing_input, timeout)
      perf_store[:perf_total_runtime] << result.perf_total_runtime
      expect(code).to eq :good
      expect(result.action).to eq :good
      expect(result.data).to be nil
      expect(result.perf_data).to be_a Hash
      expect(result.perf_total_runtime).to be > 0
      expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_rule }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_rule}/ }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
    end

    it 'catches a match' do
      code, result = context.run(matching_input, timeout)
      perf_store[:perf_total_runtime] << result.perf_total_runtime
      expect(code).to eq :monitor
      expect(result.action).to eq :monitor
      expect(result.data).to be_a Array
      expect(result.perf_data).to be_a Hash
      expect(result.perf_total_runtime).to be > 0
      expect(result.data.find { |r| r['rule']['id'] == matching_input_rule }).to_not be_nil
      expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_rule }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_rule}/ }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
    end

    context 'running multiple times' do
      let(:passing_input_user_agent) do
        passing_input
      end

      let(:matching_input_user_agent) do
        matching_input
      end

      let(:matching_input_user_agent_rule) do
        matching_input_rule
      end

      let(:matching_input_path) do
        { 'server.request.uri.raw' => '/admin.php' }
      end

      let(:matching_input_path_rule) do
        'nfd-000-001'
      end

      let(:matching_input_status) do
        { 'server.response.status' => 404 }
      end

      let(:matching_input_sqli) do
        { 'server.request.query' => [['foo', '1 OR 1;']] }
      end

      let(:matching_input_sqli_rule) do
        'crs-942-100'
      end

      it 'runs once on passing input' do
        code, result = context.run(passing_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :good
        expect(result.action).to eq :good
        expect(result.data).to be nil
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_user_agent_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(passing_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :good
        expect(result.action).to eq :good
        expect(result.data).to be nil
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_user_agent_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs once on unchanged input' do
        code, result = context.run(matching_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :monitor
        expect(result.action).to eq :monitor
        expect(result.data).to be_a Array
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        code, result = context.run(matching_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :good
        expect(result.action).to eq :good
        expect(result.data).to be nil
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        # TODO: also stress test changing matching values, e.g using arachni/v\d+
        # CHECK: maybe it will bail out and return only the first one?
      end

      context 'stress testing' do
        let(:max_time_store) do
          1024 * 1024
        end

        it 'runs once on unchanged input' do
          skip 'slow'

          code, result = context.run(matching_input_user_agent, timeout)
          perf_store[:perf_total_runtime] << result.perf_total_runtime
          expect(code).to eq :monitor
          expect(result.action).to eq :monitor
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          expect(result.data).to be_a Array
          expect(result.perf_data).to be_a Hash
          expect(result.perf_total_runtime).to be > 0

          # stress test rerun on unchanged input
          100.times do
            code, result = context.run(matching_input_user_agent, timeout)
            perf_store[:perf_total_runtime] << result.perf_total_runtime
            expect(code).to eq :good
            expect(result.action).to eq :good
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
            expect(result.data).to be nil
            expect(result.perf_data).to be_a Hash
            expect(result.perf_total_runtime).to be > 0
          end

          # TODO: also stress test changing matching values, e.g using arachni/v\d+
          # CHECK: maybe it will bail out and return only the first one?
        end
      end

      context 'with timeout' do
        let(:timeout) do
          1 # in us
        end

        it 'runs but does not match' do
          code, result = context.run(matching_input_user_agent, timeout)
          perf_store[:perf_total_runtime] << result.perf_total_runtime

          expect(result.data).to be_nil
          expect(result.perf_data).to be_nil
          expect(result.perf_total_runtime).to be > 0
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to_not be_nil

          skip 'TODO: this should return :timeout'
          expect(code).to eq :timeout
          expect(result.action).to eq :timeout
        end
      end

      it 'runs twice on changed input value' do
        code, result = context.run(passing_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :good
        expect(result.action).to eq :good
        expect(result.data).to be nil
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_user_agent_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :monitor
        expect(result.action).to eq :monitor
        expect(result.data).to be_a Array
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.data.find { |r| r['rule']['id'] == matching_input_user_agent_rule }).to_not be_nil
        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_user_agent_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs twice on additional input key for an independent rule' do
        code, result = context.run(matching_input_user_agent, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :monitor
        expect(result.action).to eq :monitor
        expect(result.data).to be_a Array
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.data.find { |r| r['rule']['id'] == matching_input_user_agent_rule }).to_not be_nil
        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_user_agent_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_sqli)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :monitor
        expect(result.action).to eq :monitor
        expect(result.data).to be_a Array
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.data.find { |r| r['rule']['id'] == matching_input_user_agent_rule }).to be_nil
        expect(result.data.find { |r| r['rule']['id'] == matching_input_sqli_rule }).to_not be_nil
        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_sqli_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_sqli_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs twice on additional input key for a rule needing both keys to match' do
        code, result = context.run(matching_input_path, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :good
        expect(result.action).to eq :good
        expect(result.data).to be nil
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_path_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_path_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_status, timeout)
        perf_store[:perf_total_runtime] << result.perf_total_runtime
        expect(code).to eq :monitor
        expect(result.action).to eq :monitor
        expect(result.data).to be_a Array
        expect(result.perf_data).to be_a Hash
        expect(result.perf_total_runtime).to be > 0

        expect(result.data.find { |r| r['rule']['id'] == matching_input_path_rule }).to_not be_nil
        expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_path_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_path_rule}/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs twice on additional input key for a rule needing both keys to match with a scoped reference' do
        lambda do
          # for this test the first input needs to be in a short-lived scope
          input = { 'server.request.uri.raw' => '/admin.php' }

          code, result = context.run(input, timeout)
          perf_store[:perf_total_runtime] << result.perf_total_runtime
          expect(code).to eq :good
          expect(result.action).to eq :good
          expect(result.data).to be nil
          expect(result.perf_data).to be_a Hash
          expect(result.perf_total_runtime).to be > 0

          expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_path_rule }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_path_rule}/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end.call

        # garbage collect the first input
        # context should still be able to run and use previously passed input
        GC.start

        lambda do
          code, result = context.run(matching_input_status, timeout)
          perf_store[:perf_total_runtime] << result.perf_total_runtime
          expect(code).to eq :monitor
          expect(result.action).to eq :monitor
          expect(result.data).to be_a Array
          expect(result.perf_data).to be_a Hash
          expect(result.perf_total_runtime).to be > 0

          expect(result.data.find { |r| r['rule']['id'] == matching_input_path_rule }).to_not be_nil
          expect(result.perf_data['topRuleRuntime'].find { |r| r.first == matching_input_path_rule }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Running .* #{matching_input_path_rule}/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end.call
      end
    end
  end
end
