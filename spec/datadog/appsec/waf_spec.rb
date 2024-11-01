# frozen_string_literal: true

require 'spec_helper'
require 'datadog/appsec/waf'

RSpec.describe Datadog::AppSec::WAF do
  let(:rule) do
    {
      'version' => '2.2',
      'metadata' => {
        'rules_version' => '1.2.3'
      },
      'rules' => [
        {
          'id' => 1,
          'name' => 'Rule 1',
          'tags' => { 'type' => 'flow1' },
          'conditions' => [
            {
              'operator' => 'match_regex',
              'parameters' => { 'inputs' => [{ 'address' => 'value2' }], 'regex' => 'rule1' }
            },
          ],
          'action' => 'record',
        }
      ]
    }
  end

  let(:timeout_usec) { 10_000_000 }

  let(:diagnostics_obj) { described_class::LibDDWAF::Object.new }
  let(:handle) { described_class::Handle.new(rule) }
  let(:context) { described_class::Context.new(handle) }

  let(:passing_input) do
    { value1: [4242, 'randomString'], value2: ['nope'] }
  end

  let(:matching_input) do
    { value1: [4242, 'randomString'], value2: ['rule1'] }
  end

  let(:log_store) { [] }

  let(:perf_store) do
    {
      total_runtime: [],
    }
  end

  let(:log_cb) do
    proc do |level, func, file, line, message, len|
      log_store << { level: level, func: func, file: file, line: line, message: message.read_bytes(len) }
    end
  end

  before(:each) do
    expect(perf_store).to eq({ total_runtime: [] })
    expect(log_store).to eq([])

    described_class::LibDDWAF.ddwaf_set_log_cb(log_cb, :ddwaf_log_trace)

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

  it 'lists required addresses' do
    expect(handle.required_addresses).to eq ['value2']
  end

  it 'raises an error when failing to create a handle' do
    invalid_rule = {}
    expect { described_class::Handle.new(invalid_rule) }.to raise_error described_class::LibDDWAF::Error
  end

  it 'raises an error when failing to create a context' do
    invalid_rule = {}
    invalid_rule_obj = described_class::Converter.ruby_to_object(invalid_rule)
    config_obj = described_class::LibDDWAF::Config.new
    invalid_handle_obj = described_class::LibDDWAF.ddwaf_init(invalid_rule_obj, config_obj, diagnostics_obj)
    expect(invalid_handle_obj.null?).to be true
    invalid_handle = described_class::Handle.new(rule)
    invalid_handle.instance_eval do
      @handle_obj = invalid_handle_obj
    end
    expect(invalid_handle.handle_obj.null?).to be true
    expect { described_class::Context.new(invalid_handle) }.to raise_error described_class::LibDDWAF::Error
  end

  it 'records good diagnostics' do
    expect(handle.diagnostics).to be_a Hash
    expect(handle.diagnostics["rules"]["loaded"].size).to eq(1)
    expect(handle.diagnostics["rules"]["failed"].size).to eq(0)
    expect(handle.diagnostics["rules"]["errors"]).to be_empty
    expect(handle.diagnostics["ruleset_version"]).to eq('1.2.3')
  end

  describe '#run' do
    it 'passes non-matching persistent data' do
      code, result = context.run(passing_input, {}, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :ok
      expect(result.status).to eq :ok
      expect(result.events).to eq []
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq []
    end

    it 'passes non-matching ephemeral data' do
      code, result = context.run({}, passing_input, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :ok
      expect(result.status).to eq :ok
      expect(result.events).to eq []
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq []
    end

    it 'catches a match on persistent data' do
      code, result = context.run(matching_input, {}, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :match
      expect(result.status).to eq :match
      expect(result.events).to be_a Array
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq []
    end

    it 'catches a match on ephemeral data' do
      code, result = context.run({}, matching_input, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :match
      expect(result.status).to eq :match
      expect(result.events).to be_a Array
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq []
    end

    context 'encoding' do
      context 'with a non UTF-8 string' do
        let(:matching_input) do
          { value1: [4242, 'randomString'], value2: ['rule1'.dup.force_encoding('ASCII-8BIT')] }
        end

        it 'catches a match' do
          code, result = context.run(matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []
        end
      end

      context 'with badly encoded string' do
        let(:matching_input) do
          { value1: [4242, 'randomString'], value2: ["rule1\xE2".dup.force_encoding('ASCII-8BIT')] }
        end

        it 'returns valid UTF-8' do
          _code, result = context.run(matching_input, {}, timeout_usec)
          expect(result.events.first['rule_matches'].first['parameters'].first['value']).to be_valid_encoding
          expect(result.events.first['rule_matches'].first['parameters'].first['highlight'].first).to be_valid_encoding
        end

        it 'catches a match' do
          code, result = context.run(matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []
        end
      end
    end
  end

  context 'with a partially bad ruleset' do
    let(:rule) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '1.2.3'
        },
        'rules' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              {
                'operator' => 'match_regex',
                'parameters' => { 'inputs' => [{ 'address' => 'value1' }], 'regex' => 'badregex(' }
              },
            ],
            'action' => 'record',
          },
          {
            'id' => 2,
            'name' => 'Rule 2',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              {
                'operator' => 'match_regex',
                'parameters' => { 'inputs' => [{ 'address' => 'value2' }], 'regex' => 'rule2' }
              },
            ],
            'action' => 'record',
          }
        ]
      }
    end

    it 'records bad diagnostics' do
      expect(handle.diagnostics).to be_a Hash
      expect(handle.diagnostics["rules"]["loaded"].size).to eq(1)
      expect(handle.diagnostics["rules"]["failed"].size).to eq(1)
      expect(handle.diagnostics["rules"]["errors"]).to_not be_empty
      expect(handle.diagnostics["ruleset_version"]).to eq('1.2.3')
    end
  end

  context 'with a fully bad ruleset' do
    let(:rule) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '1.2.3'
        },
        'rules' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              {
                'operator' => 'match_regex',
                'parameters' => { 'inputs' => [{ 'address' => 'value1' }], 'regex' => 'badregex(' }
              },
            ],
            'action' => 'record',
          }
        ]
      }
    end

    let(:handle_exception) do
      begin
        handle
      rescue StandardError => e
        return e
      end
    end

    it 'records bad diagnostics in the exception' do
      expect(handle_exception).to be_a(described_class::LibDDWAF::Error)
      expect(handle_exception.diagnostics).to be_a Hash
      expect(handle_exception.diagnostics["rules"]["loaded"].size).to eq(0)
      expect(handle_exception.diagnostics["rules"]["failed"].size).to eq(1)
      expect(handle_exception.diagnostics["rules"]["errors"]).to_not be_empty
      expect(handle_exception.diagnostics["ruleset_version"]).to eq('1.2.3')
    end
  end

  context 'with a custom rules' do
    let(:rule) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '1.2.3'
        },
        'rules' => [
          {
            'id' => 1,
            'name' => 'Rule 1',
            'tags' => { 'type' => 'flow1' },
            'conditions' => [
              {
                'operator' => 'match_regex',
                'parameters' => { 'inputs' => [{ 'address' => 'value2' }], 'regex' => 'rule1' }
              },
            ],
            'action' => 'record',
          }
        ],
        'custom_rules' => [
          {
            'id' => 3,
            'name' => 'Custom Rule 1',
            'tags' => { 'type' => 'custom_flow' },
            'conditions' => [
              {
                'operator' => 'match_regex',
                'parameters' => { 'inputs' => [{ 'address' => 'custom_address' }], 'regex' => 'custom_value' }
              },
            ],
            'action' => 'record',
          }
        ]
      }
    end

    let(:matching_input) do
      { custom_address: ['custom_value'] }
    end

    it 'matches custom rule' do
      code, = context.run(matching_input, {}, timeout_usec)
      expect(code).to eq :match
    end
  end

  describe '#merge' do
    context 'valid merge data' do
      context 'rules override' do
        it 'disable an exiting rule' do
          data = {
            "rules_override" => [
              {
                "enabled" => false,
                "id" => "1"
              }
            ]
          }

          code, = context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match

          new_handle = handle.merge(data)
          expect(new_handle).to be_a(described_class::Handle)

          new_context = described_class::Context.new(new_handle)
          code, = new_context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :ok

          new_context.finalize
          new_handle.finalize
          handle.finalize
          context.finalize
        end

        it 'updates rule actions' do
          data = {
            "rules_override" => [
              {
                "id" => "1",
                "on_match" => ["block"]
              },
            ]
          }

          code, result = context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match
          expect(result.actions).to be_empty

          new_handle = handle.merge(data)
          expect(new_handle).to be_a(described_class::Handle)

          new_context = described_class::Context.new(new_handle)
          code, result = new_context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match
          expect(result.actions).to eq(['block'])

          new_context.finalize
          new_handle.finalize
          handle.finalize
          context.finalize
        end
      end

      context 'rules data' do
        let(:rule) do
          {
            'version' => '2.2',
            'metadata' => {
              'rules_version' => '1.4.1'
            },
            'rules' => [
              {
                'id' => 'blk-001-001',
                'name' => 'Block IP Addresses',
                'tags' => { 'type' => 'block_ip', 'category' => 'security_response' },
                'conditions' => [
                  {
                    'operator' => 'ip_match',
                    'parameters' => { 'inputs' => [{ 'address' => 'http.client_ip' }], 'data' => 'blocked_ips' }
                  }
                ],
                'transformers' => [],
                'on_match' => ['block']
              }
            ]
          }
        end

        let(:matching_ip) do
          '1.2.3.4'
        end

        let(:matching_input) do
          { 'http.client_ip' => matching_ip }
        end

        it 'adds rules data' do
          data = {
            "rules_data" => [
              {
                'id' => 'blocked_ips',
                'type' => 'data_with_expiration',
                'data' => [{ 'value' => matching_ip, 'expiration' => (Time.now + 1000).to_i }]
              }
            ]
          }

          code, = context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :ok

          new_handle = handle.merge(data)
          expect(new_handle).to be_a(described_class::Handle)

          new_context = described_class::Context.new(new_handle)
          code, = new_context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match

          new_context.finalize
          new_handle.finalize
          handle.finalize
          context.finalize
        end
      end
    end

    context 'with invalid merge data' do
      it 'does not return a Handle instance' do
        data = {'invalid_data' => 'a'}

        new_handle = handle.merge(data)
        expect(new_handle).to be_nil
      end
    end

    context 'with a handle with obfuscator configuration' do
      let(:new_ruleset) do
        {
          'rules' => [
            {
              'id' => 'ua0-600-10x',
              'name' => 'Nessus',
              'tags' => {
                'type' => 'security_scanner',
                'category' => 'attack_attempt'
              },
              'conditions' => [
                {
                  'parameters' => {
                    'inputs' => [
                      {
                        'address' => 'server.request.headers.no_cookies',
                        'key_path' => [
                          'user-agent'
                        ]
                      }
                    ],
                    'regex' => '(?i)^Nessus(/|([ :]+SOAP))'
                  },
                  'operator' => 'match_regex'
                }
              ],
              'transformers' => []
            },
          ]
        }
      end

      let(:matching_input) do
        { 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } }
      end

      it 'retains old handle obfuscator configured' do
        old_handle = described_class::Handle.new(rule, obfuscator: { key_regex: 'user-agent' })
        old_context = described_class::Context.new(old_handle)

        code, = old_context.run(matching_input, {}, timeout_usec)
        expect(code).to eq :ok

        new_handle = old_handle.merge(new_ruleset)
        expect(new_handle).to be_a(described_class::Handle)

        # Finalize old handle and context
        # It should free all related information from old_handle and old_context
        # Except the old handle configuration, which is propagateed through #merge
        old_handle.finalize
        old_context.finalize

        new_context = described_class::Context.new(new_handle)

        new_code, new_result = new_context.run(matching_input, {}, timeout_usec)
        expect(new_code).to eq :match

        expect(new_result.events.first['rule_matches'].first['parameters'].first['value']).to eq '<Redacted>'
        expect(new_result.events.first['rule_matches'].first['parameters'].first['highlight']).to include '<Redacted>'
      end
    end
  end

  context 'run with a big ruleset' do
    let(:rule) do
      require 'json'

      JSON.parse(File.read(File.expand_path('../../fixtures/waf_rules.json', __dir__)))
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
      code, result = context.run(passing_input, {}, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :ok
      expect(result.status).to eq :ok
      expect(result.events).to eq []
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq []
      expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
    end

    it 'catches a match' do
      code, result = context.run(matching_input, {}, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :match
      expect(result.status).to eq :match
      expect(result.events).to be_a Array
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq []
      expect(result.events.find { |r| r['rule']['id'] == matching_input_rule }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
    end

    context 'with configured limits' do
      context 'exceeding max_container_size' do
        let(:handle) do
          described_class::Handle.new(rule, limits: { max_container_size: 1 })
        end

        context 'when key is ouside of limit yet found by path' do
          let(:matching_input) do
            { 1 => 1, 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP', 2 => 2 } }
          end

          it 'matches on matching input' do
            code, result = context.run(matching_input, {}, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :match
            expect(result.status).to eq :match
            expect(result.events).to be_a Array
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end

        context 'when sub-key is outside of limit yet found by path' do
          let(:matching_input) do
            { 1 => 1, 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP', 2 => 2 } }
          end

          it 'matches on matching input' do
            code, result = context.run(matching_input, {}, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :match
            expect(result.status).to eq :match
            expect(result.events).to be_a Array
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end

        context 'when sub-key is outside of limit yet found by path and value exceeds limit' do
          let(:matching_input) do
            { 1 => 1, 'server.request.headers.no_cookies' => { 2 => 2, 'user-agent' => { 3 => 3, 4 => 'Nessus SOAP' } } }
          end

          it 'passes on matching input outside of limit' do
            code, result = context.run(matching_input, {}, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :ok
            expect(result.status).to eq :ok
            expect(result.events).to eq []
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end

        context 'when sub-key is outside of limit yet found by path and value does not exceeds limit' do
          let(:matching_input) do
            { 1 => 1, 'server.request.headers.no_cookies' => { 2 => 2, 'user-agent' => { 4 => 'Nessus SOAP' } } }
          end

          it 'passes input inside of limit' do
            code, result = context.run(matching_input, {}, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :ok
            expect(result.status).to eq :ok
            expect(result.events).to eq []
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end
      end

      context 'exceeding max_container_depth' do
        let(:handle) do
          described_class::Handle.new(rule, limits: { max_container_depth: 1 })
        end

        context 'when value is outside of limit' do
          let(:matching_input) do
            { 'server.request.headers.no_cookies' => { 'user-agent' => ['Nessus SOAP'] } }
          end

          it 'passes on matching input outside of limit' do
            code, result = context.run(matching_input, {}, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :ok
            expect(result.status).to eq :ok
            expect(result.events).to eq []
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []
            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end

        context 'when value is inside of limit' do
          let(:matching_input) do
            { 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } }
          end

          it 'matches on matching input inside of limit' do
            code, result = context.run(matching_input, {}, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :match
            expect(result.status).to eq :match
            expect(result.events).to be_a Array
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end
      end

      context 'exceeding max_string_length' do
        let(:handle) do
          described_class::Handle.new(rule, limits: { max_string_length: 1 })
        end

        let(:matching_input) do
          { 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } }
        end

        it 'passes on matching input outside of limit' do
          code, result = context.run(matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime

          expect(code).to eq :ok
          expect(result.status).to eq :ok
          expect(result.events).to eq []
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end
      end
    end

    context 'with obfuscator' do
      context 'matching a key' do
        let(:handle) do
          described_class::Handle.new(rule, obfuscator: { key_regex: 'user-agent' })
        end

        let(:matching_input) do
          { 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } }
        end

        it 'obfuscates the key' do
          code, result = context.run(matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.events.first['rule_matches'].first['parameters'].first['value']).to eq '<Redacted>'
          expect(result.events.first['rule_matches'].first['parameters'].first['highlight']).to include '<Redacted>'
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end
      end

      context 'matching a value' do
        let(:handle) do
          described_class::Handle.new(rule, obfuscator: { value_regex: 'SOAP' })
        end

        let(:matching_input) do
          { 'server.request.headers.no_cookies' => { 'user-agent' => ['Nessus SOAP'] } }
        end

        it 'obfuscates the value' do
          code, result = context.run(matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.events.first['rule_matches'].first['parameters'].first['value']).to eq '<Redacted>'
          expect(result.events.first['rule_matches'].first['parameters'].first['highlight']).to include '<Redacted>'
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end
      end
    end

    context 'Evaluating multiple times' do
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
        { 'server.response.status' => '404' }
      end

      let(:matching_input_sqli) do
        { 'server.request.query' => [['foo', '1 OR 1;']] }
      end

      let(:matching_input_sqli_rule) do
        'crs-942-100'
      end

      it 'runs once on passing input' do
        code, result = context.run(passing_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(passing_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs once on unchanged input' do
        code, result = context.run(matching_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        code, result = context.run(matching_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        # TODO: also stress test changing matching values, e.g using arachni/v\d+
        # CHECK: maybe it will bail out and return only the first one?
      end

      context 'on a sizeable rule' do
        let(:long_rule) { 'crs-930-120' }

        it 'matches the first entry' do
          first_matching_input = {
            'server.request.body' => { 'a' => '/.htaccess' }
          }
          code, result = context.run(first_matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          expect(result.events.find { |r| r['rule']['id'] == long_rule }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{long_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end

        it 'matches the last entry' do
          last_matching_input = {
            'server.request.body' => { 'a' => '/yarn.lock' }
          }
          code, result = context.run(last_matching_input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false

          expect(result.events.find { |r| r['rule']['id'] == long_rule }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{long_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end
      end

      context 'stress testing' do
        it 'runs once on unchanged input' do
          skip 'slow'

          code, result = context.run(matching_input_user_agent, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          expect(result.events).to be_a Array
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          # stress test rerun on unchanged input
          100.times do
            code, result = context.run(matching_input_user_agent, timeout_usec)
            perf_store[:total_runtime] << result.total_runtime
            expect(code).to eq :ok
            expect(result.status).to eq :ok
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
            expect(result.events).to eq []
            expect(result.total_runtime).to be > 0
            expect(result.timeout).to eq false
            expect(result.actions).to eq []
          end

          # TODO: also stress test changing matching values, e.g using arachni/v\d+
          # CHECK: maybe it will bail out and return only the first one?
        end
      end

      context 'with timeout' do
        let(:timeout_usec) { 1 }

        it 'runs but does not match' do
          code, result = context.run(matching_input_user_agent, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime

          expect(code).to eq :ok
          expect(result.status).to eq :ok
          expect(result.events).to eq []
          expect(result.total_runtime).to be > 0
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to_not be_nil

          expect(result.timeout).to eq true
          expect(result.actions).to eq []
        end
      end

      it 'runs twice on changed input value' do
        code, result = context.run(passing_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(result.events.find { |r| r['rule']['id'] == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs twice on additional input key for an independent rule' do
        code, result = context.run(matching_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(result.events.find { |r| r['rule']['id'] == matching_input_user_agent_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_sqli, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(result.events.find { |r| r['rule']['id'] == matching_input_user_agent_rule }).to be_nil
        expect(result.events.find { |r| r['rule']['id'] == matching_input_sqli_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_sqli_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs twice on additional input key for a rule needing both keys to match' do
        code, result = context.run(matching_input_path, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_path_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_status, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq []

        expect(result.events.find { |r| r['rule']['id'] == matching_input_path_rule }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_path_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
      end

      it 'runs twice on additional input key for a rule needing both keys to match with a scoped reference' do
        lambda do
          # for this test the first input needs to be in a short-lived scope
          input = { 'server.request.uri.raw' => '/admin.php' }

          code, result = context.run(input, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :ok
          expect(result.status).to eq :ok
          expect(result.events).to eq []
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_path_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end.call

        # garbage collect the first input
        # context should still be able to run and use previously passed input
        GC.start

        lambda do
          code, result = context.run(matching_input_status, {}, timeout_usec)
          perf_store[:total_runtime] << result.total_runtime
          expect(code).to eq :match
          expect(result.status).to eq :match
          expect(result.events).to be_a Array
          expect(result.total_runtime).to be > 0
          expect(result.timeout).to eq false
          expect(result.actions).to eq []

          expect(result.events.find { |r| r['rule']['id'] == matching_input_path_rule }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_path_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end.call
      end
    end
  end

  context 'with processors' do
    let(:rule) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '1.2.3'
        },
        'rules' => [
          {
            "id" => "crs-913-120",
            "name" => "Known security scanner filename/argument",
            "tags" => {
              "type" => "security_scanner",
              "crs_id" => "913120",
              "category" => "attack_attempt"
            },
            "conditions" => [
              {
                "parameters" => {
                  "inputs" => [
                    {
                      "address" => "server.request.query"
                    },
                  ],
                  "regex" => "<EMBED[\\s/+].*?(?:src|type).*?=",
                  "options" => {
                    "min_length" => 11
                  }
                },
                "operator" => "match_regex"
              }
            ],
            "transformers" => [
              "removeNulls"
            ]
          }
        ],
        # Extracted the processor configuration from
        # https://gist.github.com/Anilm3/db97e3f24869ee4f4d0eb96655df6983
        "processors" => [
          {
            "id" => "processor-001",
            "generator" => "extract_schema",
            "conditions" => [
              {
                "operator" => "equals",
                "parameters" => {
                  "inputs" => [
                    {
                      "address" => "waf.context.processor",
                      "key_path" => [
                        "extract-schema"
                      ]
                    }
                  ],
                  "type" => "boolean",
                  "value" => true
                }
              }
            ],
            "parameters" => {
              "mappings" => [
                {
                  "inputs" => [
                    {
                      "address" => "server.request.body"
                    }
                  ],
                  "output" => "_dd.appsec.s.req.body"
                },
                {
                  "inputs" => [
                    {
                      "address" => "server.request.headers.no_cookies"
                    }
                  ],
                  "output" => "_dd.appsec.s.req.headers"
                },
                {
                  "inputs" => [
                    {
                      "address" => "server.request.query"
                    }
                  ],
                  "output" => "_dd.appsec.s.req.query"
                },
                {
                  "inputs" => [
                    {
                      "address" => "server.request.path_params"
                    }
                  ],
                  "output" => "_dd.appsec.s.req.params"
                },
                {
                  "inputs" => [
                    {
                      "address" => "server.request.cookies"
                    }
                  ],
                  "output" => "_dd.appsec.s.req.cookies"
                },
                {
                  "inputs" => [
                    {
                      "address" => "server.response.headers.no_cookies"
                    }
                  ],
                  "output" => "_dd.appsec.s.res.headers"
                },
                {
                  "inputs" => [
                    {
                      "address" => "server.response.body"
                    }
                  ],
                  "output" => "_dd.appsec.s.res.body"
                }
              ]
            },
            "evaluate" => false,
            "output" => true
          }
        ]
      }
    end

    context 'with schema extraction' do
      it 'populates derivatives' do
        waf_args = {
          'server.request.query' => {
            'hello' => 'EMBED',
          },
          'waf.context.processor' => {
            "extract-schema" => true
          }
        }

        code, result = context.run(waf_args, {}, timeout_usec)
        expect(code).to eq :ok
        expect(result.derivatives).to_not be_empty
        expect(result.derivatives).to eq({"_dd.appsec.s.req.query" => [{"hello" => [8]}]})
      end
    end

    context 'with schema extraction' do
      it 'populates derivatives' do
        waf_args = {
          'server.request.query' => {
            'hello' => 'EMBED',
          },
          'waf.context.processor' => {
            "extract-schema" => false
          }
        }

        code, result = context.run(waf_args, {}, timeout_usec)
        expect(code).to eq :ok
        expect(result.derivatives).to be_empty
      end
    end
  end
end
