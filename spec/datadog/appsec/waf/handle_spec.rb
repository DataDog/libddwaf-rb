# frozen_string_literal:true

require 'spec_helper'

RSpec.describe Datadog::AppSec::WAF::Handle do
  let(:rule) do
    {
      'version' => '2.2',
      'metadata' => {
        'rules_version' => '1.2.3'
      },
      'rules' => [
        {
          'id' => '1',
          'name' => 'Rule 1',
          'tags' => { 'type' => 'flow1' },
          'conditions' => [
            {
              'operator' => 'match_regex',
              'parameters' => { 'inputs' => [{ 'address' => 'value2' }], 'regex' => 'rule1' }
            }
          ],
          'action' => 'record'
        }
      ]
    }
  end

  let(:matching_input) do
    { value1: [4242, 'randomString'], value2: ['rule1'] }
  end

  let(:timeout_usec) { 10_000_000 }
  let(:handle) { described_class.new(rule) }
  let(:context) { Datadog::AppSec::WAF::Context.new(handle) }
  let(:log_store) { [] }

  let(:perf_store) do
    {
      total_runtime: []
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

  it 'lists required addresses' do
    expect(handle.required_addresses).to eq ['value2']
  end

  it 'raises an error when failing to create a handle' do
    invalid_rule = {}
    expect { described_class.new(invalid_rule) }.to raise_error Datadog::AppSec::WAF::LibDDWAF::Error
  end

  it 'records good diagnostics' do
    expect(handle.diagnostics).to be_a Hash
    expect(handle.diagnostics['rules']['loaded'].size).to eq(1)
    expect(handle.diagnostics['rules']['failed'].size).to eq(0)
    expect(handle.diagnostics['rules']['errors']).to be_empty
    expect(handle.diagnostics['ruleset_version']).to eq('1.2.3')
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
              }
            ],
            'action' => 'record'
          },
          {
            'id' => 2,
            'name' => 'Rule 2',
            'tags' => { 'type' => 'flow2' },
            'conditions' => [
              {
                'operator' => 'match_regex',
                'parameters' => { 'inputs' => [{ 'address' => 'value2' }], 'regex' => 'rule2' }
              }
            ],
            'action' => 'record'
          }
        ]
      }
    end

    it 'records bad diagnostics' do
      expect(handle.diagnostics).to be_a Hash
      expect(handle.diagnostics['rules']['loaded'].size).to eq(1)
      expect(handle.diagnostics['rules']['failed'].size).to eq(1)
      expect(handle.diagnostics['rules']['errors']).to_not be_empty
      expect(handle.diagnostics['ruleset_version']).to eq('1.2.3')
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
              }
            ],
            'action' => 'record'
          }
        ]
      }
    end

    let(:handle_exception) do
      handle
    rescue StandardError => e
      return e
    end

    it 'records bad diagnostics in the exception' do
      expect(handle_exception).to be_a(Datadog::AppSec::WAF::LibDDWAF::Error)
      expect(handle_exception.diagnostics).to be_a Hash
      expect(handle_exception.diagnostics['rules']['loaded'].size).to eq(0)
      expect(handle_exception.diagnostics['rules']['failed'].size).to eq(1)
      expect(handle_exception.diagnostics['rules']['errors']).to_not be_empty
      expect(handle_exception.diagnostics['ruleset_version']).to eq('1.2.3')
    end
  end

  describe '#merge' do
    context 'valid merge data' do
      context 'rules override' do
        it 'disable an exiting rule' do
          data = {
            'rules_override' => [
              {
                'enabled' => false,
                'id' => '1'
              }
            ]
          }

          code, = context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match

          new_handle = handle.merge(data)
          expect(new_handle).to be_a(described_class)

          new_context = Datadog::AppSec::WAF::Context.new(new_handle)
          code, = new_context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :ok

          new_context.finalize
          new_handle.finalize
          handle.finalize
          context.finalize
        end

        it 'updates rule actions' do
          data = {
            'rules_override' => [
              {
                'id' => '1',
                'on_match' => ['block']
              }
            ]
          }

          code, result = context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match
          expect(result.actions).to be_empty

          new_handle = handle.merge(data)
          expect(new_handle).to be_a(described_class)

          new_context = Datadog::AppSec::WAF::Context.new(new_handle)
          code, result = new_context.run(matching_input, {}, timeout_usec)
          expect(code).to eq :match
          expect(result.actions.keys).to eq(['block_request'])

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
            'rules_data' => [
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
          expect(new_handle).to be_a(described_class)

          new_context = Datadog::AppSec::WAF::Context.new(new_handle)
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
        data = { 'invalid_data' => 'a' }

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
            }
          ]
        }
      end

      let(:matching_input) do
        { 'server.request.headers.no_cookies' => { 'user-agent' => 'Nessus SOAP' } }
      end

      it 'retains old handle obfuscator configured' do
        old_handle = described_class.new(rule, obfuscator: { key_regex: 'user-agent' })
        old_context = Datadog::AppSec::WAF::Context.new(old_handle)

        code, = old_context.run(matching_input, {}, timeout_usec)
        expect(code).to eq :ok

        new_handle = old_handle.merge(new_ruleset)
        expect(new_handle).to be_a(described_class)

        # Finalize old handle and context
        # It should free all related information from old_handle and old_context
        # Except the old handle configuration, which is propagateed through #merge
        old_handle.finalize
        old_context.finalize

        new_context = Datadog::AppSec::WAF::Context.new(new_handle)

        new_code, new_result = new_context.run(matching_input, {}, timeout_usec)
        expect(new_code).to eq :match

        expect(new_result.events.first['rule_matches'].first['parameters'].first['value']).to eq '<Redacted>'
        expect(new_result.events.first['rule_matches'].first['parameters'].first['highlight']).to include '<Redacted>'
      end
    end
  end
end
