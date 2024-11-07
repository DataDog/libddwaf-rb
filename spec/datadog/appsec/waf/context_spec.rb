# frozen_string_literal: true

require 'spec_helper'
require 'datadog/appsec/waf/context'

RSpec.describe Datadog::AppSec::WAF::Context do
  include_context 'waf context'

  it 'creates a valid context' do
    expect(context.context_obj.null?).to be false
  end

  it 'raises an error when failing to create a context' do
    invalid_rule = {}
    invalid_rule_obj = Datadog::AppSec::WAF::Converter.ruby_to_object(invalid_rule)
    config_obj = Datadog::AppSec::WAF::LibDDWAF::Config.new
    invalid_handle_obj = Datadog::AppSec::WAF::LibDDWAF.ddwaf_init(invalid_rule_obj, config_obj, diagnostics_obj)
    expect(invalid_handle_obj.null?).to be true
    invalid_handle = Datadog::AppSec::WAF::Handle.new(rule)
    invalid_handle.instance_eval do
      @handle_obj = invalid_handle_obj
    end
    expect(invalid_handle.handle_obj.null?).to be true
    expect { described_class.new(invalid_handle) }.to raise_error Datadog::AppSec::WAF::LibDDWAF::Error
  end

  describe '#run' do
    it 'passes non-matching persistent data' do
      code, result = context.run(passing_input, {}, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq(:ok)
      expect(result.status).to eq(:ok)
      expect(result.events).to eq([])
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq(false)
      expect(result.actions).to eq({})
    end

    it 'passes non-matching ephemeral data' do
      code, result = context.run({}, passing_input, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :ok
      expect(result.status).to eq :ok
      expect(result.events).to eq []
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq(false)
      expect(result.actions).to eq({})
    end

    it 'catches a match on persistent data' do
      code, result = context.run(matching_input, {}, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :match
      expect(result.status).to eq :match
      expect(result.events).to be_a Array
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq({})
    end

    it 'catches a match on ephemeral data' do
      code, result = context.run({}, matching_input, timeout_usec)
      perf_store[:total_runtime] << result.total_runtime
      expect(code).to eq :match
      expect(result.status).to eq :match
      expect(result.events).to be_a Array
      expect(result.total_runtime).to be > 0
      expect(result.timeout).to eq false
      expect(result.actions).to eq({})
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
          expect(result.actions).to eq({})
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
          expect(result.actions).to eq({})
        end
      end
    end

    context 'stress testing' do
      let(:run_count) { 500 }
      let(:thread_count) { 200 }

      it 'creates a context in each thread' do
        handle

        result = { ok: 0, match: 0, err_internal: 0, err_invalid_object: 0, err_invalid_argument: 0 }
        start_barrier = Barrier.new(thread_count)
        mutex = Mutex.new

        threads = thread_count.times.map do
          Thread.new do
            context = described_class.new(handle)
            start_barrier.sync
            run_count.times do |i|
              ephemeral_data = i.even? ? matching_input : passing_input
              ephemeral_data[:value3] = [i]
              code, = context.run({}, ephemeral_data, 10_000_000)
              mutex.synchronize { result[code] += 1 }
            end
          end
        end

        threads.each(&:join)

        expect(result[:err_internal]).to eq 0
        expect(result[:err_invalid_object]).to eq 0
        expect(result[:err_invalid_argument]).to eq 0
        expect(result[:ok]).to eq 50_000
        expect(result[:match]).to eq 50_000
      end
    end
  end

  context 'run with a custom rules' do
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
              }
            ],
            'action' => 'record'
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
              }
            ],
            'action' => 'record'
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

  context 'run with a big ruleset' do
    let(:rule) do
      require 'json'

      JSON.parse(File.read(File.expand_path('../../../fixtures/waf_rules.json', __dir__)))
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
      expect(result.actions).to eq({})
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
      expect(result.actions).to eq({})
      expect(result.events.find { |r| r['rule']['id'] == matching_input_rule }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
      expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
    end

    context 'with configured limits' do
      context 'exceeding max_container_size' do
        let(:handle) do
          Datadog::AppSec::WAF::Handle.new(rule, limits: { max_container_size: 1 })
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
            expect(result.actions).to eq({})

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
            expect(result.actions).to eq({})

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
            expect(result.actions).to eq({})

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
            expect(result.actions).to eq({})

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end
      end

      context 'exceeding max_container_depth' do
        let(:handle) do
          Datadog::AppSec::WAF::Handle.new(rule, limits: { max_container_depth: 1 })
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
            expect(result.actions).to eq({})
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
            expect(result.actions).to eq({})

            expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
            expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
          end
        end
      end

      context 'exceeding max_string_length' do
        let(:handle) do
          Datadog::AppSec::WAF::Handle.new(rule, limits: { max_string_length: 1 })
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
          expect(result.actions).to eq({})

          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end
      end
    end

    context 'with obfuscator' do
      context 'matching a key' do
        let(:handle) do
          Datadog::AppSec::WAF::Handle.new(rule, obfuscator: { key_regex: 'user-agent' })
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
          expect(result.actions).to eq({})

          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end
      end

      context 'matching a value' do
        let(:handle) do
          Datadog::AppSec::WAF::Handle.new(rule, obfuscator: { value_regex: 'SOAP' })
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
          expect(result.actions).to eq({})

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
        expect(result.actions).to eq({})

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(passing_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq({})

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
        expect(result.actions).to eq({})

        code, result = context.run(matching_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :ok
        expect(result.status).to eq :ok
        expect(result.events).to eq []
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq({})

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
          expect(result.actions).to eq({})

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
          expect(result.actions).to eq({})

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
            expect(result.actions).to eq({})
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
          expect(result.actions).to eq({})
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
        expect(result.actions).to eq({})

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_user_agent_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_user_agent, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq({})

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
        expect(result.actions).to eq({})

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
        expect(result.actions).to eq({})

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
        expect(result.actions).to eq({})

        expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_path_rule}'/ }).to_not be_nil
        expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil

        code, result = context.run(matching_input_status, {}, timeout_usec)
        perf_store[:total_runtime] << result.total_runtime
        expect(code).to eq :match
        expect(result.status).to eq :match
        expect(result.events).to be_a Array
        expect(result.total_runtime).to be > 0
        expect(result.timeout).to eq false
        expect(result.actions).to eq({})

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
          expect(result.actions).to eq({})

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
          expect(result.actions).to eq({})

          expect(result.events.find { |r| r['rule']['id'] == matching_input_path_rule }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Evaluating .* '#{matching_input_path_rule}'/ }).to_not be_nil
          expect(log_store.find { |log| log[:message] =~ /Ran out of time/ }).to be_nil
        end.call
      end
    end
  end

  context 'run with processors' do
    let(:rule) do
      {
        'version' => '2.2',
        'metadata' => {
          'rules_version' => '1.2.3'
        },
        'rules' => [
          {
            'id' => 'crs-913-120',
            'name' => 'Known security scanner filename/argument',
            'tags' => {
              'type' => 'security_scanner',
              'crs_id' => '913120',
              'category' => 'attack_attempt'
            },
            'conditions' => [
              {
                'parameters' => {
                  'inputs' => [
                    {
                      'address' => 'server.request.query'
                    }
                  ],
                  'regex' => '<EMBED[\\s/+].*?(?:src|type).*?=',
                  'options' => {
                    'min_length' => 11
                  }
                },
                'operator' => 'match_regex'
              }
            ],
            'transformers' => [
              'removeNulls'
            ]
          }
        ],
        # Extracted the processor configuration from
        # https://gist.github.com/Anilm3/db97e3f24869ee4f4d0eb96655df6983
        'processors' => [
          {
            'id' => 'processor-001',
            'generator' => 'extract_schema',
            'conditions' => [
              {
                'operator' => 'equals',
                'parameters' => {
                  'inputs' => [
                    {
                      'address' => 'waf.context.processor',
                      'key_path' => [
                        'extract-schema'
                      ]
                    }
                  ],
                  'type' => 'boolean',
                  'value' => true
                }
              }
            ],
            'parameters' => {
              'mappings' => [
                {
                  'inputs' => [
                    {
                      'address' => 'server.request.body'
                    }
                  ],
                  'output' => '_dd.appsec.s.req.body'
                },
                {
                  'inputs' => [
                    {
                      'address' => 'server.request.headers.no_cookies'
                    }
                  ],
                  'output' => '_dd.appsec.s.req.headers'
                },
                {
                  'inputs' => [
                    {
                      'address' => 'server.request.query'
                    }
                  ],
                  'output' => '_dd.appsec.s.req.query'
                },
                {
                  'inputs' => [
                    {
                      'address' => 'server.request.path_params'
                    }
                  ],
                  'output' => '_dd.appsec.s.req.params'
                },
                {
                  'inputs' => [
                    {
                      'address' => 'server.request.cookies'
                    }
                  ],
                  'output' => '_dd.appsec.s.req.cookies'
                },
                {
                  'inputs' => [
                    {
                      'address' => 'server.response.headers.no_cookies'
                    }
                  ],
                  'output' => '_dd.appsec.s.res.headers'
                },
                {
                  'inputs' => [
                    {
                      'address' => 'server.response.body'
                    }
                  ],
                  'output' => '_dd.appsec.s.res.body'
                }
              ]
            },
            'evaluate' => false,
            'output' => true
          }
        ]
      }
    end

    context 'with schema extraction' do
      it 'populates derivatives' do
        waf_args = {
          'server.request.query' => {
            'hello' => 'EMBED'
          },
          'waf.context.processor' => {
            'extract-schema' => true
          }
        }

        code, result = context.run(waf_args, {}, timeout_usec)
        expect(code).to eq :ok
        expect(result.derivatives).to_not be_empty
        expect(result.derivatives).to eq({ '_dd.appsec.s.req.query' => [{ 'hello' => [8] }] })
      end
    end

    context 'without schema extraction' do
      it 'populates derivatives' do
        waf_args = {
          'server.request.query' => {
            'hello' => 'EMBED'
          },
          'waf.context.processor' => {
            'extract-schema' => false
          }
        }

        code, result = context.run(waf_args, {}, timeout_usec)
        expect(code).to eq :ok
        expect(result.derivatives).to be_empty
      end
    end
  end
end
