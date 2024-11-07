# frozen_string_literal:true

require 'datadog/appsec/waf'

RSpec.shared_context 'waf context' do
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

  let(:passing_input) do
    { value1: [4242, 'randomString'], value2: ['nope'] }
  end

  let(:matching_input) do
    { value1: [4242, 'randomString'], value2: ['rule1'] }
  end

  let(:timeout_usec) { 10_000_000 }
  let(:handle) { Datadog::AppSec::WAF::Handle.new(rule) }
  let(:context) { Datadog::AppSec::WAF::Context.new(handle) }
  let(:diagnostics_obj) { Datadog::AppSec::WAF::LibDDWAF::Object.new }
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
end
