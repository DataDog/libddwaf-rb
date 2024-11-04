# frozen_string_literal: true

require 'spec_helper'
require 'datadog/appsec/waf/result'

RSpec.describe Datadog::AppSec::WAF::Result do
  describe '#to_h' do
    let(:actions) do
      { 'block_request' => { 'status_code' => '403', 'type' => 'auto', 'grpc_status_code' => '10' } }
    end
    let(:events) do
      [
        {
          'rule' => {
            'id' => 'rasp-003-001',
            'name' => 'SQL Injection',
            'tags' => {},
            'on_match' => ['block']
          },
          'rule_matches' => [
            {
              'operator' => 'sqli_detector',
              'operator_value' => '',
              'parameters' => [
                { 'resource' => {}, 'params' => {}, 'db_type' => {}, 'highlight' => [] }
              ]
            }
          ]
        }
      ]
    end

    let(:result) { described_class.new(:match, events, 286_125, false, actions, {}) }

    it 'converts to Hash' do
      expect(result.to_h).to eq({
                                  status: :match,
                                  events: events,
                                  timeout: false,
                                  total_runtime: 286_125,
                                  actions: actions,
                                  derivatives: {}
                                })
    end
  end
end
