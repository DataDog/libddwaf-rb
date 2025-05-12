require "spec_helper"

RSpec.describe "WAF configuration" do
  let(:waf_config) do
    JSON.parse(File.read("spec/fixtures/waf_rules.json"))
  end

  context "limits" do
    context "max_container_size" do
      it "matches when value is within container size limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new
        builder.add_or_update_config(config: waf_config, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        result = context.run({"server.request.headers.no_cookies" => {"user-agent" => "Nessus SOAP"}}, {})

        expect(result.status).to eq(:match)
      end

      it "does not match when value is not within container size limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new(limits: {max_container_size: 1})
        builder.add_or_update_config(config: waf_config, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        result = context.run({"server.request.headers.no_cookies" => {"another" => "key", "user-agent" => "Nessus SOAP"}}, {})

        expect(result.status).to eq(:ok)
      end
    end

    context "max_container_depth" do
      it "matches when value is within container depth limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new
        builder.add_or_update_config(config: waf_config, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        result = context.run({"server.request.headers.no_cookies" => {"user-agent" => "Nessus SOAP"}}, {})

        expect(result.status).to eq(:match)
      end

      it "does not match when value is not within container depth limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new(limits: {max_container_depth: 1})
        builder.add_or_update_config(config: waf_config, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        result = context.run({"server.request.headers.no_cookies" => {"user-agent" => ["Nessus SOAP"]}}, {})

        expect(result.status).to eq(:ok)
      end
    end

    context "max_string_length" do
      it "matches when value is within string length limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new(limits: {max_string_length: 11})
        builder.add_or_update_config(config: waf_config, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        result = context.run({"server.request.headers.no_cookies" => {"user-agent" => "Nessus SOAP"}}, {})

        expect(result.status).to eq(:match)
      end

      it "does not match when value is not within string length limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new(limits: {max_string_length: 10})
        builder.add_or_update_config(config: waf_config, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        result = context.run({"server.request.headers.no_cookies" => {"user-agent" => ["Nessus SOAP"]}}, {})

        expect(result.status).to eq(:ok)
      end
    end
  end

  context "obfuscator" do
    it "matches and obfuscates keys" do
      builder = Datadog::AppSec::WAF::HandleBuilder.new(obfuscator: {key_regex: "user-agent"})
      builder.add_or_update_config(config: waf_config, path: "some/path")
      handle = builder.build_handle
      context = handle.build_context

      result = context.run({"server.request.headers.no_cookies" => {"user-agent" => ["Nessus SOAP"]}}, {})

      expect(result.status).to eq(:match)
      expect(result.events.dig(0, "rule_matches", 0, "parameters", 0, "value")).to eq("<Redacted>")
    end

    it "matches and obfuscates values" do
      builder = Datadog::AppSec::WAF::HandleBuilder.new(obfuscator: {value_regex: "SOAP"})
      builder.add_or_update_config(config: waf_config, path: "some/path")
      handle = builder.build_handle
      context = handle.build_context

      result = context.run({"server.request.headers.no_cookies" => {"user-agent" => ["Nessus SOAP"]}}, {})

      expect(result.status).to eq(:match)
      expect(result.events.dig(0, "rule_matches", 0, "parameters", 0, "value")).to eq("<Redacted>")
    end
  end
end
