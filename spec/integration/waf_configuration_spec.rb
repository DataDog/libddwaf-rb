require "spec_helper"

RSpec.describe "WAF configuration" do
  let(:rules) do
    {
      "version" => "2.2",
      "rules" => [{
        "id" => "security-scanner",
        "name" => "Security scanner",
        "tags" => {"type" => "security_scanner", "category" => "attack_attempt"},
        "conditions" => [{
          "operator" => "match_regex",
          "parameters" => {
            "inputs" => [{"address" => "server.request.headers.no_cookies", "key_path" => ["user-agent"]}],
            "regex" => "Nessus SOAP"
          }
        }]
      }]
    }
  end

  context "fixed input limits" do
    let(:converter) { Datadog::AppSec::WAF::Converter }
    context "max_container_size" do
      it "matches when value is within container size limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new
        builder.add_or_update_config(rules, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        headers = (converter::MAX_CONTAINER_SIZE - 1).times.map { |i| ["header#{i}", "value"] }.to_h
        headers["user-agent"] = "Nessus SOAP"
        result = context.eval({"server.request.headers.no_cookies" => headers}, 10_000_000)

        expect(result.status).to eq(:match)
        expect(result).not_to be_input_truncated
      ensure
        context&.finalize!
        handle&.finalize!
        builder&.finalize!
      end

      it "does not match when value is not within container size limit" do
        builder = Datadog::AppSec::WAF::HandleBuilder.new
        builder.add_or_update_config(rules, path: "some/path")
        handle = builder.build_handle
        context = handle.build_context

        headers = converter::MAX_CONTAINER_SIZE.times.map { |i| ["header#{i}", "value"] }.to_h
        headers["user-agent"] = "Nessus SOAP"
        result = context.eval({"server.request.headers.no_cookies" => headers}, 10_000_000)

        expect(result.status).to eq(:ok)
        expect(result).to be_input_truncated
      ensure
        context&.finalize!
        handle&.finalize!
        builder&.finalize!
      end
    end
  end

  context "obfuscator" do
    it "matches and obfuscates keys" do
      builder = Datadog::AppSec::WAF::HandleBuilder.new(obfuscator: {key_regex: "user-agent"})
      builder.add_or_update_config(rules, path: "some/path")
      handle = builder.build_handle
      context = handle.build_context

      result = context.eval({"server.request.headers.no_cookies" => {"user-agent" => ["Nessus SOAP"]}}, 10_000_000)

      expect(result.status).to eq(:match)
      expect(result.events.dig(0, "rule_matches", 0, "parameters", 0, "value")).to eq("<Redacted>")
    ensure
      context&.finalize!
      handle&.finalize!
      builder&.finalize!
    end

    it "matches and obfuscates values" do
      builder = Datadog::AppSec::WAF::HandleBuilder.new(obfuscator: {value_regex: "SOAP"})
      builder.add_or_update_config(rules, path: "some/path")
      handle = builder.build_handle
      context = handle.build_context

      result = context.eval({"server.request.headers.no_cookies" => {"user-agent" => ["Nessus SOAP"]}}, 10_000_000)

      expect(result.status).to eq(:match)
      expect(result.events.dig(0, "rule_matches", 0, "parameters", 0, "value")).to eq("<Redacted>")
    ensure
      context&.finalize!
      handle&.finalize!
      builder&.finalize!
    end
  end
end
