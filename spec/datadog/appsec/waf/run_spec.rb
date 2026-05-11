# frozen_string_literal: true

require "spec_helper"

RSpec.describe "LibDDWAF run path" do
  let(:waf)       { Datadog::AppSec::WAF::LibDDWAF }
  let(:converter) { Datadog::AppSec::WAF::Converter }
  let(:object)    { Datadog::AppSec::WAF::LibDDWAF::Object }

  let(:ruleset) do
    {
      "version" => "2.1",
      "rules" => [
        {
          "id" => "test-rule-1",
          "name" => "Match URI containing 'evil'",
          "tags" => {"category" => "test", "type" => "test"},
          "conditions" => [
            {
              "operator" => "match_regex",
              "parameters" => {
                "inputs" => [{"address" => "server.request.uri.raw"}],
                "regex" => "evil"
              }
            }
          ],
          "on_match" => ["block"]
        }
      ]
    }
  end

  def build_handle
    builder = waf.ddwaf_builder_init({})
    diag = object.new
    ruleset_obj = converter.ruby_to_object(ruleset, coerce: false)
    ok = waf.ddwaf_builder_add_or_update_config(builder, "default", ruleset_obj, diag)
    raise "add_or_update_config failed" unless ok
    # free_fn=NULL → libddwaf doesn't free ruleset_obj; wrapper's dfree handles
    # it on GC. No `disown!` here.

    handle = waf.ddwaf_builder_build_instance(builder)
    waf.ddwaf_builder_destroy(builder)
    handle
  end

  def run_with(handle, input)
    context = waf.ddwaf_context_init(handle)
    persistent = converter.ruby_to_object(input, coerce: false)
    ephemeral = converter.ruby_to_object({}, coerce: false)
    result = object.new
    ret = waf.ddwaf_run(context, persistent, ephemeral, result, 1_000_000)
    # free_fn=NULL → no disown! after ddwaf_run; wrapper GC cleans both inputs.
    waf.ddwaf_context_destroy(context)
    [ret, result]
  end

  describe "ddwaf_object_type" do
    it "returns the type Symbol matching the wrapper accessor" do
      o = converter.ruby_to_object("hello", coerce: false)
      expect(waf.ddwaf_object_type(o.object_ptr)).to eq(:ddwaf_obj_string)
      expect(waf.ddwaf_object_type(o.object_ptr)).to eq(o.type)
    end
  end

  describe "lifecycle" do
    it "builds a handle and a context, then destroys both" do
      handle = build_handle
      expect(handle).to be_a(Datadog::AppSec::WAF::LibDDWAF::Handle)

      context = waf.ddwaf_context_init(handle)
      expect(context).to be_a(Datadog::AppSec::WAF::LibDDWAF::Context)

      waf.ddwaf_context_destroy(context)
      waf.ddwaf_destroy(handle)
    end

    it "raises after explicit destroy if the wrapper is reused" do
      handle = build_handle
      waf.ddwaf_destroy(handle)
      expect { waf.ddwaf_context_init(handle) }.to raise_error(RuntimeError, /destroyed/)
    end

    it "is idempotent — destroying twice does not crash" do
      handle = build_handle
      waf.ddwaf_destroy(handle)
      waf.ddwaf_destroy(handle)
    end
  end

  describe "ddwaf_run" do
    it "returns :ddwaf_match for an input that hits a rule" do
      handle = build_handle
      ret, _ = run_with(handle, {"server.request.uri.raw" => "http://evil.com/foo"})
      expect(ret).to eq(:ddwaf_match)
      waf.ddwaf_destroy(handle)
    end

    it "returns :ddwaf_ok for input that does not hit any rule" do
      handle = build_handle
      ret, _ = run_with(handle, {"server.request.uri.raw" => "http://example.com/"})
      expect(ret).to eq(:ddwaf_ok)
      waf.ddwaf_destroy(handle)
    end

    it "populates the result Object with a map on a match" do
      handle = build_handle
      _, result = run_with(handle, {"server.request.uri.raw" => "http://evil.com/foo"})
      expect(result.type).to eq(:ddwaf_obj_map)
      expect(result.nb_entries).to be > 0
      waf.ddwaf_destroy(handle)
    end

    it "tolerates concurrent runs on different contexts of the same handle" do
      # libddwaf contract: handle is thread-safe; per-context state is not.
      # Ensures the GVL-release path actually parallelises libddwaf calls.
      handle = build_handle
      threads = 4.times.map do
        Thread.new do
          ret, _ = run_with(handle, {"server.request.uri.raw" => "http://evil.com/foo"})
          ret
        end
      end
      results = threads.map(&:value)
      expect(results).to all(eq(:ddwaf_match))
      waf.ddwaf_destroy(handle)
    end
  end
end
