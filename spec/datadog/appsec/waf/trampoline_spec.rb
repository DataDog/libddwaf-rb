# frozen_string_literal: true

require "spec_helper"
require "libddwaf_native"
require "rbconfig"

RSpec.describe "LibDDWAF trampolines" do
  let(:waf)    { Datadog::AppSec::WAF::LibDDWAF }
  let(:object) { Datadog::AppSec::WAF::LibDDWAF::Object }

  describe "ddwaf_get_version (0-arg, string return)" do
    it "returns the linked libddwaf version" do
      expect(waf.ddwaf_get_version).to eq("1.30.0")
    end
  end

  describe "primitive setter trampolines" do
    it "ddwaf_object_invalid sets type to :ddwaf_obj_invalid" do
      o = object.new
      ret = waf.ddwaf_object_invalid(o.object_ptr)
      expect(ret).not_to be_zero
      expect(o.type).to eq(:ddwaf_obj_invalid)
    end

    it "ddwaf_object_null sets type to :ddwaf_obj_null" do
      o = object.new
      waf.ddwaf_object_null(o.object_ptr)
      expect(o.type).to eq(:ddwaf_obj_null)
    end

    it "ddwaf_object_unsigned round-trips a uint64" do
      o = object.new
      waf.ddwaf_object_unsigned(o.object_ptr, 2**63)
      expect(o.type).to eq(:ddwaf_obj_unsigned)
      expect(o.unsigned_value).to eq(2**63)
    end

    it "ddwaf_object_signed round-trips a negative int64" do
      o = object.new
      waf.ddwaf_object_signed(o.object_ptr, -(2**62))
      expect(o.signed_value).to eq(-(2**62))
    end

    it "ddwaf_object_bool round-trips both boolean values" do
      [true, false].each do |b|
        o = object.new
        waf.ddwaf_object_bool(o.object_ptr, b)
        expect(o.type).to eq(:ddwaf_obj_bool)
        expect(o.bool_value).to eq(b)
      end
    end

    it "ddwaf_object_float round-trips a double" do
      o = object.new
      waf.ddwaf_object_float(o.object_ptr, Math::PI)
      expect(o.float_value).to eq(Math::PI)
    end

    it "ddwaf_object_string takes a NUL-terminated string" do
      o = object.new
      waf.ddwaf_object_string(o.object_ptr, "hello")
      expect(o.string_bytes).to eq("hello")
    end

    it "ddwaf_object_string_from_unsigned formats the integer" do
      o = object.new
      waf.ddwaf_object_string_from_unsigned(o.object_ptr, 42)
      expect(o.string_bytes).to eq("42")
    end

    it "ddwaf_object_string_from_signed formats with the sign" do
      o = object.new
      waf.ddwaf_object_string_from_signed(o.object_ptr, -42)
      expect(o.string_bytes).to eq("-42")
    end
  end

  describe "container trampolines" do
    it "ddwaf_object_array creates an empty array" do
      o = object.new
      waf.ddwaf_object_array(o.object_ptr)
      expect(o.type).to eq(:ddwaf_obj_array)
      expect(o.nb_entries).to eq(0)
    end

    it "ddwaf_object_map creates an empty map" do
      o = object.new
      waf.ddwaf_object_map(o.object_ptr)
      expect(o.type).to eq(:ddwaf_obj_map)
      expect(o.nb_entries).to eq(0)
    end

    it "ddwaf_object_array_add transfers ownership of a child" do
      arr = object.new
      waf.ddwaf_object_array(arr.object_ptr)
      child = object.new
      waf.ddwaf_object_unsigned(child.object_ptr, 7)

      expect(waf.ddwaf_object_array_add(arr.object_ptr, child.object_ptr)).to be true
      child.disown!

      expect(arr.nb_entries).to eq(1)
      expect(arr.array_index(0).unsigned_value).to eq(7)
    end

    it "ddwaf_object_map_add inserts a NUL-terminated-keyed entry" do
      mp = object.new
      waf.ddwaf_object_map(mp.object_ptr)
      v = object.new
      waf.ddwaf_object_bool(v.object_ptr, false)

      expect(waf.ddwaf_object_map_add(mp.object_ptr, "k1", v.object_ptr)).to be true
      v.disown!

      entry = mp.array_index(0)
      expect(entry.key_bytes).to eq("k1")
      expect(entry.bool_value).to eq(false)
    end
  end

  describe "primitive getter trampolines" do
    it "ddwaf_object_get_unsigned" do
      o = object.new
      waf.ddwaf_object_unsigned(o.object_ptr, 1234)
      expect(waf.ddwaf_object_get_unsigned(o.object_ptr)).to eq(1234)
    end

    it "ddwaf_object_get_signed" do
      o = object.new
      waf.ddwaf_object_signed(o.object_ptr, -99)
      expect(waf.ddwaf_object_get_signed(o.object_ptr)).to eq(-99)
    end

    it "ddwaf_object_get_bool" do
      o = object.new
      waf.ddwaf_object_bool(o.object_ptr, true)
      expect(waf.ddwaf_object_get_bool(o.object_ptr)).to eq(true)
    end

    it "ddwaf_object_get_float" do
      o = object.new
      waf.ddwaf_object_float(o.object_ptr, 1.5)
      expect(waf.ddwaf_object_get_float(o.object_ptr)).to eq(1.5)
    end

    it "ddwaf_object_size for an array" do
      arr = object.new
      waf.ddwaf_object_array(arr.object_ptr)
      3.times do |i|
        c = object.new
        waf.ddwaf_object_unsigned(c.object_ptr, i)
        waf.ddwaf_object_array_add(arr.object_ptr, c.object_ptr)
        c.disown!
      end
      expect(waf.ddwaf_object_size(arr.object_ptr)).to eq(3)
    end

    it "ddwaf_object_length for a string" do
      o = object.new
      waf.ddwaf_object_string(o.object_ptr, "abc")
      expect(waf.ddwaf_object_length(o.object_ptr)).to eq(3)
    end

    it "ddwaf_object_get_index returns a non-zero pointer into the parent" do
      arr = object.new
      waf.ddwaf_object_array(arr.object_ptr)
      c = object.new
      waf.ddwaf_object_unsigned(c.object_ptr, 99)
      waf.ddwaf_object_array_add(arr.object_ptr, c.object_ptr)
      c.disown!

      child_ptr = waf.ddwaf_object_get_index(arr.object_ptr, 0)
      expect(child_ptr).not_to be_zero
    end
  end

  describe "binary-string cfuncs (non-trampoline)" do
    it "ddwaf_object_stringl handles embedded NULs" do
      o = object.new
      bytes = "foo\x00bar".b
      waf.ddwaf_object_stringl(o.object_ptr, bytes, bytes.bytesize)
      expect(o.string_bytes).to eq(bytes)
      expect(o.nb_entries).to eq(7)
    end

    it "ddwaf_object_map_addl accepts binary keys" do
      mp = object.new
      waf.ddwaf_object_map(mp.object_ptr)
      v = object.new
      waf.ddwaf_object_signed(v.object_ptr, -1)
      key = "k\x00ey".b
      expect(waf.ddwaf_object_map_addl(mp.object_ptr, key, key.bytesize, v.object_ptr)).to be true
      v.disown!

      expect(mp.array_index(0).key_bytes).to eq(key)
    end
  end

  describe "FFX magic marker in the compiled extension" do
    # Sanity-check the Phase 4 trampoline ZJIT metadata is actually emitted.
    # Magic value 0x46464930 stored little-endian → bytes "\x30\x49\x46\x46".
    let(:bundle_path) do
      File.expand_path("../../../../lib/libddwaf_native.#{RbConfig::CONFIG["DLEXT"]}", __dir__)
    end

    it "appears at least once per registered trampoline" do
      skip "fallback build (extconf naked-attr probe = no)" unless Datadog::AppSec::WAF::LibDDWAF::TRAMPOLINES

      contents = File.binread(bundle_path)
      magic = "\x30\x49\x46\x46".b
      # 21 trampolines registered in trampolines.c (per Phase 4). Each emits
      # the magic exactly once. Allow some slack in case the linker produces
      # extra references (string tables, etc.) — assert at least 21.
      expect(contents.scan(magic).count).to be >= 21
    end
  end
end
