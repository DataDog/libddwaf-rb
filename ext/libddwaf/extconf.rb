require "rbconfig"

# Honor a `CC=` env override before mkmf is loaded — RbConfig::CONFIG['CC'] is
# set when Ruby itself was built and mkmf reads it from there. This lets a
# distribution-built Ruby (e.g. ruby:4.0 on Debian, which was built with gcc)
# use a different compiler at extension-build time. The naked-attribute probe
# below depends on this for aarch64-linux: gcc ignores the attribute, clang
# honors it.
if ENV["CC"]
  RbConfig::CONFIG["CC"] = ENV["CC"]
  RbConfig::MAKEFILE_CONFIG["CC"] = ENV["CC"]
end

require "mkmf"
require_relative "binary"
require_relative "../../lib/datadog/appsec/waf/version"

LIBDDWAF_VERSION = Datadog::AppSec::WAF::VERSION::BASE_STRING

host_platform = Gem::Platform.local.dup
host_platform.instance_eval { @version = nil } if host_platform.os == "darwin"
if host_platform.os == "linux" && host_platform.version.nil? && RUBY_PLATFORM =~ /linux-(.+)$/
  host_platform.instance_eval { @version = ::Regexp.last_match(1) }
end

LibDDWAFBinary.ensure_present(platform: host_platform, version: LIBDDWAF_VERSION)

host_variant = LibDDWAFBinary.variant_dir(host_platform, LIBDDWAF_VERSION)

$INCFLAGS << " -I#{File.join(host_variant, "include")}"
$LDFLAGS << " -L#{File.join(host_variant, "lib")} -lddwaf"

# `$ORIGIN` must reach the linker literally — but it has to survive both make
# and the shell that make invokes. Make consumes `$$` → `$`. Shell consumes
# `\$` → `$`. So we need `\$$ORIGIN` in the Makefile, which is `\\$$ORIGIN`
# (Ruby string: backslash + dollar + dollar + ORIGIN). `@loader_path` on
# darwin has no `$` and needs no escaping.
rpath_origin = (host_platform.os == "darwin") ? "@loader_path" : "\\$$ORIGIN"
$LDFLAGS << " -Wl,-rpath,#{rpath_origin}/../vendor/libddwaf/#{File.basename(host_variant)}/lib"

# GCC on aarch64-linux silently *ignores* `__attribute__((naked))` on functions
# with a body — it emits a "naked attribute ignored" warning under [-Wattributes]
# but compiles successfully, then synthesises a regular prologue/epilogue around
# our inline asm. The assembler then rejects the resulting object because our
# `.byte` magic / type-byte data ends up at unaligned offsets in the executable
# segment. `-Werror=attributes` promotes the silent warning to a probe failure
# so we drop to the FFX fallback (plain wrapper, no ZJIT metadata) instead of
# producing a broken trampoline.
have_naked = checking_for("__attribute__((naked)) support") do
  try_compile(<<~C, "-Werror=attributes")
    __attribute__((naked, aligned(16)))
    static void probe(void) { __asm__("ret"); }
  C
end
$defs << "-DHAVE_NAKED_ATTRIBUTE" if have_naked

$CFLAGS << " -Wall -Wextra"

create_makefile("libddwaf_native")
