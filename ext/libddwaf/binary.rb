require "fileutils"
require "rubygems/package"
require "net/http"
require "uri"
require "digest"

module LibDDWAFBinary
  RELEASE_BASE_URL = "https://github.com/DataDog/libddwaf/releases/download"

  class << self
    def vendor_dir
      File.expand_path("../../vendor/libddwaf", __dir__)
    end

    def variant_dir_name(platform, version)
      "libddwaf-#{version}-#{[platform.os, platform.version, platform.cpu].compact.join("-")}"
    end

    def variant_dir(platform, version)
      File.join(vendor_dir, variant_dir_name(platform, version))
    end

    def header_path(platform, version)
      File.join(variant_dir(platform, version), "include", "ddwaf.h")
    end

    def shared_lib_path(platform, version)
      File.join(variant_dir(platform, version), "lib", "libddwaf.#{shared_ext(platform)}")
    end

    def tarball_path(platform, version)
      File.join(vendor_dir, tarball_filename(platform, version))
    end

    # Gem-relative paths matching the entries in `spec.files` of `libddwaf.gemspec`.
    # Used by the `libddwaf:build` rake task to filter the file list down to
    # the target platform when packaging a platform-specific gem.
    def gem_relative_lib_path(platform, version)
      "vendor/libddwaf/#{variant_dir_name(platform, version)}/lib/libddwaf.#{shared_ext(platform)}"
    end

    def gem_relative_header_path(platform, version)
      "vendor/libddwaf/#{variant_dir_name(platform, version)}/include/ddwaf.h"
    end

    def fetch_tarball(platform:, version:)
      FileUtils.mkdir_p(vendor_dir)

      filename = tarball_filename(platform, version)
      path = File.join(vendor_dir, filename)

      expected_sha = http_get(release_url(version, filename, kind: :checksum)).strip.split(/\s+/).first
      raise "missing checksum for #{filename}" if expected_sha.nil? || expected_sha.empty?
      return path if File.exist?(path) && Digest::SHA256.hexdigest(File.binread(path)) == expected_sha

      log "downloading #{filename}"
      body = http_get(release_url(version, filename))
      actual_sha = Digest::SHA256.hexdigest(body)
      raise "checksum mismatch for #{filename}: expected #{expected_sha}, got #{actual_sha}" if actual_sha != expected_sha

      File.binwrite(path, body)
      path
    end

    def ensure_present(platform:, version:)
      lib = shared_lib_path(platform, version)
      header = header_path(platform, version)
      return variant_dir(platform, version) if File.exist?(lib) && File.exist?(header)

      extract_tarball(platform: platform, version: version)
    end

    private

    # Public-by-association: also called from gem_relative_lib_path above.
    # Kept private because external callers should compose via the public
    # path methods, not poke this directly.
    def shared_ext(platform)
      (platform.os == "darwin") ? "dylib" : "so"
    end

    def tarball_filename(platform, version)
      modern_linux = Gem::Version.new(version) >= Gem::Version.new("1.16.0") && platform.os == "linux"
      parts = modern_linux ? [platform.cpu, platform.os, "musl"] : [platform.os, platform.version, platform.cpu]
      "libddwaf-#{version}-#{parts.compact.join("-")}"
    end

    def release_url(version, filename, kind: :binary)
      base = "#{RELEASE_BASE_URL}/#{version}/#{filename}"
      (kind == :checksum) ? "#{base}.sha256" : base
    end

    def extract_tarball(platform:, version:)
      path = fetch_tarball(platform: platform, version: version)
      target = variant_dir(platform, version)

      log "extracting #{File.basename(path)}"
      FileUtils.rm_rf(target)
      File.open(path, "rb") { |f| Gem::Package.new("").extract_tar_gz(f, vendor_dir) }

      target
    end

    def http_get(url, redirects_left: 5)
      raise "too many redirects fetching #{url}" if redirects_left.negative?

      response = Net::HTTP.get_response(URI.parse(url))
      return response.body if response.is_a?(Net::HTTPSuccess)
      return http_get(response["location"] || response["Location"], redirects_left: redirects_left - 1) if response.is_a?(Net::HTTPRedirection)

      raise "HTTP #{response.code} fetching #{url}: #{response.body.to_s[0, 200]}"
    end

    def log(msg)
      $stderr.puts "[libddwaf] #{msg}"
    end
  end
end
