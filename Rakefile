require "bundler/gem_tasks"
require "datadog/appsec/waf/version"
require "rspec/core/rake_task"
require "yard"
require "fileutils"

def system!(*args)
  puts "Run: #{args.join(" ")}"
  system(*args) || abort("\n== Command #{args} failed ==")
end

YARD::Rake::YardocTask.new(:docs) do |t|
  t.options += ["--title", "datadog-instrumentation #{Datadog::AppSec::WAF::VERSION::STRING} documentation"]
  t.options += ["--markup", "markdown"]
  t.options += ["--markup-provider", "redcarpet"]
end

RSpec::Core::RakeTask.new(:spec) do |t, args|
  t.pattern = "spec/**/*_spec.rb"
  t.rspec_opts = args.to_a.join(" ")
end

module Helpers
  require "uri"
  require "json"
  require "net/http"
  require "pathname"

  module_function

  def binary_gemspec(platform: Gem::Platform.local, str: RUBY_PLATFORM)
    platform.instance_eval { @version = "musl" } if str =~ /-musl/ && platform.version.nil?

    gemspec = eval(File.read("libddwaf.gemspec")) # standard:disable Security/Eval
    gemspec.platform = platform
    gemspec
  end

  def libddwaf_version
    Datadog::AppSec::WAF::VERSION::BASE_STRING
  end

  def libddwaf_vendor_dir
    Pathname.new("vendor/libddwaf")
  end

  def libddwaf_tarball_filename(platform:)
    platform = if Gem::Version.new(libddwaf_version) >= Gem::Version.new("1.16.0") && platform.os == "linux"
      [platform.cpu, platform.os, "musl"].compact.join("-")
    else
      [platform.os, platform.version, platform.cpu].compact.join("-")
    end

    "libddwaf-#{libddwaf_version}-#{platform}.tar.gz"
  end

  def libddwaf_library_path(platform:)
    folder_name = "libddwaf-#{libddwaf_version}-#{[platform.os, platform.version, platform.cpu].compact.join("-")}"
    extension = (platform.os == "darwin") ? "dylib" : "so"

    # unfortunately archive name does not match extracted folder name for linux since libddwaf v1.16.0.
    libddwaf_vendor_dir.join(folder_name, "lib/libddwaf.#{extension}")
  end

  def parse_platform(platform_string = nil)
    local_platform = Gem::Platform.local

    # use provided platform string, defaulting to the local platform
    # dup the local platform as we may side-effectfully patch the platform instance
    platform = platform_string ? Gem::Platform.new(platform_string) : local_platform.dup

    if platform.os == "darwin"
      # darwin has a single libddwaf build, strip any version passed
      platform.instance_eval { @version = nil }
    end

    if platform.os == "linux" && platform.version.nil? && (platform_string || RUBY_PLATFORM) =~ /linux-(.+)$/
      # old rubygems cannot handle non-gnu libc in version
      # if a platform arg was not passed, platform is the local platform
      # use either platform string to set the version correctly
      platform.instance_eval { @version = ::Regexp.last_match(1) }
    end

    platform
  end

  def release_url(kind, binary_name:, version:)
    unless %i[binary checksum].include?(kind)
      raise Helpers.format("\n   %red[error] unknown release asset kind #{kind.inspect}\n\n")
    end

    url = "https://github.com/DataDog/libddwaf/releases/download/%<version>s/%<filename>s"
    url += ".sha256" if kind == :checksum

    Kernel.format(url, version: version, filename: binary_name)
  end

  def query_github_api(query)
    uri = URI.parse("https://api.github.com/graphql")
    headers = {"Authorization" => "bearer #{github_token}", "Content-Type" => "application/json"}
    response = Net::HTTP.post(uri, {query: query, variables: "{}"}.to_json, headers)

    unless response.is_a?(Net::HTTPOK)
      raise Helpers.format(<<~TEXT)

           %red[error] Github API call was unsuccessful!
        %yellow[response] #{response.body}

      TEXT
    end

    response = JSON.parse(response.body)

    if response.key?("errors")
      errors = response["errors"].map.with_index do |error, index|
        next error["message"] if index.zero?

        error["message"].rjust(10 + error["message"].length, " ")
      end

      raise Helpers.format(<<~TEXT)

           %red[error] Github API call was unsuccessful!
        %yellow[response] #{errors.join("\n")}

      TEXT
    end

    response
  end

  def download(url, redirects_allowed: 3)
    raise Helpers.format("\n   %red[error] exeeded maximum redirects count\n\n") if redirects_allowed.zero?

    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)

    case response
    when Net::HTTPFound then Helpers.download(response["Location"], redirects_allowed: redirects_allowed - 1)
    when Net::HTTPOK then response.body
    else
      raise Helpers.format(<<~TEXT)

           %red[error] fail to download #{uri}
        %yellow[response] #{response.body}

      TEXT
    end
  end

  def github_token
    token_path = File.expand_path(".github-token", __dir__)

    if !ENV.key?("GITHUB_TOKEN") && !File.exist?(token_path)
      raise Helpers.format(
        "\n   %red[error] Github token file %red[#{token_path}] not found!\n" \
        "         Please generate new token here %blue[https://github.com/settings/tokens/new]\n" \
        "   %yellow[NOTE:] Token requires only %yellow[repo:public_repo] access with authorised SSO and should expire.\n" \
        "         See more %blue[https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-saml-single-sign-on/authorizing-a-personal-access-token-for-use-with-saml-single-sign-:console]\n\n"
      )
    end

    ENV.fetch("GITHUB_TOKEN") { File.read(token_path) }
  end

  def format(payload)
    coloring_regexp = /(?<match>%(?<color>red|green|yellow|blue)\[(?<content>(?:.+?|)\]*)\])/
    coloring_escape_codes = {
      "red" => "\033[0;31m%s\033[0m",
      "green" => "\033[0;32m%s\033[0m",
      "yellow" => "\033[0;33m%s\033[0m",
      "blue" => "\033[0;34m%s\033[0m"
    }

    payload = payload.dup
    matches = payload.scan(coloring_regexp)
    matches.each do |(match, color, content)|
      formatter = coloring_escape_codes.fetch(color) { raise Error, "unknown color `#{color}`" }
      payload[match] = Kernel.format(formatter, content)
    end

    payload
  end
end

namespace :spec do
  RSpec::Core::RakeTask.new(:stress_tests) do |t, _args|
    t.pattern = "spec/**/*_spec.rb"
    t.rspec_opts = "--tag stress_tests"
  end

  namespace :memory_leaks do
    desc "Run all tests for memory leaks"
    RSpec::Core::RakeTask.new(:all) do |t, _args|
      t.rspec_opts = "--tag memory_leaks"
    end

    Dir.glob("spec/memory_leaks/*").select { |dir| File.directory?(dir) }.map { |dir| dir.sub("spec/memory_leaks/", "") }.each do |subdir|
      desc "Run #{subdir} related tests for memory leaks"
      RSpec::Core::RakeTask.new(subdir) do |t, _args|
        t.rspec_opts = "--tag memory_leaks --example_matches /#{subdir}/"
      end
    end
  end
end

namespace :coverage do
  # Generates one global report for all tracer tests
  task :report do
    require "simplecov"

    resultset_files = Dir["#{ENV.fetch("COVERAGE_DIR", "coverage")}/.resultset.json"] +
      Dir["#{ENV.fetch("COVERAGE_DIR", "coverage")}/versions/**/.resultset.json"]

    SimpleCov.collate resultset_files do
      coverage_dir "#{ENV.fetch("COVERAGE_DIR", "coverage")}/report"
      if ENV["CI"] == "true"
        require "codecov"
        formatter SimpleCov::Formatter::MultiFormatter.new([SimpleCov::Formatter::HTMLFormatter,
          SimpleCov::Formatter::Codecov])
      else
        formatter SimpleCov::Formatter::HTMLFormatter
      end
    end
  end

  # Generates one report for each Ruby version
  task :report_per_ruby_version do
    require "simplecov"

    versions = Dir["#{ENV.fetch("COVERAGE_DIR", "coverage")}/versions/*"].map { |f| File.basename(f) }
    versions.map do |version|
      puts "Generating report for: #{version}"
      SimpleCov.collate Dir["#{ENV.fetch("COVERAGE_DIR", "coverage")}/versions/#{version}/**/.resultset.json"] do
        coverage_dir "#{ENV.fetch("COVERAGE_DIR", "coverage")}/report/versions/#{version}"
        formatter SimpleCov::Formatter::HTMLFormatter
      end
    end
  end
end

namespace :steep do
  task :check do
    require "open3"

    stdout, status = Open3.capture2("bundle exec steep check")
    puts stdout

    ignore_rules = File.readlines(".steepignore", chomp: true)
    unexpected_errors = []
    error_lines = stdout.lines.select { |line| line.include?("[error]") }
    error_lines.each do |line|
      location, error = line.split(": [error]").map(&:strip)

      should_ignore = ignore_rules.any? do |ignore_rule|
        ignored_loc, ignored_error = ignore_rule.scan(/(.+)\s+"(.+)"/).first
        location.end_with?(ignored_loc) && error.include?(ignored_error)
      end

      unexpected_errors << [location, error] unless should_ignore
    end

    if unexpected_errors.any?
      puts "Unexpected problems found:"
      puts(unexpected_errors.map { |location, error| "#{location}: #{error}" })
      exit status.exitstatus
    else
      puts
      puts "Ignored #{error_lines.size} problems according to .steepignore."
      puts <<~MSG
        Gem ffi v1.17.0 was shipped with incorrect RBS types and is causing Steep to fail.
        https://github.com/ffi/ffi/issues/1107
      MSG
      exit 0
    end
  end
end

namespace :libddwaf do
  desc "Extract pre-packaged `libddwaf` tarball into shared libs"
  task :extract, [:platform] do |_, args|
    platform = Helpers.parse_platform(args.to_h[:platform])

    if Helpers.libddwaf_library_path(platform: platform).exist?
      path = Helpers.libddwaf_library_path(platform: platform)
      next puts Helpers.format("    %yellow[skip] #{path} (exist)")
    end

    Rake::Task["libddwaf:fetch"].execute(args)

    require "rubygems/package"

    vendor_dir = Helpers.libddwaf_vendor_dir
    binary_name = Helpers.libddwaf_tarball_filename(platform: platform)
    binary_path = vendor_dir.join(binary_name)

    puts Helpers.format(" %blue[extract]  #{binary_name}")

    File.open(binary_path, "rb") do |file|
      FileUtils.rm_rf(Helpers.libddwaf_library_path(platform: platform))
      Gem::Package.new("").extract_tar_gz(file, vendor_dir)
    end

    puts Helpers.format("%green[complete] #{Helpers.libddwaf_library_path(platform: platform)}")
  end

  desc "Download pre-packaged `libddwaf` tarball into shared libs"
  task :fetch, [:platform] do |_, args|
    platform = Helpers.parse_platform(args.to_h[:platform])

    version = Helpers.libddwaf_version
    vendor_dir = Helpers.libddwaf_vendor_dir

    binary_name = Helpers.libddwaf_tarball_filename(platform: platform)
    binary_path = vendor_dir.join(binary_name)

    checksum_url = Helpers.release_url(:checksum, binary_name: binary_name, version: version)
    expected_binary_sha256 = Helpers.download(checksum_url).split(" ", 2)[0]

    if expected_binary_sha256.nil?
      raise Helpers.format(
        "\n   %red[error] Could not find checksum for %red[#{binary_name}]" \
        "\n         Please check https://github.com/DataDog/libddwaf/releases page.\n\n"
      )
    end

    if binary_path.exist? && Digest::SHA256.hexdigest(File.read(binary_path)) == expected_binary_sha256
      next puts Helpers.format("    %yellow[skip] #{binary_name} (exists)")
    end

    puts Helpers.format("%blue[download] #{binary_name}")

    release_url = Helpers.release_url(:binary, binary_name: binary_name, version: version)
    binary = Helpers.download(release_url)
    binary_sha256 = Digest::SHA256.hexdigest(binary)

    if binary_sha256 != expected_binary_sha256
      raise Helpers.format(<<~TEXT)

           %red[error] fail to verify checksum of %blue[#{release_url}]
        %green[expected] #{binary_sha256}
          %yellow[actual] #{expected_binary_sha256}

      TEXT
    end

    FileUtils.mkdir_p(vendor_dir)
    File.binwrite(binary_path, binary)

    puts Helpers.format("%green[complete] #{binary_path}")
  end

  desc "Download and extract pre-packaged `libddwaf` binary"
  task :binary, [:platform] do |_, args|
    subplatform_for = {
      # lean gems
      "x86_64-linux-gnu" => ["x86_64-linux"],
      "x86_64-linux-musl" => ["x86_64-linux"],
      "aarch64-linux-gnu" => ["aarch64-linux"],
      "aarch64-linux-musl" => ["aarch64-linux"],
      "x86_64-darwin" => ["x86_64-darwin"],
      "arm64-darwin" => ["arm64-darwin"],

      # portable gems
      "x86_64-linux:llvm" => ["x86_64-linux"],
      "aarch64-linux:llvm" => ["aarch64-linux"],

      # fat gems
      "x86_64-linux:gnu+musl" => %w[
        x86_64-linux
        x86_64-linux-musl
      ],
      "aarch64-linux:gnu+musl" => %w[
        aarch64-linux
        aarch64-linux-musl
      ],
      "java" => %w[
        x86_64-linux
        aarch64-linux
        x86_64-darwin
        arm64-darwin
      ]
    }

    # alias default portable build
    subplatform_for["x86_64-linux"] = subplatform_for["x86_64-linux:llvm"]
    subplatform_for["aarch64-linux"] = subplatform_for["aarch64-linux:llvm"]

    # preprocess argument
    platform_arg = args.to_h[:platform]
    if platform_arg.nil?
      platform_arg = if RUBY_PLATFORM.match?(/-linux$/)
        # no arg + -linux$ should build linux-gnu only
        RUBY_PLATFORM + "-gnu"
      elsif RUBY_PLATFORM =~ /^(.+-darwin)/
        # no arg + darwin should build darwin$
        Regexp.last_match(1)
      elsif RUBY_PLATFORM.match?(/-linux-musl$/)
        # no arg + -linux-musl$ should build linux-musl on old rubygems
        RUBY_PLATFORM
      else
        RUBY_PLATFORM
      end
    end

    subplatforms = subplatform_for[platform_arg]
    raise "target platform not found: #{platform_arg.inspect}" if subplatforms.nil?

    # loop for multiple deps on a single target, accumulating each shared lib path
    subplatforms.each do |subplatform_string|
      subplatform = Helpers.parse_platform(subplatform_string)

      Rake::Task["libddwaf:extract"].execute(Rake::TaskArguments.new([:platform], [subplatform]))
    end
  end

  desc "Release bundled gem with all supported platforms"
  task :release do
    platforms = [
      "x86_64-linux",
      "x86_64-darwin",
      "arm64-darwin",
      "aarch64-linux",
    ]

    platforms.each { |platform| Rake::Task["libddwaf:build"].execute(platform: platform) }
    Rake::Task["build"].invoke

    Rake::Task["release"].invoke
    platforms.each { |platform| Rake::Task["libddwaf:push"].execute(platform: platform) }
  end

  task :build, [:platform] do |_, args|
    Rake::Task["libddwaf:binary"].execute(args)

    platform_arg = args.to_h[:platform]
    platform_arg ||= if RUBY_PLATFORM.match?(/-linux$/)
      # no arg + -linux$ should build linux-gnu only
      RUBY_PLATFORM + '-gnu'
    elsif RUBY_PLATFORM =~ /^(.+-darwin)/
      # no arg + darwin should build darwin$
      $1
    elsif RUBY_PLATFORM.match?(/-linux-musl$/)
      # no arg + -linux-musl$ should build linux-musl on old rubygems
      RUBY_PLATFORM
    else
      RUBY_PLATFORM
    end

    platform_string, _opts = platform_arg.split(':')
    platform = Helpers.parse_platform(platform_string)

    vendor_dir = Helpers.libddwaf_vendor_dir.to_s
    platform_binary = Helpers.libddwaf_library_path(platform: platform).to_s

    gemspec = Helpers.binary_gemspec(platform: platform)
    gemspec.files.reject! do |file|
      file.start_with?(vendor_dir) && file != platform_binary
    end

    FileUtils.chmod(0o0644, gemspec.files)
    FileUtils.mkdir_p('pkg')

    puts Helpers.format("   %blue[build] libddwaf-#{gemspec.version}-#{gemspec.platform}")

    package = if Gem::VERSION < '2.0.0'
      Gem::Builder.new(gemspec).build
    else
      require 'rubygems/package'
      Gem::Package.build(gemspec)
    end

    FileUtils.mv(package, 'pkg')
    puts Helpers.format("%green[libddwaf #{Helpers.libddwaf_version} built to pkg/#{package}.]")
  end

  # NOTE: This is used in CI only
  task :buildx do
    platforms = [
      "x86_64-linux",
      "x86_64-darwin",
      "arm64-darwin",
      "aarch64-linux",
    ]

    platforms.each { |platform| Rake::Task["libddwaf:binary"].execute(platform: platform) }
    Rake::Task["build"].invoke
  end

  task :push, [:platform] do |_, args|
    gem_path = "pkg/#{Helpers.binary_gemspec(platform: args[:platform]).file_name}"
    Kernel.system("gem push #{gem_path}", exception: true)
  end
end

task test: :spec
task default: :spec
