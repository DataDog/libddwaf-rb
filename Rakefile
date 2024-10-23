require 'bundler/gem_tasks'
require 'datadog/appsec/waf/version'
require 'rubocop/rake_task' if Gem.loaded_specs.key? 'rubocop'
require 'rspec/core/rake_task'
require 'yard'
require 'fileutils'

def system!(*args)
  puts "Run: #{args.join(' ')}"
  system(*args) || abort("\n== Command #{args} failed ==")
end

if defined?(RuboCop::RakeTask)
  RuboCop::RakeTask.new(:rubocop) do |t|
    t.options << ['-D', '--force-exclusion']
    t.patterns = ['lib/**/*.rb', 'spec/**/*.rb', 'Gemfile', 'Rakefile']
  end
end

YARD::Rake::YardocTask.new(:docs) do |t|
  t.options += ['--title', "datadog-instrumentation #{Datadog::AppSec::WAF::VERSION::STRING} documentation"]
  t.options += ['--markup', 'markdown']
  t.options += ['--markup-provider', 'redcarpet']
end

RSpec::Core::RakeTask.new(:spec) do |t, args|
  t.pattern = 'spec/**/*_spec.rb'
  t.rspec_opts = args.to_a.join(' ')
end

desc 'CI task; it runs all tests for current version of Ruby'
task :ci do
  system! 'bundle exec rake spec'
end

namespace :coverage do
  # Generates one global report for all tracer tests
  task :report do
    require 'simplecov'

    resultset_files = Dir["#{ENV.fetch('COVERAGE_DIR', 'coverage')}/.resultset.json"] +
                      Dir["#{ENV.fetch('COVERAGE_DIR', 'coverage')}/versions/**/.resultset.json"]

    SimpleCov.collate resultset_files do
      coverage_dir "#{ENV.fetch('COVERAGE_DIR', 'coverage')}/report"
      if ENV['CI'] == 'true'
        require 'codecov'
        formatter SimpleCov::Formatter::MultiFormatter.new([SimpleCov::Formatter::HTMLFormatter,
                                                            SimpleCov::Formatter::Codecov])
      else
        formatter SimpleCov::Formatter::HTMLFormatter
      end
    end
  end

  # Generates one report for each Ruby version
  task :report_per_ruby_version do
    require 'simplecov'

    versions = Dir["#{ENV.fetch('COVERAGE_DIR', 'coverage')}/versions/*"].map { |f| File.basename(f) }
    versions.map do |version|
      puts "Generating report for: #{version}"
      SimpleCov.collate Dir["#{ENV.fetch('COVERAGE_DIR', 'coverage')}/versions/#{version}/**/.resultset.json"] do
        coverage_dir "#{ENV.fetch('COVERAGE_DIR', 'coverage')}/report/versions/#{version}"
        formatter SimpleCov::Formatter::HTMLFormatter
      end
    end
  end
end

# TODO: Migrate images to Datadog Docker repo
RUBY_VERSIONS = {
  '2.1' => { version: '2.1', image: 'delner/ruby:2.1', service: 'ruby-2.1' },
  '2.2' => { version: '2.2', image: 'delner/ruby:2.2', service: 'ruby-2.2' },
  '2.3' => { version: '2.3', image: 'delner/ruby:2.3', service: 'ruby-2.3' },
  '2.4' => { version: '2.4', image: 'delner/ruby:2.4', service: 'ruby-2.4' },
  '2.5' => { version: '2.5', image: 'delner/ruby:2.5', service: 'ruby-2.5' },
  '2.6' => { version: '2.6', image: 'delner/ruby:2.6', service: 'ruby-2.6' },
  '2.7' => { version: '2.7', image: 'delner/ruby:2.7', service: 'ruby-2.7' },
  '3.0' => { version: '3.0', image: 'delner/ruby:3.0', service: 'ruby-3.0' },
  'jruby-9.2' => { version: 'jruby-9.2', image: 'delner/ruby:jruby-9.2', service: 'jruby-9.2' }
}.freeze

DEFAULT_RUBY_VERSION = RUBY_VERSIONS['2.7']

namespace :docker do
  task :build do
    RUBY_VERSIONS.each_value do |ruby|
      command = 'docker build'
      command += " -t #{ruby[:image]}"
      command += ' -t delner/ruby:latest' if ruby == DEFAULT_RUBY_VERSION
      command += " -f .docker/images/ruby/#{ruby[:version]}/Dockerfile"
      command += " .docker/images/ruby/#{ruby[:version]}"

      system!(command)
    end
  end

  task :push do
    RUBY_VERSIONS.each_value do |ruby|
      command = 'docker push'
      command += " #{ruby[:image]}"

      system!(command)
      system!('docker push delner/ruby:latest') if ruby == DEFAULT_RUBY_VERSION
    end
  end

  task :run do
    # Select Docker service to run
    ruby_version = RUBY_VERSIONS.find do |ver, ruby|
      ver == ENV['RUBY_VER'] \
        || ruby[:version] == ENV['RUBY_VER'] \
        || ruby[:service] == ENV['RUBY_VER']
    end || DEFAULT_RUBY_VERSION

    # Build and start Docker container
    system! "docker-compose build #{ruby_version[:service]}"
    system! "docker-compose run --rm #{ruby_version[:service]}"
  end
end

module Helpers
  require 'uri'
  require 'json'
  require 'net/http'
  require 'pathname'

  module_function

  def binary_gemspec(platform: Gem::Platform.local, str: RUBY_PLATFORM)
    platform.instance_eval { @version = 'musl' } if str =~ /-musl/ && platform.version.nil?

    gemspec = eval(File.read('libddwaf.gemspec')) # rubocop:disable Security/Eval
    gemspec.platform = platform
    gemspec
  end

  def libddwaf_version
    Datadog::AppSec::WAF::VERSION::BASE_STRING
  end

  def libddwaf_dir(platform:)
    libddwaf_vendor_dir.join(libddwaf_basename(platform: platform))
  end

  def libddwaf_vendor_dir
    Pathname.new('vendor/libddwaf')
  end

  def libddwaf_filename(platform:)
    "#{libddwaf_basename(platform: platform)}.tar.gz"
  end

  def libddwaf_binary_checksum(binary_name)
    checksums = File.readlines(libddwaf_checksums_path, chomp: true).map do |line|
      sha256, name = line.split(' ')
      [name, sha256]
    end

    checksums.to_h[binary_name]
  end

  def libddwaf_checksums_path
    Pathname.new('libddwaf-releases.sha256')
  end

  def shared_lib_path(platform:)
    ext = platform.os == 'darwin' ? 'dylib' : 'so'
    libddwaf_dir(platform: platform).join("lib/libddwaf.#{ext}")
  end

  def parse_platform(platform_string = nil)
    # use provided platform string, defaulting to the local platform
    # dup the local platform as we may side-effectfully patch the platform instance
    platform = platform_string ? Gem::Platform.new(platform_string) : Gem::Platform.local.dup

    if platform.os == 'darwin'
      # darwin has a single libddwaf build, strip any version passed
      platform.instance_eval { @version = nil }
    end

    if platform.os == 'linux' && platform.version.nil? && (platform_string || RUBY_PLATFORM) =~ /linux-(.+)$/
      # old rubygems cannot handle non-gnu libc in version
      # if a platform arg was not passed, platform is the local platform
      # use either platform string to set the version correctly
      platform.instance_eval { @version = $1 }
    end

    platform
  end

  def query_github_api(query)
    uri = URI.parse('https://api.github.com/graphql')
    headers = { 'Authorization' => "bearer #{github_token}", 'Content-Type' => 'application/json' }
    response = Net::HTTP.post(uri, { query: query, variables: '{}' }.to_json, headers)

    unless response.is_a?(Net::HTTPOK)
      fail Helpers.format(<<~TEXT)

          %red[ERROR:] Github API call was unsuccessful!
        %green[RESPONSE:] #{response.body}

      TEXT
    end

    response = JSON.parse(response.body)

    if response.key?('errors')
      errors = response['errors'].map.with_index do |error, index|
        next error['message'] if index.zero?

        error['message'].rjust(10 + error['message'].length, ' ')
      end

      fail Helpers.format(<<~TEXT)

           %red[ERROR:]    Github API call was unsuccessful!
        %yellow[RESPONSE:] #{errors.join("\n")}

      TEXT
    end

    response
  end

  def download(url)
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)

    unless response.is_a?(Net::HTTPOK)
      fail Helpers.format(<<~TEXT)

           %red[ERROR:] fail to download #{uri}
        %yellow[RESPONSE:] #{response.body}

      TEXT
    end

    response.body
  end

  def github_token
    token_path = File.expand_path('.github-token', __dir__)

    if !ENV.key?('GITHUB_TOKEN') && !File.exist?(token_path)
      fail Helpers.format(<<~TEXT)

        %red[ERROR:] Github token file %red[#{token_path}] not found!
               Please generate new token here %blue[https://github.com/settings/tokens/new]
        %yellow[NOTE:]  Token requires only %yellow[repo:public_repo] access with authorised SSO and should expire.
               See more %blue[https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-saml-single-sign-on/authorizing-a-personal-access-token-for-use-with-saml-single-sign-:console]

      TEXT
    end

    ENV.fetch('GITHUB_TOKEN') { File.read(token_path) }
  end

  def format(payload)
    coloring_regexp = /(?<match>%(?<color>red|green|yellow|blue)\[(?<content>(?:.+?|)\]*)\])/
    coloring_escape_codes = {
      'red' => "\033[0;31m%s\033[0m",
      'green' => "\033[0;32m%s\033[0m",
      'yellow' => "\033[0;33m%s\033[0m",
      'blue' => "\033[0;34m%s\033[0m",
    }

    payload = payload.dup
    matches = payload.scan(coloring_regexp)
    matches.each do |(match, color, content)|
      formatter = coloring_escape_codes.fetch(color) { raise Error, "unknown color `#{color}`" }
      payload[match] = Kernel.format(formatter, content)
    end

    payload
  end

  # private

  def shared_lib_triplet(platform:)
    platform.version ? "#{platform.os}-#{platform.version}-#{platform.cpu}" : "#{platform.os}-#{platform.cpu}"
  end

  def libddwaf_basename(platform:)
    "libddwaf-#{libddwaf_version}-#{shared_lib_triplet(platform: platform)}"
  end
end

namespace :libddwaf do
  desc 'Download last 100 `libddwaf` releases checksums into a single checksum file'
  task :download_checksums do
    Helpers.github_token

    releases_path = Pathname.new('tmp/releases')
    FileUtils.mkdir_p(releases_path)

    response = Helpers.query_github_api(<<~QUERY)
      query {
        repository(name: "libddwaf", owner: "DataDog") {
          releases(last: 100) {
            nodes {
              releaseAssets(last: 100) {
                nodes {
                  url
                  name
                }
              }
            }
          }
        }
      }
    QUERY

    response.dig('data', 'repository', 'releases', 'nodes').each do |release|
      release.dig('releaseAssets', 'nodes').each do |asset|
        next unless asset['name'].match?(/\Alibddwaf-[\d.]+-(?:linux|darwin)-(?:arm64|x86_64|aarch64)\.tar\.gz\.sha256\z/)

        sha256_path = releases_path.join(asset['name'])
        next puts Helpers.format("%yellow[SKIP]     #{asset['name']} (exist)") if sha256_path.size?

        puts Helpers.format("%blue[DOWNLOAD] #{asset['name']}")

        binary = Helpers.download(asset['url'])
        File.open(sha256_path, 'wb') { |file| file.write(binary) }
      end
    end

    checksums_path = Helpers.libddwaf_checksums_path
    File.open(checksums_path, 'wb') do |file|
      # NOTE: To sort releases descending in the checksum file we will need to
      #       sort them in a consistent way. We turn version into the number,
      #       group files by the version and additionally sort files within same
      #       version.
      versions = Dir[releases_path.join('*.sha256')].each_with_object({}) do |file, memo|
        version = file.match(/libddwaf-([\d.]+)-/)[1].tr('.', '').to_i

        memo[version] ||= []
        memo[version].push(file)
      end

      versions.each_value(&:sort!).sort.reverse.flat_map { |_, values| values }.each do |sha256_path|
        file.write(File.read(sha256_path))
      end
    end

    puts Helpers.format("%green[COMPLETE] #{checksums_path}")
  end

  desc 'Extract pre-packaged `libddwaf` tarball into shared libs'
  task :extract, [:platform] do |_, args|
    platform = Helpers.parse_platform(args.to_h[:platform])

    if Helpers.shared_lib_path(platform: platform).exist?
      path = Helpers.shared_lib_path(platform: platform)
      next puts Helpers.format("%yellow[SKIP]     #{path} (exist)")
    end

    Rake::Task['fetch'].execute(args)

    require 'rubygems/package'

    vendor_dir = Helpers.libddwaf_vendor_dir
    binary_name = Helpers.libddwaf_filename(platform: platform)
    binary_path = vendor_dir.join(binary_name)

    puts Helpers.format("%blue[EXTRACT]  #{binary_name}")

    File.open(binary_path, 'rb') do |file|
      FileUtils.rm_rf(Helpers.libddwaf_dir(platform: platform))
      Gem::Package.new('').extract_tar_gz(file, vendor_dir)
    end

    puts Helpers.format("%green[COMPLETE] #{Helpers.libddwaf_dir(platform: platform)}")
  end

  desc 'Download pre-packaged `libddwaf` tarball into shared libs'
  task :fetch, [:platform] do |_, args|
    platform = Helpers.parse_platform(args.to_h[:platform])

    # NOTE: Check Github Token upfront to fail-fast
    Helpers.github_token

    version = Helpers.libddwaf_version
    vendor_dir = Helpers.libddwaf_vendor_dir

    binary_name = Helpers.libddwaf_filename(platform: platform)
    binary_path = vendor_dir.join(binary_name)
    expected_binary_sha256 = Helpers.libddwaf_binary_checksum(binary_name)

    if expected_binary_sha256.nil?
      fail Helpers.format(<<~TEXT)

        %red[ERROR:] Could not find checksum for %red[#{binary_name}]
               Please run `%yellow[rake libddwaf:download_checksums]` to update the list

      TEXT
    end

    if binary_path.exist? && Digest::SHA256.hexdigest(File.read(binary_path)) == expected_binary_sha256
      next puts Helpers.format("%yellow[SKIP]     #{binary_name} (exists)")
    end

    response = Helpers.query_github_api(<<~QUERY)
      query {
        repository(name: "libddwaf", owner: "DataDog") {
          release(tagName: "#{version}") {
            releaseAssets(first: 1, name: "#{binary_name}") {
              nodes { url }
            }
          }
        }
      }
    QUERY

    puts Helpers.format("%blue[DOWNLOAD] #{binary_name}")

    url = response.dig('data', 'repository', 'release', 'releaseAssets', 'nodes', 0, 'url')
    if url.nil?
      fail Helpers.format(<<~TEXT)

        %red[ERROR:] possibly wrong libddwaf version `%yellow[#{version}]` or binary name `%yellow[#{binary_name}]`

      TEXT
    end

    binary = Helpers.download(url)
    binary_sha256 = Digest::SHA256.hexdigest(binary)

    if binary_sha256 != expected_binary_sha256
      fail Helpers.format(<<~TEXT)

           %red[ERROR:]    fail to verify checksum of %blue[#{url}]
        %green[EXPECTED:] #{binary_sha256}
          %red[ACTUAL:] #{expected_binary_sha256}

      TEXT
    end

    FileUtils.mkdir_p(vendor_dir)
    File.open(binary_path, 'wb') { |file| file.write(binary) }

    puts Helpers.format("%green[COMPLETE] #{binary_path}")
  end
end

# NOTE: Left for compatibility and should be removed after pipelines are migrated
task(:fetch, [:platform]) { |_, args| Rake::Task['libddwaf:fetch'].execute(args) }
task(:extract, [:platform]) { |_, args| Rake::Task['libddwaf:extract'].execute(args) }

desc 'Build `libddwaf` gem binary'
task :binary, [:platform] => [] do |_, args|
  subplatform_for = {
    # lean gems
    'x86_64-linux-gnu'       => ['x86_64-linux'],
    'x86_64-linux-musl'      => ['x86_64-linux-musl'],
    'aarch64-linux-gnu'      => ['aarch64-linux'],
    'aarch64-linux-musl'     => ['aarch64-linux-musl'],
    'x86_64-darwin'          => ['x86_64-darwin'],
    'arm64-darwin'           => ['arm64-darwin'],

    # portable gems
    'x86_64-linux:llvm'      => ['x86_64-linux'],
    'aarch64-linux:llvm'     => ['aarch64-linux'],

    # fat gems
    'x86_64-linux:gnu+musl' => [
      'x86_64-linux',
      'x86_64-linux-musl',
    ],
    'aarch64-linux:gnu+musl' => [
      'aarch64-linux',
      'aarch64-linux-musl',
    ],
    'java' => [
      'x86_64-linux',
      'aarch64-linux',
      'x86_64-darwin',
      'arm64-darwin',
    ],
  }

  # alias default portable build
  subplatform_for['x86_64-linux']  = subplatform_for['x86_64-linux:llvm']
  subplatform_for['aarch64-linux'] = subplatform_for['aarch64-linux:llvm']

  # preprocess argument
  platform_arg = args.to_h[:platform]
  if platform_arg.nil?
    platform_arg = if RUBY_PLATFORM =~ /-linux$/
                     # no arg + -linux$ should build linux-gnu only
                     RUBY_PLATFORM + '-gnu'
                   elsif RUBY_PLATFORM =~ /^(.+-darwin)/
                     # no arg + darwin should build darwin$
                     $1
                   elsif RUBY_PLATFORM =~ /-linux-musl$/
                     # no arg + -linux-musl$ should build linux-musl on old rubygems
                     RUBY_PLATFORM
                   else
                     RUBY_PLATFORM
                   end
  end

  platform_string, _opts = platform_arg.split(':')
  platform = Helpers.parse_platform(platform_string)

  subplatforms = subplatform_for[platform_arg]

  if subplatforms.nil?
    fail "target platform not found: #{platform_arg.inspect}"
  end

  # loop for multiple deps on a single target, accumulating each shared lib path
  shared_lib_paths = subplatforms.map do |subplatform_string|
    subplatform = Helpers.parse_platform(subplatform_string)

    Rake::Task['extract'].execute(Rake::TaskArguments.new([:platform], [subplatform]))

    Helpers.shared_lib_path(platform: subplatform).to_s
  end

  gemspec = Helpers.binary_gemspec(platform: platform)
  gemspec.extensions.clear

  gemspec.files = []
  gemspec.files += Dir['lib/**/*.rb']
  gemspec.files += ['NOTICE', 'CHANGELOG.md'] + Dir['LICENSE*']

  gemspec.files += shared_lib_paths

  FileUtils.chmod(0o0644, gemspec.files)
  FileUtils.mkdir_p('pkg')

  puts Helpers.format("%blue[BUILD]    libddwaf-#{gemspec.version}-#{gemspec.platform}")

  package = if Gem::VERSION < '2.0.0'
              Gem::Builder.new(gemspec).build
            else
              require 'rubygems/package'
              Gem::Package.build(gemspec)
            end

  FileUtils.mv(package, 'pkg')

  puts Helpers.format("%green[COMPLETE] pkg/#{package}")
end

task test: :spec

namespace :steep do
  task :check do
    require 'open3'

    stdout, status = Open3.capture2('bundle exec steep check')
    puts stdout

    ignore_rules = File.readlines('.steepignore', chomp: true)
    unexpected_errors = []
    error_lines = stdout.lines.select { |line| line.include?('[error]') }
    error_lines.each do |line|
      location, error = line.split(': [error]').map(&:strip)

      should_ignore = ignore_rules.any? do |ignore_rule|
        ignored_loc, ignored_error = ignore_rule.scan(/(.+)\s+"(.+)"/).first
        location.end_with?(ignored_loc) && error.include?(ignored_error)
      end

      unexpected_errors << [location, error] unless should_ignore
    end

    if unexpected_errors.any?
      puts 'Unexpected problems found:'
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

task default: 'spec'
