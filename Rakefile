require 'bundler/gem_tasks'
require 'datadog/security/waf/version'
require 'rubocop/rake_task' if Gem.loaded_specs.key? 'rubocop'
require 'rspec/core/rake_task'
require 'yard'

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
  t.options += ['--title', "datadog-instrumentation #{Datadog::Security::WAF::VERSION::STRING} documentation"]
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
    RUBY_VERSIONS.each do |_name, ruby|
      command = 'docker build'
      command += " -t #{ruby[:image]}"
      command += ' -t delner/ruby:latest' if ruby == DEFAULT_RUBY_VERSION
      command += " -f .docker/images/ruby/#{ruby[:version]}/Dockerfile"
      command += " .docker/images/ruby/#{ruby[:version]}"

      system!(command)
    end
  end

  task :push do
    RUBY_VERSIONS.each do |_name, ruby|
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
  def self.gemspec
    eval(File.read('libddwaf.gemspec')) # rubocop:disable Security/Eval
  end

  def self.binary_gemspec(platform: Gem::Platform.local, str: RUBY_PLATFORM)
    platform.instance_eval { @version = 'musl' } if str =~ /-musl/ && platform.version.nil?

    spec = gemspec
    spec.platform = platform
    spec
  end

  def self.binary_gem_name(platform = Gem::Platform.local)
    File.basename(binary_gemspec(platform).cache_file)
  end

  def self.local_os
    Gem::Platform.local.os
  end

  def self.local_cpu
    Gem::Platform.local.cpu
  end

  def self.os(platform:)
    platform.os
  end

  def self.cpu(platform:)
    platform.cpu
  end

  def self.vendor_dir
    'vendor'
  end

  def self.libddwaf_vendor_dir
    File.join(vendor_dir, 'libddwaf')
  end

  def self.libddwaf_dir(platform:)
    File.join(libddwaf_vendor_dir, "libddwaf-#{Datadog::Security::WAF::VERSION::BASE_STRING}-#{os(platform: platform)}-#{cpu(platform: platform)}")
  end

  def self.shared_lib_extname(platform:)
    platform.os == 'darwin' ? '.dylib' : '.so'
  end

  def self.shared_lib_path(platform:)
    File.join(libddwaf_dir(platform: platform), "lib/libddwaf#{shared_lib_extname(platform: platform)}")
  end
end

task :fetch, [:platform] => [] do |_, args|
  platform = args.to_h[:platform] ? Gem::Platform.new(args.to_h[:platform]) : Gem::Platform.local.dup

  require 'net/http'
  require 'fileutils'

  dirname = 'vendor/libddwaf'

  version = Datadog::Security::WAF::VERSION::BASE_STRING
  os = platform.os
  cpu = platform.cpu
  extname = '.tar.gz'
  filename_base = 'libddwaf-%<version>s-%<os>s-%<cpu>s%<extname>s'
  uri_base = 'https://github.com/DataDog/libddwaf/releases/download/%<version>s/%<filename>s'

  sha256_filename = {
    'libddwaf-1.0.11-darwin-x86_64.tar.gz'  => '0f046ccc789e1ddf06923ac09c0eabd68e0e45a6ab51d0bb7171b583034871ad',
    'libddwaf-1.0.11-darwin-arm64.tar.gz'   => '03f1edc01a18379b7ec6c967225a50224c5cc463b5982d64aad9f68c2c1e6823',
    'libddwaf-1.0.11-linux-x86_64.tar.gz'   => 'd1a3e49c96c272620b0c5f82f9fa68fcfa871dddf2a38f9d3af374e742a1e0c0',
    'libddwaf-1.0.11-linux-aarch64.tar.gz'  => 'af21751b2f53b3ddbaecdacda281e585642448702edc100a47b972f4939137b5',
    'libddwaf-1.0.12-darwin-x86_64.tar.gz'  => '2a809bf7dcf3f5d86409f0b18f8ec9f8e6c9a4a913f321bb68d65abad280170d',
    'libddwaf-1.0.12-darwin-arm64.tar.gz'   => 'e1a40846db2ce0e99b21198ff5edb239ed8e2d4857e8e42fffb3c8e574bd6ece',
    'libddwaf-1.0.12-linux-x86_64.tar.gz'   => '1b5ba745b6b1c19261844d33c60c9dbea5f4303e27b1a03ad2e855e83491d70c',
    'libddwaf-1.0.12-linux-aarch64.tar.gz'  => 'a1f4a5022bbcafa4d31de31be7789d00b81b361377d0f62f419873122d8be228',
  }

  filename = format(filename_base, version: version, os: os, cpu: cpu, extname: extname)
  filepath = File.join(dirname, filename)
  sha256 = sha256_filename[filename]

  if sha256.nil?
    fail 'unsupported platform: #{filename}'
  end

  if File.exist?(filepath) && Digest::SHA256.hexdigest(File.read(filepath)) == sha256
    next
  end

  uri = URI(format(uri_base, version: version, filename: filename))

  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    puts "fetch #{uri}"
    req = Net::HTTP::Get.new(uri)
    res = http.request(req)
    case res
    when Net::HTTPFound
      uri = URI(res['Location'])
      Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        puts "fetch #{uri}"
        req = Net::HTTP::Get.new(uri)
        res = http.request(req)
        case res
        when Net::HTTPFound
          uri = URI(res['Location'])
          fail "unexpected redirect: #{uri}"
        when Net::HTTPOK
          if (actual = Digest::SHA256.hexdigest(res.body)) != sha256
            puts "fetch failed: expected #{sha256}, got #{actual}"
            exit 1
          end

          FileUtils.mkdir_p(dirname)
          File.open(filepath, 'wb') { |f| f.write(res.body) }
        else
          puts "fetch failed: #{res.class.name}"
          exit 1
        end
      end
    when Net::HTTPOK
      if (actual = Digest::SHA256.hexdigest(res.body)) != sha256
        puts "fetch failed: expected #{sha256}, got #{actual}"
        exit 1
      end

      FileUtils.mkdir_p(dirname)
      File.open(filepath, 'wb') { |f| f.write(res.body) }
    else
      puts "fetch failed: #{res.class.name}"
      exit 1
    end
  end
end

task :extract, [:platform] => [] do |_, args|
  platform = args.to_h[:platform] ? Gem::Platform.new(args.to_h[:platform]) : Gem::Platform.local.dup

  Rake::Task['fetch'].execute(Rake::TaskArguments.new([:platform], [platform]))

  require 'rubygems/package'
  require 'fileutils'

  dirname = 'vendor/libddwaf'

  version = Datadog::Security::WAF::VERSION::BASE_STRING
  os = platform.os
  cpu = platform.cpu
  extname = '.tar.gz'
  filename_base = 'libddwaf-%<version>s-%<os>s-%<cpu>s%<extname>s'

  filename = format(filename_base, version: version, os: os, cpu: cpu, extname: extname)
  filepath = File.join(dirname, filename)

  File.open(filepath, 'rb') do |f|
    FileUtils.rm_rf(File.join(dirname, File.basename(filename, extname)))
    Gem::Package.new('').extract_tar_gz(f, dirname)
  end
end

task :binary, [:platform] => [] do |_, args|
  platform = args.to_h[:platform] ? Gem::Platform.new(args.to_h[:platform]) : Gem::Platform.local.dup

  Rake::Task['extract'].execute(Rake::TaskArguments.new([:platform], [platform]))

  gemspec = Helpers.binary_gemspec(platform: platform)
  gemspec.extensions.clear

  gemspec.files = []
  gemspec.files += Dir['lib/**/*.rb']
  gemspec.files += ['NOTICE'] + Dir['LICENSE*']

  gemspec.files += Dir[File.join(Helpers.libddwaf_dir(platform: platform), 'include/**/*.h')]
  gemspec.files += Dir[File.join(Helpers.libddwaf_dir(platform: platform), "lib/**/*#{Helpers.shared_lib_extname(platform: platform)}")]

  FileUtils.chmod(0o0644, gemspec.files)
  FileUtils.mkdir_p('pkg')

  package = if Gem::VERSION < '2.0.0'
              Gem::Builder.new(gemspec).build
            else
              require 'rubygems/package'
              Gem::Package.build(gemspec)
            end

  FileUtils.mv(package, 'pkg')
end

task test: :spec

task default: 'spec'
