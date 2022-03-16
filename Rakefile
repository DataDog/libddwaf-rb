require 'bundler/gem_tasks'
require 'datadog/appsec/waf/version'
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
    File.join(libddwaf_vendor_dir, "libddwaf-#{Datadog::AppSec::WAF::VERSION::BASE_STRING}-#{os(platform: platform)}-#{cpu(platform: platform)}")
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

  version = Datadog::AppSec::WAF::VERSION::BASE_STRING
  os = platform.os
  cpu = platform.cpu
  extname = '.tar.gz'
  filename_base = 'libddwaf-%<version>s-%<os>s-%<cpu>s%<extname>s'
  uri_base = 'https://github.com/DataDog/libddwaf/releases/download/%<version>s/%<filename>s'

  sha256_filename = {
    'libddwaf-1.0.11-darwin-arm64.tar.gz'  => '03f1edc01a18379b7ec6c967225a50224c5cc463b5982d64aad9f68c2c1e6823',
    'libddwaf-1.0.11-darwin-x86_64.tar.gz' => '0f046ccc789e1ddf06923ac09c0eabd68e0e45a6ab51d0bb7171b583034871ad',
    'libddwaf-1.0.11-linux-aarch64.tar.gz' => 'af21751b2f53b3ddbaecdacda281e585642448702edc100a47b972f4939137b5',
    'libddwaf-1.0.11-linux-x86_64.tar.gz'  => 'd1a3e49c96c272620b0c5f82f9fa68fcfa871dddf2a38f9d3af374e742a1e0c0',

    'libddwaf-1.0.12-darwin-arm64.tar.gz'  => 'e1a40846db2ce0e99b21198ff5edb239ed8e2d4857e8e42fffb3c8e574bd6ece',
    'libddwaf-1.0.12-darwin-x86_64.tar.gz' => '2a809bf7dcf3f5d86409f0b18f8ec9f8e6c9a4a913f321bb68d65abad280170d',
    'libddwaf-1.0.12-linux-aarch64.tar.gz' => 'a1f4a5022bbcafa4d31de31be7789d00b81b361377d0f62f419873122d8be228',
    'libddwaf-1.0.12-linux-x86_64.tar.gz'  => '1b5ba745b6b1c19261844d33c60c9dbea5f4303e27b1a03ad2e855e83491d70c',

    'libddwaf-1.0.13-darwin-arm64.tar.gz'  => 'a1be729493d4e9936ae488e1d1278a863f427d593dcf55a03dade3cd2ac07b9c',
    'libddwaf-1.0.13-darwin-x86_64.tar.gz' => '54bc542bb3c9900d22fd69a8df32345d5ce2f69f45ded6cc4d1445a4b7ea1ebd',
    'libddwaf-1.0.13-linux-aarch64.tar.gz' => '30b19db220b83707533440a5e912edbc9ea068e9e62f40d401923ea9097856cf',
    'libddwaf-1.0.13-linux-x86_64.tar.gz'  => '80b6f6f66dde8fea645e020e779d4e3860435b88270f27d8b18677cf2a422920',

    'libddwaf-1.0.14-darwin-arm64.tar.gz'  => '8bda9b34f7d6e56973c7f227f4a1537a300f3d8c0e73274d285484d0fdd16da2',
    'libddwaf-1.0.14-darwin-x86_64.tar.gz' => '6444ac85dc4dfc9ffb398649329f2a2cbe069e71fd983e87e8128b348eeff17c',
    'libddwaf-1.0.14-linux-aarch64.tar.gz' => '6b9699bcbf5903f32d38db6e683add3e12f0d781165fac3fa11eab25dd79ac9c',
    'libddwaf-1.0.14-linux-x86_64.tar.gz'  => 'fedc4d4fc4bfde7731acf56a06c0dec2b489d75f79e2f8062c7c4311c6476b77',

    'libddwaf-1.0.15-darwin-arm64.tar.gz'  => '7340915f1bcfa56c2fcc9998c7811f22b9f98c9ff68d559425a378cc300ba373',
    'libddwaf-1.0.15-darwin-x86_64.tar.gz' => '83b1d8bb58a80f3b4e8d3aeb952382053a95f4a57b49aa22c4c114f366643664',
    'libddwaf-1.0.15-linux-aarch64.tar.gz' => '10867711c069ffffc24c6badd6de8fb38eb1ec99377092706b954b94cd4e9325',
    'libddwaf-1.0.15-linux-x86_64.tar.gz'  => '346627afe7e8957deff41a973a36e1f3a8172611aa11a642ad8f2b5619fdc7c6',

    'libddwaf-1.0.16-darwin-arm64.tar.gz'  => 'e369a137c4d86ec6d70ba97c5d9105fcdf265a1694b04b1791fbe14f1866e8de',
    'libddwaf-1.0.16-darwin-x86_64.tar.gz' => 'bbf4c596ee7e8139c2d22e7da79aea71d2aebdbc4181218bfbbd4dee4d8d28e6',
    'libddwaf-1.0.16-linux-aarch64.tar.gz' => '9b421356ca8dfbaae150c0528237ba6ec27c72d933a1e8ec02bfd991791032ea',
    'libddwaf-1.0.16-linux-x86_64.tar.gz'  => '21857275be172cd0dce7550ecda20585290d22f72f9be754abc52d8e62b6096d',

    'libddwaf-1.0.17-darwin-arm64.tar.gz'  => 'fb5653468dd402f0b06ac305b2efe50e4341422d0e40d13ebb3c3d1989733b57',
    'libddwaf-1.0.17-darwin-x86_64.tar.gz' => '06ea6692d18b85d3ec152026d955de3aa96b969a7d7ffad93cda87bce4dfa43e',
    'libddwaf-1.0.17-linux-aarch64.tar.gz' => 'cd29cf1815fe70861a2332d479f367d999c69c0e0a723a88bcffc93ff1c367ae',
    'libddwaf-1.0.17-linux-x86_64.tar.gz'  => 'af7e6205269871c2226eb131e3702d0f505f91fe40eb0aec1982c9cb90636e6e',

    'libddwaf-1.0.18-darwin-arm64.tar.gz'  => '242a046a235120c851cd473f53a264235e9747f17f4a93b747b50f4fd40a75de',
    'libddwaf-1.0.18-darwin-x86_64.tar.gz' => '4daa5c6ff3ab5150a7cab9522cd5e65e3aa3c611ecda7b36fb081f8794bbca28',
    'libddwaf-1.0.18-linux-aarch64.tar.gz' => '63ed8e663133e7be32f63a16ed73900220b5b31c8937d9b05549641231a34a04',
    'libddwaf-1.0.18-linux-x86_64.tar.gz'  => 'ae667f31cfa69f9f85c2fe4d963285361a5893d9bec3d5328a3ac9453c4cdd11',
  }

  filename = format(filename_base, version: version, os: os, cpu: cpu, extname: extname)
  filepath = File.join(dirname, filename)
  sha256 = sha256_filename[filename]

  if sha256.nil?
    fail "hash not found: #{filename}"
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

  version = Datadog::AppSec::WAF::VERSION::BASE_STRING
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
