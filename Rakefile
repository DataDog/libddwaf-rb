require 'bundler/gem_tasks'
require 'datadog/waf/version'
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
  t.options += ['--title', "datadog-instrumentation #{Datadog::WAF::VERSION::STRING} documentation"]
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

task :fetch do
  require 'net/http'
  require 'fileutils'

  dirname = 'vendor/libddwaf'

  version = Datadog::WAF::VERSION::BASE_STRING
  os = 'darwin'
  cpu = 'x86_64'
  extname = '.tar.gz'
  filename_base = 'libddwaf-%<version>s-%<os>s-%<cpu>s%<extname>s'
  uri_base = 'https://github.com/DataDog/libddwaf/releases/download/%<version>s/%<filename>s'

  sha256_filename = {
    'libddwaf-1.0.8-darwin-x86_64.tar.gz' => '8562fa09fde83aebf85bb6ea0e9933623e2a997794ddc9f4b9c3051c28183e04',
  }

  filename = format(filename_base, version: version, os: os, cpu: cpu, extname: extname)
  filepath = File.join(dirname, filename)
  sha256 = sha256_filename[filename]

  if (actual = Digest::SHA256.hexdigest(File.read(filepath))) == sha256
    next
  end

  uri = URI(format(uri_base, version: version, filename: filename))

  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    puts "fetch #{uri}"
    req = Net::HTTP::Get.new(uri)
    res = http.request(req)
    case res
    when Net::HTTPNotFound
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

task :extract => :fetch do
  require 'rubygems/package'
  require 'fileutils'

  dirname = 'vendor/libddwaf'

  version = Datadog::WAF::VERSION::BASE_STRING
  os = 'darwin'
  cpu = 'x86_64'
  extname = '.tar.gz'
  filename_base = 'libddwaf-%<version>s-%<os>s-%<cpu>s%<extname>s'

  filename = format(filename_base, version: version, os: os, cpu: cpu, extname: extname)
  filepath = File.join(dirname, filename)

  File.open(filepath, 'rb') do |f|
    FileUtils.rm_rf(File.join(dirname, File.basename(filename, extname)))
    Gem::Package.new('').extract_tar_gz(f, dirname)
  end
end

task default: 'spec'
