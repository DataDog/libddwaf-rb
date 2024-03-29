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
    if RUBY_ENGINE == 'jruby'
      os_name = java.lang.System.get_property('os.name')

      os = case os_name
           when /linux/i then 'linux'
           when /mac/i   then 'darwin'
           else raise Error, "unsupported JRuby os.name: #{os_name.inspect}"
           end

      return os
    end

    Gem::Platform.local.os
  end

  def self.local_version
    return nil unless local_os == 'linux'

    # Old rubygems don't handle non-gnu linux correctly
    return $1 if RUBY_PLATFORM =~ /linux-(.+)$/

    'gnu'
  end

  def self.local_cpu
    if RUBY_ENGINE == 'jruby'
      os_arch = java.lang.System.get_property('os.arch')

      cpu = case os_arch
            when 'amd64' then 'x86_64'
            else raise Error, "unsupported JRuby os.arch: #{os_arch.inspect}"
            end

      return cpu
    end

    Gem::Platform.local.cpu
  end

  def self.os(platform:)
    platform.os
  end

  def self.version(platform:)
    platform.version
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

  def self.shared_lib_triplet(platform:)
    platform.version ? "#{platform.os}-#{platform.version}-#{platform.cpu}" : "#{platform.os}-#{platform.cpu}"
  end

  def self.libddwaf_version
    Datadog::AppSec::WAF::VERSION::BASE_STRING
  end

  def self.libddwaf_basename(platform:)
    "libddwaf-#{libddwaf_version}-#{shared_lib_triplet(platform: platform)}"
  end

  def self.libddwaf_filename(platform:)
    "#{libddwaf_basename(platform: platform)}.tar.gz"
  end

  def self.libddwaf_dir(platform:)
    File.join(libddwaf_vendor_dir, libddwaf_basename(platform: platform))
  end

  def self.shared_lib_extname(platform:)
    platform.os == 'darwin' ? '.dylib' : '.so'
  end

  def self.shared_lib_filename(platform:)
    "libddwaf#{shared_lib_extname(platform: platform)}"
  end

  def self.shared_lib_path(platform:)
    File.join(libddwaf_dir(platform: platform), 'lib', shared_lib_filename(platform: platform))
  end

  def self.parse_platform(platform_string = nil)
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
end

task :fetch, [:platform] => [] do |_, args|
  platform = Helpers.parse_platform(args.to_h[:platform])

  require 'net/http'
  require 'fileutils'

  dirname = Helpers.libddwaf_vendor_dir

  version = Helpers.libddwaf_version
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

    'libddwaf-1.1.0-darwin-arm64.tar.gz'  => '7318aefea7150fb85886cac1523052a2503af7f1c4c12beaacd6276ea334e83f',
    'libddwaf-1.1.0-darwin-x86_64.tar.gz' => '01501b3effcd1d08ae4d4544b9be9674dfe093cc2b7f11f176879c91f374c8f8',
    'libddwaf-1.1.0-linux-aarch64.tar.gz' => '160dc8ddb7ce475cd5860fd6c34cb61915b436deb9f0990c9d65dea144ac6d26',
    'libddwaf-1.1.0-linux-x86_64.tar.gz'  => '909f3d3f442b13d46d6862f61685ea63156c61564674740ba8af8b7f8c9b5267',

    'libddwaf-1.2.0-darwin-arm64.tar.gz'  => '1476e94e6a2a9dc1bec749fa58a9f55d21e31aec78295ec66b444cdfef51ea2b',
    'libddwaf-1.2.0-darwin-x86_64.tar.gz' => 'f0b5ddf958d6a69903e03033380929cad67b663cf525ce51fa2b3a1d7fd23918',
    'libddwaf-1.2.0-linux-aarch64.tar.gz' => 'e4bb190ba2c815a819f405f2d0b6aeea88299ebe831e0752393f8b20014a6cae',
    'libddwaf-1.2.0-linux-x86_64.tar.gz'  => 'ce8f5f549a98475b1e793df8886e1fdff608c0cbf0cb4372590b0ec4b384c405',

    'libddwaf-1.2.1-darwin-arm64.tar.gz'  => '5be84523ab84230344abff397dfd0fc7445c6619d41402601da3b81b62f15e34',
    'libddwaf-1.2.1-darwin-x86_64.tar.gz' => '2c3ff1eadc4d9d3fc2fdca6f8795409dd9f11f12e3d98108c59fb6c3d34b0bdf',
    'libddwaf-1.2.1-linux-aarch64.tar.gz' => '88111f8f33b5206ac60a6b886c1cda5197ba085f48c5c2cbe5ff3eafb7baa461',
    'libddwaf-1.2.1-linux-x86_64.tar.gz'  => '108dce1c96625890709b0d2e65b9bbf6cdbf9e6b570d071f2fe6170f8ff00f32',

    'libddwaf-1.3.0-darwin-arm64.tar.gz'  => 'cd5bce11dee1951b5c72dbaa862a7c04cefecadff6737231b4da979994f47883',
    'libddwaf-1.3.0-darwin-x86_64.tar.gz' => '7c1a66308d8977233761ad35cccf96bdd3c6ef3b7b3e7e978176abfe626d96d5',
    'libddwaf-1.3.0-linux-aarch64.tar.gz' => 'f173e4037a55ea8abbe05728672bea9707579a4ae75f2ceee8e64d560da312a8',
    'libddwaf-1.3.0-linux-x86_64.tar.gz'  => '54da81f96a11cc40fd40f1adb569d4d41651da27c0a123202d71823a661a14b6',

    'libddwaf-1.5.1-darwin-arm64.tar.gz'  => '817567043187e797fe7ce102dd3c5f8d5c6e4c19a76bbced5ab183dbf091a4d8',
    'libddwaf-1.5.1-darwin-x86_64.tar.gz' => '17052d22a29853edad9d064edfc4e9978a4f32d4d9c7d6f62d7e0bab3a775845',
    'libddwaf-1.5.1-linux-aarch64.tar.gz' => '73b18be793ba2efcae7b7a43c5e7c3ed94a0b2bbb7c56b177ca698c4a378fbd6',
    'libddwaf-1.5.1-linux-x86_64.tar.gz'  => '782f5c0cff725d5afbbea2a255a2690397a8d85cff0199626ff5f0197d6813ee',

    'libddwaf-1.6.2-darwin-arm64.tar.gz'  => 'e0a990b9d62aae46d0cf726fdb77550e42e95bb04660d8c0099fd42356fb251c',
    'libddwaf-1.6.2-darwin-x86_64.tar.gz' => '6c29cc7729fd04821e19cecfa9bd5180d863baeb44a12a24ea2aa3a6d06c39c6',
    'libddwaf-1.6.2-linux-aarch64.tar.gz' => 'db08e8c7f3e949e17c57934efa3ac10c9241ab4786b4ba2996c24df58f7cb3f0',
    'libddwaf-1.6.2-linux-x86_64.tar.gz'  => 'a667df7c9a7ae36ab6eecf759845abdb4dcc8ebb593a43af0698eb70aa9f89ca',

    'libddwaf-1.7.0-darwin-arm64.tar.gz'  => '2a1aca6b67614c6199e775bb22c6c67544d55bd6487b824ae0899cd42399f3f7',
    'libddwaf-1.7.0-darwin-x86_64.tar.gz' => 'f91f587c679183a2d9c22d0e90f2275760d544f84ff2aff2b54d897d563e93e6',
    'libddwaf-1.7.0-linux-aarch64.tar.gz' => '3db729225f3a21eab5ad6996b7b4d261e1fda2904148424ae37de4a97837f6ba',
    'libddwaf-1.7.0-linux-x86_64.tar.gz'  => '854fda937a0ca298795a79e63623a762afe013fd3f76b6aae58eee1211b56da5',

    'libddwaf-1.8.2-darwin-arm64.tar.gz'  => 'f7a18df1716241dcee10ff1289ba67fc377e60c5eaf6b2774b765432e0874e72',
    'libddwaf-1.8.2-darwin-x86_64.tar.gz' => 'c1fbf821396c9ba62deeae9719aff9ecb6a904f77b7d68c95de4eb759fb646ac',
    'libddwaf-1.8.2-linux-aarch64.tar.gz' => 'fee446827b2971454be992fa99284fb5b5d2609dd2cefba4c331fa1b53bc7faf',
    'libddwaf-1.8.2-linux-x86_64.tar.gz'  => '106d5830b9011df1d7257d70ca1016a5970c8f287e75e0ad00d67e821c9ff04c',

    'libddwaf-1.9.0-darwin-arm64.tar.gz'  => 'dbec69fbfd383266566f6bb2d9e033a88baab9bfc97b2ab552fbc22626b65b5a',
    'libddwaf-1.9.0-darwin-x86_64.tar.gz' => 'fbb00c3dad779141ef037238315aab84adac5abfffb7944b19e5493d432ea43c',
    'libddwaf-1.9.0-linux-aarch64.tar.gz' => '3869b807be750bc71359e1add277635afecc20ea8609e3fc4c0c9722a68b709f',
    'libddwaf-1.9.0-linux-x86_64.tar.gz'  => 'a1e7422116d318883ad43942d7416bbe3e92797e60840336a98d1100487de912',

    'libddwaf-1.10.0-darwin-arm64.tar.gz'  => '4ddecf38ca0a2048088dbbf663dc66c053fb243504be0000c44dfa802f15788f',
    'libddwaf-1.10.0-darwin-x86_64.tar.gz' => 'f2bc8ed671cfa0662ed45cf3895cb4dd7fa0c8e9cdf4d2fe2b59eda9e9589813',
    'libddwaf-1.10.0-linux-aarch64.tar.gz' => 'd74ebadd09a11cb342082d763439dd235be4583f52b8f597369640cc5daa60c6',
    'libddwaf-1.10.0-linux-x86_64.tar.gz'  => 'a51c63ea0d0223df5b7b0d7d9abc608cf63f65b5aebbbb1acba7bd667e4f1335',

    'libddwaf-1.11.0-darwin-arm64.tar.gz'  => 'a50d087d5b8f6d3b4bc72d4ef85e8004c06b179f07e5974f7849ccb552b292c8',
    'libddwaf-1.11.0-darwin-x86_64.tar.gz' => 'e1285b9a62393a4a37fad16b49812052b9eed95920ffe4cd591e06ac27ed1b32',
    'libddwaf-1.11.0-linux-aarch64.tar.gz' => '92a0a64daa00376b127dfe7d7f02436f39a611325113e212cf2cdafddd50053a',
    'libddwaf-1.11.0-linux-x86_64.tar.gz'  => '7a0682c2e65cec7540d04646621d6768bc8f42c5ff22da2a0d20801b51ad442a',

    'libddwaf-1.14.0-darwin-arm64.tar.gz'  => 'd9cd1c92a3a814b8f3c4f92f7dce3037904c2650fcff52019121b0a7c56a5106',
    'libddwaf-1.14.0-darwin-x86_64.tar.gz' => '9bea4519fabd0d740ad45050654aef92b3c33ede2ea76e0c616adfb4b2aff828',
    'libddwaf-1.14.0-linux-aarch64.tar.gz' => 'e54bd624459158c33f62c846399ccaf7ae851b039cb2daa727949ab5b1d50ff5',
    'libddwaf-1.14.0-linux-x86_64.tar.gz'  => '0e56a381e81cbdf8d8375d42642ee31ac46e576c7e4ad9e72d0b7d214c0f9874',
  }

  filename = Helpers.libddwaf_filename(platform: platform)
  filepath = File.join(dirname, filename)
  sha256 = sha256_filename[filename]

  if sha256.nil?
    fail "hash not found: #{filename.inspect}"
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
  platform = Helpers.parse_platform(args.to_h[:platform])

  if File.exist?(Helpers.shared_lib_path(platform: platform))
    next
  end

  Rake::Task['fetch'].execute(Rake::TaskArguments.new([:platform], [platform]))

  require 'rubygems/package'
  require 'fileutils'

  dirname = Helpers.libddwaf_vendor_dir
  filename = Helpers.libddwaf_filename(platform: platform)
  filepath = File.join(dirname, filename)

  File.open(filepath, 'rb') do |f|
    FileUtils.rm_rf(Helpers.libddwaf_dir(platform: platform))
    Gem::Package.new('').extract_tar_gz(f, dirname)
  end
end

task :binary, [:platform] => [] do |_, args|
  subplatform_for = {
    # lean gems
    'x86_64-linux-gnu'       => ['x86_64-linux-gnu'],
    'x86_64-linux-musl'      => ['x86_64-linux-musl'],
    'aarch64-linux-gnu'      => ['aarch64-linux-gnu'],
    'aarch64-linux-musl'     => ['aarch64-linux-musl'],
    'x86_64-darwin'          => ['x86_64-darwin'],
    'arm64-darwin'           => ['arm64-darwin'],

    # portable gems
    'x86_64-linux:llvm'      => ['x86_64-linux'],
    'aarch64-linux:llvm'     => ['aarch64-linux'],

    # fat gems
    'x86_64-linux:gnu+musl' => [
      'x86_64-linux-gnu',
      'x86_64-linux-musl',
    ],
    'aarch64-linux:gnu+musl' => [
      'aarch64-linux-gnu',
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

    Helpers.shared_lib_path(platform: subplatform)
  end

  gemspec = Helpers.binary_gemspec(platform: platform)
  gemspec.extensions.clear

  gemspec.files = []
  gemspec.files += Dir['lib/**/*.rb']
  gemspec.files += ['NOTICE', 'CHANGELOG.md'] + Dir['LICENSE*']

  gemspec.files += shared_lib_paths

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
