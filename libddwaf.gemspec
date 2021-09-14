# coding: utf-8

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'datadog/waf/version'

Gem::Specification.new do |spec|
  spec.name                  = 'libddwaf'
  spec.version               = Datadog::WAF::VERSION::STRING
  spec.required_ruby_version = [">= #{Datadog::WAF::VERSION::MINIMUM_RUBY_VERSION}", "< #{Datadog::WAF::VERSION::MAXIMUM_RUBY_VERSION}"]
  spec.required_rubygems_version = '>= 2.0.0'
  spec.authors               = ['Datadog, Inc.']
  spec.email                 = ['dev@datadoghq.com']

  spec.summary     = 'Datadog WAF'
  spec.description = <<-EOS.gsub(/^[\s]+/, '')
    libddwaf packages a WAF implementation in C++, exposed to Ruby
  EOS

  spec.homepage = 'https://github.com/DataDog/libddwaf'
  spec.license  = 'BSD-3-Clause'

  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = 'https://rubygems.org'
  else
    raise 'RubyGems 2.0 or newer is required to protect against public gem pushes.'
  end

  spec.files =
    `git ls-files -z`
    .split("\x0")
    .reject { |f| f.match(%r{^(spec|[.]circleci)/}) }
    .reject do |f|
      ['.dockerignore', '.env', '.rspec', '.rubocop.yml', '.rubocop_todo.yml',
      '.simplecov', 'Gemfile', 'Rakefile', 'docker-compose.yml'].include?(f)
    end
  spec.require_paths = ['lib']

  spec.add_dependency 'ffi'
end
