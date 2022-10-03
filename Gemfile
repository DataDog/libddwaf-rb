source 'https://rubygems.org'

gemspec

gem 'climate_control', '~> 0.2.0'
gem 'pry'
if RUBY_PLATFORM != 'java'
  # There's a few incompatibilities between pry/pry-byebug on older Rubies
  gem 'pry-byebug' if RUBY_VERSION >= '2.6.0' && RUBY_VERSION < '3.0' && RUBY_ENGINE != 'truffleruby'
  gem 'pry-nav' if RUBY_VERSION < '2.6.0'
  gem 'pry-stack_explorer' if RUBY_VERSION >= '2.2.0'
end

gem 'rake', '>= 10.5'
gem 'redcarpet', '~> 3.4' if RUBY_PLATFORM != 'java'
gem 'rspec', '~> 3.10'
gem 'rspec-collection_matchers', '~> 1.1'
gem 'rspec_junit_formatter', '>= 0.4.1'
gem 'rspec_n', '~> 1.3' if RUBY_VERSION >= '2.4.0'

if RUBY_VERSION >= '2.4.0'
  gem 'rubocop', '~> 1.36', require: false
  gem 'rubocop-performance', '~> 1.9', require: false
  gem 'rubocop-rspec', '~> 2.2', require: false
end

if RUBY_VERSION >= '2.5.0'
  # Merging branch coverage results does not work for old, unsupported rubies.
  # We have a fix up for review, https://github.com/simplecov-ruby/simplecov/pull/972,
  # but given it only affects unsupported version of Ruby, it might not get merged.
  gem 'simplecov', git: 'https://github.com/DataDog/simplecov', ref: '3bb6b7ee58bf4b1954ca205f50dd44d6f41c57db'
else
  # Compatible with older rubies. This version still produces compatible output
  # with a newer version when the reports are merged.
  gem 'simplecov', '~> 0.17'
end

gem 'yard', '~> 0.9'

gem 'steep'
gem 'rbs'
