source "https://rubygems.org"

gemspec

gem "climate_control", "~> 0.2.0"
gem "pry"

gem "rake", ">= 10.5"
gem "redcarpet", "~> 3.4" if RUBY_PLATFORM != "java"
gem "rspec", "~> 3.10"
gem "rspec-collection_matchers", "~> 1.1"
gem "rspec_junit_formatter", ">= 0.4.1"

if RUBY_VERSION >= "3.0.0"
  gem "standard"
  gem "ruby_memcheck", ">= 3"
end

if RUBY_VERSION >= "2.5.0"
  # Merging branch coverage results does not work for old, unsupported rubies.
  # We have a fix up for review, https://github.com/simplecov-ruby/simplecov/pull/972,
  # but given it only affects unsupported version of Ruby, it might not get merged.
  gem "simplecov", git: "https://github.com/DataDog/simplecov", ref: "3bb6b7ee58bf4b1954ca205f50dd44d6f41c57db"
else
  # Compatible with older rubies. This version still produces compatible output
  # with a newer version when the reports are merged.
  gem "simplecov", "~> 0.17"
end

gem "yard", "~> 0.9"

platforms :mri do
  if RUBY_VERSION >= "3.1.0"
    gem "rbs", "~> 3.6.1", require: false
    gem "steep", "~> 1.8.1", require: false

    # parallel 1.23 seems to annoy steep:
    # cannot load such file -- parallel/processor_count (LoadError)
    gem "parallel", "< 1.23"
  end
end
