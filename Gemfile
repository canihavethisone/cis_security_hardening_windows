source ENV['GEM_SOURCE'] || 'https://rubygems.org'
#source "file://#{File.expand_path('rubygems')}"

# Unit / fast tests
group :test do
  gem 'beaker-openstack', '>= 2.0', '< 3.0', require: false
  gem 'hiera-eyaml', '>= 4.0', '< 5.0', require: false
  gem 'in-parallel', '>= 1.0', '< 2.0', require: false
  gem 'puppet_metadata', '>= 5.0', '< 7.0', require: false
  gem 'rainbow', '>= 3.0', '< 4.0', require: false
  gem 'voxpupuli-test', '~> 13.0', require: false
  gem 'voxpupuli-release', '>= 4.0', '< 6.0', require: false
end

# Development / tooling
group :development do
  gem 'guard-rake', '>= 1.0', '< 2.0', require: false
  gem 'overcommit', '>= 0.39.1', require: false
end

# System / acceptance tests (require full environment)
group :system_tests do
  gem 'voxpupuli-acceptance', '>= 3.0', '< 5.0', require: false
end

# Runtime / core
gem 'rake', require: false

gem 'openvox', ENV.fetch('OPENVOX_GEM_VERSION', [">= 7", "< 9"]), :require => false, :groups => [:test]

# Platform-specific ffi version for Ruby < 3.0
gem 'ffi', RUBY_VERSION < '3.0' ? '~> 1.15.5' : nil
