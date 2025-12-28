source ENV['GEM_SOURCE'] || 'https://rubygems.org'

# Unit / fast tests
group :test do
  gem 'voxpupuli-test', '~> 13.0', require: false
  gem 'puppet_metadata', '~> 5.0', require: false
  gem 'voxpupuli-release', '>= 4.0', '< 6.0', require: false
  gem 'in-parallel'
  gem 'beaker-puppet'
  gem 'beaker-openstack'
  gem 'hiera-eyaml'
  gem 'rainbow'
  gem 'openvox', ENV.fetch('OPENVOX_GEM_VERSION', [">= 7", "< 9"]), require: false
end

# Development / tooling
group :development do
  gem 'guard-rake', require: false
  gem 'overcommit', '>= 0.39.1', require: false
end

# System / acceptance tests (require full environment)
group :system_tests do
  gem 'voxpupuli-acceptance', '>= 3.0', '< 5.0', require: false
end

# Runtime / core
gem 'rake', require: false

# Platform-specific ffi version for Ruby < 3.0
gem 'ffi', RUBY_VERSION < '3.0' ? '~> 1.15.5' : nil
