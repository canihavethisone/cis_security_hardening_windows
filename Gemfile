source ENV['GEM_SOURCE'] || 'https://rubygems.org'

# Core test framework (used in dev/test only)
group :test do
  gem 'voxpupuli-test'
  gem 'hiera-eyaml'
  gem 'simplecov'
  gem 'simplecov-console'
  gem 'concurrent-ruby'
  gem 'in-parallel'
  gem 'rainbow'
end

# Release tooling (used during release process)
group :release do
  gem 'voxpupuli-release'
end

# System / acceptance tests
group :system_tests do
  gem 'voxpupuli-acceptance'
  gem 'beaker-openstack'
  gem 'beaker-module_install_helper'
end

# Required for Puppet compatibility (runtime)
gem 'openvox'

# Platform-specific ffi version for Ruby < 3.0
gem 'ffi', RUBY_VERSION < '3.0' ? '~> 1.15.5' : nil
