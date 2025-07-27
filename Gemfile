source ENV['GEM_SOURCE'] || 'https://rubygems.org'

# Core test framework (used in dev/test only)
group :test do
  gem 'voxpupuli-test'
  gem 'voxpupuli-release'
  gem 'beaker-hiera'
  gem 'hiera-eyaml'
  gem 'in-parallel'
  gem 'rainbow'
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
