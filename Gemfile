source ENV['GEM_SOURCE'] || 'https://rubygems.org'

# Core test framework
gem 'voxpupuli-test'
gem 'openvox'

# Acceptance / Beaker
gem 'voxpupuli-acceptance'
gem 'voxpupuli-release'
gem 'beaker-openstack'

# Coverage
gem 'simplecov'
gem 'simplecov-console'

# Utilities
gem 'hiera-eyaml'
gem 'concurrent-ruby'
gem 'in-parallel'
gem 'rainbow'

# Platform-specific dependency
if RUBY_VERSION < '3.0'
  gem 'ffi', '~> 1.15.5'
else
  gem 'ffi'
end


# Other gems...
# gem 'fast_gettext'          # Needed by i18n tooling (eyaml etc.)
# gem 'rb-readline'
