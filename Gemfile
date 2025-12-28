source ENV['GEM_SOURCE'] || 'https://rubygems.org'

group :test do
  gem 'voxpupuli-test', '~> 13.0',  :require => false
  gem 'puppet_metadata', '~> 5.0',  :require => false
  gem 'in-parallel'
  gem 'beaker-puppet'
  gem 'beaker-openstack'
  gem 'hiera-eyaml'
  gem 'rainbow'
end

group :development do
  gem 'guard-rake',               :require => false
  gem 'overcommit', '>= 0.39.1',  :require => false
end

group :system_tests do
  gem 'voxpupuli-acceptance', '>= 3.0', '< 5.0',  :require => false
end

group :release do
  gem 'voxpupuli-release', '>= 4.0', '< 6.0',   :require => false
end

# Platform-specific ffi version for Ruby < 3.0
gem 'ffi', RUBY_VERSION < '3.0' ? '~> 1.15.5' : nil

gem 'rake', :require => false

gem 'openvox', ENV.fetch('OPENVOX_GEM_VERSION', [">= 7", "< 9"]), :require => false, :groups => [:test]
