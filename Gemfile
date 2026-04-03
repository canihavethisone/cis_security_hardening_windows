source ENV['GEM_SOURCE'] || 'https://rubygems.org'

# -----------------------------
# Unit / fast tests
# -----------------------------
group :test do
  gem 'beaker-openstack', '~> 3.0', require: false
  gem 'hiera-eyaml', require: false
  gem 'in-parallel', require: false

  # Allow latest compatible versions
  gem 'puppet_metadata', require: false
  gem 'rainbow', require: false
  gem 'voxpupuli-test', require: false
  gem 'voxpupuli-release', require: false
end

# -----------------------------
# Development / tooling
# -----------------------------
group :development do
  gem 'guard-rake', require: false
  gem 'overcommit', require: false
end

# -----------------------------
# System / acceptance tests
# -----------------------------
group :system_tests do
  gem 'voxpupuli-acceptance', require: false
end

# -----------------------------
# Runtime / core
# -----------------------------
gem 'rake', require: false

# OpenVox / Puppet runtime (CI-controlled)
gem 'openvox',
    ENV.fetch('OPENVOX_GEM_VERSION', ['>= 7', '< 9']),
    require: false,
    groups: [:test]

# ffi (Puppet/OpenVox dependency)
gem 'ffi', require: false