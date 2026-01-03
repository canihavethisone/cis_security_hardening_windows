# frozen_string_literal: true
require 'voxpupuli/test/spec_helper'
require 'rainbow'

puts "\n"
puts "Loaded Puppet module version: #{Puppet.version}"
puts "Loaded from: #{Gem.loaded_specs['openvox']&.full_gem_path}"
puts "Old Puppet gem: #{Gem.loaded_specs['puppet']&.full_name || 'none'}"
puts "Active openvox gem: #{Gem.loaded_specs['openvox']&.full_name || 'none'}"
puts "\n#{Rainbow("Using Puppet #{Puppet.version}").cyan}\n\n" if defined?(Puppet)

default_facts = {
  puppetversion: Puppet.version,
  facterversion: Facter.version,
}

default_fact_files = [
  File.expand_path(File.join(File.dirname(__FILE__), 'default_facts.yml')),
  File.expand_path(File.join(File.dirname(__FILE__), 'default_module_facts.yml')),
]

default_fact_files.each do |f|
  next unless File.exist?(f) && File.readable?(f) && File.size?(f)
  begin
    default_facts.merge!(YAML.safe_load(File.read(f), permitted_classes: [], permitted_symbols: [], aliases: true))
  rescue StandardError => e
    RSpec.configuration.reporter.message "WARNING: Unable to load #{f}: #{e}"
  end
end

# read default_facts and merge them over what is provided by facterdb
default_facts.each do |fact, value|
  add_custom_fact fact, value
end

RSpec.configure do |c|
  # c.run_all_when_everything_filtered = true
  c.hiera_config = File.expand_path(File.join(__FILE__, '../fixtures/hiera.yaml'))
  c.formatter = 'documentation'
  c.mock_with :rspec
  c.tty = true
  c.default_facts = default_facts

  c.before :each do
    # set to strictest setting for testing
    Puppet.settings[:strict] = :warning
    Puppet.settings[:strict_variables] = true

    # stub local_security_policy
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Administrators').and_return('S-1-5-32-544')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Remote Desktop Users').and_return('S-1-5-32-555')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('LocalService').and_return('S-1-5-19')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Network Service').and_return('S-1-5-20')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Users').and_return('S-1-5-32-545')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Service').and_return('S-1-5-6')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Guests').and_return('S-1-5-32-546')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('Local account').and_return('S-1-5-113')
    allow(Puppet::Util::Windows::SID).to receive(:name_to_sid).with('WDAGUtilityAccount').and_return('S-1-5-21')
    # keep original call behavior
    allow(Puppet::Util).to receive(:which).and_call_original
  end

  c.filter_run_excluding(bolt: true) unless ENV['GEM_BOLT']

  # Report coverage after entire suite
  c.after(:suite) do
    # This ensures only one report, threshold applies across all OSes
    RSpec::Puppet::Coverage.report!(90)
  end

  # Filter backtrace noise
  backtrace_exclusion_patterns = [%r{spec_helper}, %r{gems}]
  [:backtrace_exclusion_patterns, :backtrace_clean_patterns].each do |attr|
    c.public_send("#{attr}=", backtrace_exclusion_patterns) if c.respond_to?(attr)
  end
end

# Ensures that a module is defined
# @param module_name Name of the module
def ensure_module_defined(module_name)
  module_name.split('::').reduce(Object) do |last_module, next_module|
    last_module.const_set(next_module, Module.new) unless last_module.const_defined?(next_module, false)
    last_module.const_get(next_module, false)
  end
end

# 'spec_overrides' from sync.yml will appear below this line
