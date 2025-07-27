require 'rubygems'
require 'bundler'
require 'bundler/setup'
require 'tmpdir'
require 'rake/clean'
require 'puppet-strings/tasks'
require 'puppetlabs_spec_helper/rake_tasks'
require 'puppet/version'
require 'semantic_puppet'
require 'puppet-lint/tasks/puppet-lint'
require 'puppet-syntax/tasks/puppet-syntax'
require 'metadata-json-lint/rake_task'
require 'yaml'
# require 'puppet_blacksmith/rake_tasks'

# Hobble the puppet gem so the Openvox gem is used exclusively
begin
  puppet_path = Bundler.rubygems.find_name('puppet').first.full_gem_path
  if defined?(Puppet) && File.directory?(puppet_path)
    system('bundle binstub openvox --force')
    system("rm -rf #{puppet_path}.old")
    if File.rename(puppet_path, "#{puppet_path}.old")
      puts "\e[0;36m\nRenamed puppet rubygem in #{puppet_path} to ensure Openvox is used\e[0m\n\n"
    end
  end
rescue => e
  warn "Could not locate puppet gem: #{e.message}"
end

# Allow acceptances tests to set their own value for the BEAKER_set variable.
beaker_set = {}

exclude_paths = [
    "bundle/**/*",
    "pkg/**/*",
    "vendor/**/*",
    "spec/**/*",
]

all_acc_tasks = []

Rake::Task[:lint].clear
PuppetLint.configuration.send('disable_relative')

PuppetLint::RakeTask.new :lint do |config|
  config.ignore_paths = exclude_paths
end

PuppetSyntax.exclude_paths = exclude_paths

# Create rake tasks for individual acceptance tests
# Need to cater for nested structure
# Enables the ability to run tests on different hiera configurations
acc_tests = Dir.glob(['spec/acceptance/**/*']).grep(/_spec\.rb/i)
acc_tests.each do |item|

  target = item.sub('spec/', '').gsub('/', ':').sub(/_spec\.rb/, '') # Generate task name
  hiera_target = target.gsub('acceptance', '').gsub(':', '/').gsub('.yaml', '')
  hiera_tests = Dir.glob(["spec/fixtures/hiera/data/#{hiera_target}/*"]).grep(/acceptance/)

  if hiera_tests.empty?
    hiera_tests.push('acceptance')
  else
    hiera_tests.map! {|hiera_test| File.basename hiera_test}
  end

  hiera_tests.each do |testcase|
    target_task = target + testcase.gsub('acceptance','').gsub('.yaml', '')
    all_acc_tasks.push(target_task)
    RSpec::Core::RakeTask.new(target_task) do |task|
      if beaker_set[target_task]
        ENV['BEAKER_set'] = beaker_set[target_task]
      end

      handle_beaker_provision

      # second argument is the hiera file assigned to this test case
      task.rspec_opts = ['--color' , "--options #{testcase.gsub('.yaml', '')}"]
      task.pattern = item
    end
  end
end

# Create rake tasks for individual spec tests
# Need to cater for nested structure
spec_tests = Dir.glob(['spec/classes/**/*', 'spec/defines/**/*'])
spec_tests.each do |item|

  if item =~ /_spec\.rb/i
    target = item.sub('spec/', '').gsub('classes', 'spec/classes').gsub('/', ':').sub(/_spec\.rb/, '') # Generate task name

    RSpec::Core::RakeTask.new(target) do |task|
      Rake::Task[:syntax].invoke
      Rake::Task[:lint].invoke
      Rake::Task[:spec_prep].invoke
      task.rspec_opts = ['--color']
      task.pattern = item
    end
  end
end

# *** Important Note: we need to cater for nested structure
# where the profiles/roles are nested the tests, metadata and hiera data will conform to the same structure

# Create tasks for running all role/profile acceptance tests in parallel
# Get array of all acceptance tasks
namespace 'acceptance' do
  desc "Run acceptance tests in parallel"
  multitask :all_p => all_acc_tasks
  desc "Run acceptance tests"
  task :all do
    all_acc_tasks.each do |task|
      Rake::Task[task].invoke()
    end
  end
end

desc "Run syntax, lint, and spec tests."
task :test => [
    :metadata_lint,
    :syntax,
    :lint,
    :spec,
]

# Set the BEAKER_setfile env variable to use a temporary nodefile crafted
# with the machine names from the previous run when BEAKER_provision=no
def handle_beaker_provision
  bp = ENV['BEAKER_provision'] ? ENV['BEAKER_provision'] : 'yes'
  p "handling BEAKER_provision ('#{bp}')"
  if bp.casecmp('no') == 0

    # Find the logfile for the last run
    nodeset_name = ENV['BEAKER_set'] ? ENV['BEAKER_set'] : 'default'
    logdir = File.join(Dir.pwd, "log", nodeset_name)
    last_logfile = Dir.glob("#{logdir}/**/*.*").max_by { |f| File.mtime(f) }
    p "Extracting node names from #{File.expand_path(last_logfile)}"

    # Extract node name to role mapping
    nodenames = Hash.new
    File.open(last_logfile).each do |line|
      hostname, role = line.split.values_at(5, 6).map { |v| v.gsub(/[()]/, '') }
      nodenames[role] = hostname
    end
    p "Node mapping: #{nodenames.to_s}"

    # Generate temporary nodeset file
    nodeset_dir = File.join(Dir.pwd, 'spec', 'acceptance', 'nodesets')
    nodeset = YAML::load(File.open(File.join(nodeset_dir, "#{nodeset_name}.yml")))
    nodeset['HOSTS'] = nodeset['HOSTS'].inject({}) { |result, node|
      result.merge({nodenames[node.first] => node.last})
    }
    File.open(Dir::Tmpname.create(['tmp_nodeset', '.yaml'], nodeset_dir) {}, 'w') { |nodefile|
      nodefile.write nodeset.to_yaml
      p "Nodeset YAML written to #{File.expand_path(nodefile)}"

      # Set env to use temp nodeset file
      ENV['BEAKER_setfile'] = File.expand_path(nodefile)
      ENV.delete('BEAKER_set')
    }
  end

  CLEAN.include(FileList["#{nodeset_dir}/tmp_nodeset*.yaml"])
end
