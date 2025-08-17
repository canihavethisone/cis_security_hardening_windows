# Updated Rakefile for Voxpupuli toolchain
# Safely adapted from the original Puppetlabs-based test structure

require 'bundler/setup'                # Ensures all gems in Gemfile are available (must be first)
require 'tmpdir'                       # Standard library: used for temporary file/dir handling
require 'yaml'                         # Standard library: used for parsing YAML files
require 'rake/clean'                   # Adds Rake tasks for cleaning files/directories
require 'voxpupuli/test/rake'          # Loads test-related Rake tasks (e.g., lint, syntax, spec)
require 'voxpupuli/release/rake_tasks' # Adds Voxpupuli release automation tasks (e.g., changelog, tagging)

# Load standard Voxpupuli rake tasks
task_path = File.expand_path('lib/voxpupuli/test/rake_tasks.rb', Gem.loaded_specs['voxpupuli-test']&.full_gem_path || '')
require task_path if File.exist?(task_path)

# Disable default :lint task to customize paths
Rake::Task[:lint].clear if Rake::Task.task_defined?(:lint)

PuppetLint.configuration.send('disable_relative')
exclude_paths = ["bundle/**/*", "pkg/**/*", "vendor/**/*", "spec/**/*"]
PuppetLint::RakeTask.new :lint do |config|
  config.ignore_paths = exclude_paths
end

# Acceptance test task creation
beaker_set = {}
all_acc_tasks = []
acc_tests = Dir.glob(['spec/acceptance/**/*']).grep(/_spec\.rb/i)
acc_tests.each do |item|
  target = item.sub('spec/', '').gsub('/', ':').sub(/_spec\.rb/, '')
  hiera_target = target.gsub('acceptance', '').gsub(':', '/').gsub('.yaml', '')
  hiera_tests = Dir.glob(["spec/fixtures/hiera/data/#{hiera_target}/*"]).grep(/acceptance/)
  hiera_tests = ['acceptance'] if hiera_tests.empty?
  hiera_tests.map! { |hiera_test| File.basename(hiera_test) }

  hiera_tests.each do |testcase|
    target_task = target + testcase.gsub('acceptance','').gsub('.yaml', '')
    all_acc_tasks.push(target_task)
    RSpec::Core::RakeTask.new(target_task) do |task|
      ENV['BEAKER_set'] = beaker_set[target_task] if beaker_set[target_task]
      handle_beaker_provision
      task.rspec_opts = ["--format", "documentation", "--options", testcase.gsub('.yaml', '')]
      task.pattern = item
    end
  end
end

# Unit test tasks for each spec file
spec_tests = Dir.glob(['spec/classes/**/*', 'spec/defines/**/*']).grep(/_spec\.rb/i)
spec_tests.each do |item|
  target = item.sub('spec/', '').gsub('classes', 'spec/classes').gsub('/', ':').sub(/_spec\.rb/, '')
  RSpec::Core::RakeTask.new(target) do |task|
    Rake::Task[:syntax].invoke if Rake::Task.task_defined?(:syntax)
    Rake::Task[:lint].invoke if Rake::Task.task_defined?(:lint)
    Rake::Task[:spec_prep].invoke if Rake::Task.task_defined?(:spec_prep)
    task.rspec_opts = ["--format", "documentation"]
    task.pattern = item
  end
end

namespace 'acceptance' do
  desc "Run acceptance tests in parallel"
  multitask :all_p => all_acc_tasks

  desc "Run acceptance tests sequentially"
  task :all do
    all_acc_tasks.each { |task| Rake::Task[task].invoke }
  end

  desc "Run Windows 10 tests"
  task :windows10 do
    ENV['BEAKER_set'] = 'windows10'
    sh "bundle exec rspec spec/acceptance/cis_security_hardening_windows_spec.rb"
  end

  desc "Run Windows 11 tests"
  task :windows11 do
    ENV['BEAKER_set'] = 'windows11'
    sh "bundle exec rspec spec/acceptance/cis_security_hardening_windows_spec.rb"
  end

  desc "Run Windows 10 and 11 tests in parallel"
  multitask :windows_p => [:windows10, :windows11]

  # desc "Run Windows 10 and 11 tests sequentially"
  # task :windows => [:windows10, :windows11]
end

desc "Run full test suite: metadata, syntax, lint, and spec."
task :test => [
  :metadata_lint,
  :syntax,
  :lint,
  :spec
]

def handle_beaker_provision
  bp = ENV['BEAKER_provision'] || 'yes'
  return unless bp.casecmp('no').zero?

  nodeset_name = ENV['BEAKER_set'] || 'default'
  logdir = File.join(Dir.pwd, "log", nodeset_name)
  last_logfile = Dir.glob("#{logdir}/**/*.*").max_by { |f| File.mtime(f) }
  return unless last_logfile

  nodenames = {}
  File.foreach(last_logfile) do |line|
    hostname, role = line.split.values_at(5, 6).map { |v| v&.gsub(/[()]/, '') }
    nodenames[role] = hostname if hostname && role
  end

  nodeset_dir = File.join(Dir.pwd, 'spec', 'acceptance', 'nodesets')
  nodeset_file = File.join(nodeset_dir, "#{nodeset_name}.yml")
  nodeset = YAML.load_file(nodeset_file)
  nodeset['HOSTS'] = nodeset['HOSTS'].transform_keys { |role| nodenames[role] || role }

  tmp_nodefile = Dir::Tmpname.create(['tmp_nodeset', '.yaml'], nodeset_dir) {}
  File.write(tmp_nodefile, nodeset.to_yaml)
  ENV['BEAKER_setfile'] = File.expand_path(tmp_nodefile)
  ENV.delete('BEAKER_set')

  CLEAN.include(FileList["#{nodeset_dir}/tmp_nodeset*.yaml"])
end

Rake::Task[:default].clear
task :default do
  puts "\nAvailable Rake tasks:\n\n"
  system("bundle exec rake --tasks")
end
