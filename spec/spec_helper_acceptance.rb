## spec_helper_acceptance.rb
# frozen_string_literal: true

### ---------------- References ------------------- ###
# https://rdoc.info/gems/beaker-puppet/1.18.15/Beaker/DSL/InstallUtils/FOSSUtils
# https://github.com/puppetlabs/beaker-puppet/tree/master/lib/beaker-puppet
# https://www.rubydoc.info/github/puppetlabs/beaker/Beaker/Host
# https://github.com/puppetlabs/beaker-module_install_helper/blob/master/lib/beaker/module_install_helper.rb
# https://github.com/puppetlabs/beaker-puppet_install_helper/blob/master/lib/beaker/puppet_install_helper.rb
# https://www.rubydoc.info/gems/beaker/3.2.0/Beaker/DSL/InstallUtils/FOSSUtils#install_puppet_agent_on-instance_method
# https://www.rubydoc.info/gems/beaker/3.2.0/Beaker/OpenStack
# https://www.rubydoc.info/gems/beaker/Beaker/HostPrebuiltSteps
# https://github.com/puppetlabs/beaker/blob/master/docs/concepts/argument_processing_and_precedence.md
# https://www.rubydoc.info/gems/beaker/Beaker%2FDSL%2FWrappers:powershell
# https://github.com/puppetlabs/beaker-windows
# https://github.com/simp/rubygem-simp-beaker-helpers

# Patch occurences of file.exists with file.exist for ruby > 3.x
class File
  class << self
    alias_method :exists?, :exist?
  end
end

### ---------------- Gems Required ------------------- ###
require 'serverspec'                    # Base Serverspec framework
require 'beaker-rspec'                  # Beaker integration with RSpec and Serverspec
# require 'beaker/module_install_helper'  # Helper to install module and dependencies
require 'beaker_puppet_helpers'         # Additional Puppet-related helpers for Beaker
require 'rainbow'                       # Add color to console printed text

### ---------------- Set Variables ------------------- ###
PROJECT_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..'))
METADATA_PATH = File.join(PROJECT_ROOT, 'metadata.json'); raise "metadata.json missing at #{METADATA_PATH}" unless File.exist?(METADATA_PATH)

@metadata_json = JSON.parse(File.read(METADATA_PATH))
CLASS = @metadata_json['name'].tr('-', '::').freeze

TEST_FILES = File.expand_path(File.join(File.dirname(__FILE__), 'acceptance', 'files'))
DEPENDENCY_LIST = 'fixtures'.freeze

# Dirs to rsync to master for testing
FILES_TO_COPY = "data/ manifests/ files/ lib/ ./hiera.yaml ./metadata.json"

# Safer: prefer hostname -I and filter loopback/APIPA so multiple addresses don't break parsing
MASTER_IP = on(master, "hostname -I | tr ' ' '\\n' | grep -vE '^(127|169)\\.' | head -n1").stdout.strip # master.get_ip
MASTER_FQDN = on(master, 'hostname').stdout.strip # master.node_name

## Set unique environment variable if static-master, otherwise use production
ENVIRONMENT = if master['hypervisor'] == 'none'
                agents[0].hostname
              else
                'production'
              end

## Configuration
CONFIG = {
  release_yum_repo_url: 'https://yum.voxpupuli.org/openvox8-release-el-10.noarch.rpm',
  server_package_name: 'openvox-server',
  agent_package_name: 'openvox-agent',
  puppet_collection: 'openvox8',
  puppet_agent_service: 'puppet',
  puppet_agent_version: ENV['PUPPET_AGENT_VERSION'] || 'latest',
  puppetserver_version: ENV['PUPPETSERVER_VERSION'] || 'latest',
}.freeze

ALL_DEPS = []

### ---------------- Define Functions ------------------- ###
## Print stage headings
def print_stage(header)
  separator = Rainbow('-' * 100).green
  puts "\n\n#{separator}\n#{Rainbow(header).cyan}\n#{separator}\n"
end

# Color info message
def info_msg(text)
  # fallback to plain text if Rainbow fails for any reason
  begin
    puts "\n#{Rainbow(text).cyan}\n"
  rescue StandardError
    puts "\n#{text}\n"
  end
end

# Get agent ip and fqdn
def get_ip_and_fqdn(host)
  if host['platform'] =~ %r{windows}i
    ip = on(host, "powershell -Command \"(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^169\\.' -and $_.IPAddress -notmatch '^127\\.' } | Select-Object -First 1).IPAddress\"").stdout.strip
    fqdn = on(host, "powershell -Command \"[System.Net.Dns]::GetHostEntry('localhost').HostName\"").stdout.strip
  else
    # Safer Linux IP extraction: hostname -I then filter
    ip = on(host, "hostname -I | tr ' ' '\\n' | grep -vE '^(127|169)\\.' | head -n1").stdout.strip
    fqdn = on(host, 'hostname').stdout.strip
  end
  [ip, fqdn]
end

## As each dependency is installed from fixtures, add the latest version to an array
## (uses the 5th line of output so that only primary dependencies are written to metadata.json)
def compile_dependency_versions(output)
  dep_line = output.lines[4]&.split
  return if dep_line.nil? || dep_line.size < 3
  dep_name = dep_line[1]
  dep_ver = dep_line[2][9..-6] if dep_line[2] && dep_line[2].length > 14
  ALL_DEPS.push({ dep_name: dep_name, dep_ver: dep_ver }) if dep_name && dep_ver
end

## Update dependencies in metadata
def write_metadata_dot_json(dependencies)
  # Group dependencies by name and select the highest version
  unique_dependencies = dependencies.group_by { |dep| dep[:dep_name] }
                                    .map { |_name, deps| deps.max_by { |dep| dep[:dep_ver] } }
                                    .sort_by { |dep| dep[:dep_name] }

  dependencies = unique_dependencies.map do |dep|
    next if dep[:dep_name].match?(%r{puppetlabs-.*_core})

    # Construct dependency hash based on version locking requirements
    version_req = if ['puppetlabs-example1', 'puppetlabs-example2'].include?(dep[:dep_name])
                    dep[:dep_ver].to_s
                  else
                    ">= #{dep[:dep_ver]} < #{dep[:dep_ver].to_i + 1}.0.0"
                  end
    { 'name' => dep[:dep_name], 'version_requirement' => version_req }
  end.compact

  # Merge with existing dependencies to avoid wiping unrelated entries
  existing = @metadata_json['dependencies'] || []
  filtered_existing = existing.reject { |dep| dependencies.any? { |new_dep| new_dep['name'] == dep['name'] } }
  @metadata_json['dependencies'] = filtered_existing + dependencies

  # Write the updated JSON to metadata.json with trailing newline
  File.write(METADATA_PATH, JSON.pretty_generate(@metadata_json) + "\n")
end

## Stop firewall
def stop_firewall_on(host)
  case host['platform']
  when %r{debian}
    on host, 'iptables -F', acceptable_exit_codes: [0, 1]
  when %r{fedora|el-|centos}
    on(host, 'puppet resource service firewalld ensure=stopped', acceptable_exit_codes: [0, 1])
  when %r{debian}
    on(host, 'puppet resource service ufw ensure=stopped', acceptable_exit_codes: [0, 1])
  else
    logger.notify("Not sure how to clear firewall on #{host['platform']}")
  end
end

## Install Puppetserver
def install_puppetserver(host)
  info_msg("Installing #{CONFIG[:server_package_name]} on #{host}")
  on(master, "echo -e 'minrate=5\ntimeout=500' >> /etc/yum.conf")
  on(master, "yum install -y #{CONFIG[:release_yum_repo_url]}")
  on(master, "yum install -y #{CONFIG[:server_package_name]}")
  # install_puppetlabs_release_repo(master, CONFIG[:puppet_collection], CONFIG[release_yum_repo_url])
  # install_puppetserver_on(master, version: CONFIG['puppetserver_version'], puppet_collection: CONFIG[:puppet_collection])
end

## Setup Puppet agent on windows
def setup_puppet_on(host)
  agents.each do |agent|
    agent_ip, agent_fqdn = get_ip_and_fqdn(agent)
    print_stage("Configuring agent at #{agent_ip} #{agent_fqdn}")
    case agent['platform']
    when %r{windows}i
      # Set network profile to private
      info_msg("Setting network profile to private on #{agent_fqdn}")
      on(agent, powershell('Set-NetConnectionProfile -NetworkCategory private'))

      # Disable Windows Update service for testing on Windows agents
      info_msg("Disabling Windows Update service to prevent updates during testing on #{agent_fqdn}")
      on(agent, powershell('Set-Service wuauserv -StartupType Disabled'))
      on(agent, powershell("taskkill /f /t /fi 'SERVICES eq wuauserv'"), acceptable_exit_codes: [0, 1])
      on(agent, powershell('Stop-Service wuauserv -Force'), acceptable_exit_codes: [0, 1])

      # Install puppet-agent if not already installed
      info_msg("Checking if Puppet or Openvox agent is installed on #{agent_fqdn}")
      unless on(agent, powershell("if((gp HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*).DisplayName -Match 'Puppet Agent^|OpenVox Agent \\(64-bit\\)') {exit 0} else {exit 1}")).exit_code.zero?
        on(agent, powershell('Invoke-WebRequest https://artifacts.voxpupuli.org/downloads/windows/openvox8/openvox-agent-8.19.2-x64.msi -OutFile c:\\openvox-agent-8.19.2-x64.msi; Start-Process msiexec -ArgumentList \'/qn /norestart /i c:\\openvox-agent-8.19.2-x64.msi\' -Wait'))
      end

      # Configure Puppet agent settings
      # on(agent, powershell("Set-Content -path c:\\ProgramData\\PuppetLabs\\puppet\\etc\\puppet.conf -Value \"[agent]`r`nserver=#{MASTER_FQDN}`r`nenvironment=#{ENVIRONMENT}\""))
      info_msg("Configuring puppet agent.conf and add host entry for master on #{agent_fqdn}")
      on(agent, powershell("puppet config set server #{MASTER_FQDN} --section agent; puppet config set environment #{ENVIRONMENT} --section agent"))
      on(agent, powershell("Add-Content -path c:\\windows\\system32\\drivers\\etc\\hosts -Value \"#{MASTER_IP}`t#{MASTER_FQDN}\""))

      # Disable the Puppet service for manual runs only
      info_msg("Disabling Puppet service so only manual runs occur on #{agent_fqdn}")
      on(agent, powershell('Set-Service puppet -StartupType Disabled; Stop-Service puppet -Force'))
    else
      info_msg('This module only support Windows agents')
    end
  end
end

## Setup Puppetserver
def setup_puppetserver_on(host)
  print_stage("Configuring master at #{MASTER_IP} #{MASTER_FQDN} #{host}")
  # Set class under test to console display. Requires restart of tty1 serivce to display without logon or reboot
  agent_names = agents.map { |a| "#{a['roles'].first.gsub('agent_', '').ljust(20)}#{a.node_name.ljust(30)}#{a.ip.ljust(40)}" }.join("\n")
  master_info = "#{master['roles'].first.ljust(20)}#{MASTER_FQDN.ljust(30)}#{MASTER_IP.ljust(40)}"
  message = <<~MSG
    You are running an acceptance test of \e[1;32m#{CLASS}\e[0m

    from this MASTER
    \e[1;34m#{master_info}\e[0m

    to AGENTS
    \e[1;36m#{agent_names}\e[0m
  MSG
  on(host, "echo -e '#{message}' | tee /etc/motd /etc/issue")
  on host, 'systemctl restart getty@tty1'
  # Set puppetserver options
  host['type'] = 'aio'
  options['is_puppetserver'] = true
  master['puppetservice'] = 'puppetserver'
  master['puppetserver-confdir'] = '/etc/puppetlabs/puppetserver/conf.d'
  master['type'] = 'aio'
  # Check if puppetserver package installed, if not install it
  result = on(master, "rpm -qa | grep -E 'puppetserver|openvox-server'", acceptable_exit_codes: [0, 1])
  install_puppetserver(master) if result.exit_code == 1
  # Set the puppetserver to know it is its own master, so commands like 'puppetserver ca list' work
  on(master, 'puppet config set server `hostname`')
  # Create folder for module and install dependencies
  on(master, "install -d -o puppet -g puppet /etc/puppetlabs/code/environments/#{ENVIRONMENT}/{modules,data,manifests}")
  install_modules_on master
  # Generate puppet types on master to overcome issue with some windows types on initial runs
  on(master, "/opt/puppetlabs/puppet/bin/puppet generate types --environment #{ENVIRONMENT}")
  on(master, 'puppet resource service puppetserver ensure=running')
  # Enable autosign on the master
  on(master, "echo '*' > /etc/puppetlabs/puppet/autosign.conf")
  # Stop firewall on master
  stop_firewall_on master
end

## Copy test module and install dependencies on Puppetserver
def install_modules_on(host)
  info_msg("Copying module and installing dependencies on master at #{MASTER_IP} #{MASTER_FQDN}")
  install_dependencies_from DEPENDENCY_LIST

  # Copy only required files to the master for testing
  info_msg("Copying required module files to master at #{MASTER_IP} #{MASTER_FQDN}")
  system("rsync -avR #{FILES_TO_COPY} root@#{MASTER_IP}:/etc/puppetlabs/code/environments/production/modules/cis_security_hardening_windows") || (raise "rsync failed")
               
  on(master, "echo -e 'modulepath = /etc/puppetlabs/code/environments/#{ENVIRONMENT}/modules' > /etc/puppetlabs/code/environments/#{ENVIRONMENT}/environment.conf")
  on(master, 'puppet module list --tree')
end

## Determine and install dependencies from either .fixtures or metadata.json
def install_dependencies_from(list)
  puts "\n#{Rainbow("#{list} selected to determine dependencies").cyan}\n\n"
  file_path = case list
              when 'fixtures' then File.join(PROJECT_ROOT, '.fixtures.yml')
              when 'metadata' then File.join(PROJECT_ROOT, 'metadata.json')
              else
                raise ArgumentError, "Invalid dependency list source: #{list.inspect}"
              end

  return unless File.exist?(file_path)

  dependencies = if list == 'fixtures'
                   begin
                     yaml_content = File.read(file_path, encoding: 'UTF-8')
                     parsed_yaml = YAML.safe_load(yaml_content, permitted_classes: [Hash, Array], aliases: true)
                     parsed_yaml.fetch('fixtures', {}).fetch('forge_modules', []).map do |dep|
                       {
                         name: dep[1].is_a?(Hash) ? dep[1]['repo'].tr('/', '-') : dep[1].tr('/', '-'),
                         version: dep[1].is_a?(Hash) ? dep[1]['ref'] : nil
                       }
                     end
                   rescue Psych::SyntaxError => e
                     raise "YAML parsing error in #{file_path}: #{e.message}"
                   end
                 else
                   begin
                     JSON.parse(File.read(file_path, encoding: 'UTF-8')).fetch('dependencies', []).map do |dep|
                       {
                         name: dep['name'].tr('/', '-'),
                         version: dep.key?('version_requirement') ? module_version_from_requirement(dep['name'], dep['version_requirement']) : nil
                       }
                     end
                   rescue JSON::ParserError => e
                     raise "JSON parsing error in #{file_path}: #{e.message}"
                   end
                 end

  dependencies.each do |dep|
    version_flag = dep[:version] ? "--version #{dep[:version]}" : ''
    on(master, "puppet module install #{dep[:name]} #{version_flag} --environment #{ENVIRONMENT} --vardir /etc/puppetlabs/code/environments/#{ENVIRONMENT}/tmp/", acceptable_exit_codes: [0]) do |result|
      compile_dependency_versions(result.stdout) if ENVIRONMENT == 'production' && list == 'fixtures'
    end
  end

  write_metadata_dot_json(ALL_DEPS) if ENVIRONMENT == 'production' && list == 'fixtures'
rescue KeyError => e
  raise "Dependencies can only be determined from fixtures or metadata. You selected #{list} - Error: #{e.message}"
end

### ---------------- Call Functions ------------------- ###
unless ENV['BEAKER_provision'] == 'no'
  # Message if the test is run on a gitlab runner or not
  if ENV['GITLAB_CI']
    info_msg('Running in GitLab CI pipeline')
  else
    info_msg('Running locally on developer machine')
  end

  setup_puppetserver_on(master)
  setup_puppet_on(agents)
end

RSpec.configure do |c|
  # Readable test descriptions
  c.formatter = :documentation
  # Actions before suite
  c.before :suite do
  end
  # Actions after suite
  c.after :suite do
    if master['hypervisor'] == 'none'
      print_stage("Cleaning up static-master at #{MASTER_IP} #{MASTER_FQDN}")
      # Delete accumulating lines in sshd_conf and /etc/hosts when reusing master
      on(master, "sed -i '/PermitUserEnvironment yes/d' /etc/ssh/sshd_config")
      on(master, "echo -e \"127.0.0.1\tlocalhost localhost.localdomain\n#{MASTER_IP}\t#{MASTER_FQDN}\" > /etc/hosts")
      unless ENV['BEAKER_destroy'] == 'no'
        # Clean up environment and certificates when using static-master
        on(master, "find /etc/puppetlabs/code/environments/#{ENVIRONMENT} ! -name production -type d -exec rm -rf {} +")
        agents.each do |agent|
          on(master, "/opt/puppetlabs/bin/puppetserver ca clean --certname #{agent.node_name}")
        end
      end
    end
    agents.each do |agent|
      agent_ip, agent_fqdn = get_ip_and_fqdn(agent)
      print_stage("Completed tests on agent #{agent_ip} #{agent_fqdn} using master #{MASTER_IP} #{MASTER_FQDN}")
    end
  end
end