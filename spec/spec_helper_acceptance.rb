## spec_helper_acceptance.rb

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

### ---------------- Gems Required ------------------- ###
# require_relative 'beaker-openstack'
require 'beaker-puppet'
require 'beaker-rspec/spec_helper'
require 'beaker-rspec/helpers/serverspec'
require 'serverspec'
require 'beaker/module_install_helper'

### ---------------- Set Variables ------------------- ###
## Set unique environment variable if static-master, otherwise use production
CLASS = 'canihavethisone/cis_security_hardening_windows'.freeze
MASTER_IP = master.get_ip
MASTER_FQDN = master.node_name
PROJECT_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..'))
TEST_FILES = File.expand_path(File.join(File.dirname(__FILE__), 'acceptance', 'files'))
DEPENDENCY_LIST = 'fixtures'.freeze
ENVIRONMENT = if master['hypervisor'] == 'none'
                agents[0].hostname
              else
                'production'
              end

## Configuration
CONFIG = {
  puppet_agent_version: ENV['PUPPET_AGENT_VERSION'] || '7.27.0',
  puppetserver_version: ENV['PUPPETSERVER_VERSION'] || '7.14.0',
  puppet_collection: 'puppet7',
  puppet_agent_service: 'puppet',
}.freeze

ALL_DEPS = []

# DOMAIN           = fact_on(master, 'domain')
# master_domain    = master.node_name.split('.', 2)[1]
# agent_domain     = agent.node_name.split('.', 2)[1]

### ---------------- Define Functions ------------------- ###
## Print stage headings
def print_stage(h)
  puts "\n\n"
  puts "\e[0;32m-------------------------------------------------------------------------------------------\e[0m"
  puts "\e[0;36m#{h}\e[0m"
  puts "\e[0;32m-------------------------------------------------------------------------------------------\e[0m"
  puts "\n"
end

## As each dependency is installed from fixtures, add the latest version to an array (uses the 5th line of output so that only primary dependencies are written to metadata.json
def compile_dependency_versions(output)
  dep_arr = output.lines[4]&.split(' ')
  ALL_DEPS.push({ dep_name: dep_arr[1], dep_ver: dep_arr[2][9..-6] }) unless dep_arr.nil?
end

## Update dependencies in metadata
def write_metadata_dot_json(dependencies)
  dep_set = []
  metadata = File.read(PROJECT_ROOT + '/metadata.json')
  return unless metadata
  metadata_json = JSON.parse(metadata)
  metadata_json['dependencies'] = []
  dependencies.each do |dep|
    matches = dep_set.select do |elem|
      elem[:dep_name] == dep[:dep_name]
    end
    if matches.empty?
      dep_set.push(dep)
    elsif dep[:dep_ver] > matches[0][:dep_ver]
      dep_set[dep_set.index matches[0]] = dep
    end
  end
  dep_set = dep_set.sort_by { |dep| dep[:dep_name] }
  dep_set.each do |dep|
    # Hard locked Puppet modules - specify here if version locked in fixtures
    dep_hash = if ['puppetlabs-example1', 'puppetlabs-example2'].include?(dep[:dep_name])
                 { "name": dep[:dep_name],
                 "version_requirement": (dep[:dep_ver]).to_s }
               else
                 { "name": dep[:dep_name],
                 # Add upper version
                 "version_requirement": ">= #{dep[:dep_ver]} < #{dep[:dep_ver].to_i + 1}.0.0" }
               end
    metadata_json['dependencies'].push(dep_hash) unless dep[:dep_name].match?(%r{puppetlabs-.*_core})
  end
  File.open('metadata.json', 'w+') do |f|
    f.write(JSON.pretty_generate(JSON.parse(metadata_json.to_json)))
  end
end

## Stop firewall
def stop_firewall_on(host)
  case host['platform']
  when %r{debian}
    on host, 'iptables -F'
  when %r{fedora|el-|centos}
    on host, puppet('resource', 'service', 'firewalld', 'ensure=stopped')
  when %r{ubuntu}
    on host, puppet('resource', 'service', 'ufw', 'ensure=stopped')
  else
    logger.notify("Not sure how to clear firewall on #{host['platform']}")
  end
end

## Install Puppet agent
def install_puppet_agent(agent)
  print_stage("Installing Puppet agent on #{agent}")
  configure_type_defaults_on(agent)
  on(master, "echo -e 'minrate=5\ntimeout=500' >> /etc/yum.conf")
  install_puppetlabs_release_repo(agent, CONFIG[:puppet_collection])
  install_puppet_agent_on(agent, puppet_agent_version: CONFIG[:puppet_agent_version], puppet_collection: CONFIG[:puppet_collection])
end

## Agent options
def agent_opts(_host)
  {
    main: { color: 'ansi' },
    agent: { ssldir: '$vardir/ssl', server: MASTER_FQDN, environment: ENVIRONMENT },
  }
end

def puppet_conf(host)
  if host['platform'].include? 'windows'
    'C:/ProgramData/PuppetLabs/puppet/etc/puppet.conf'
  else
    '/etc/puppetlabs/puppet/puppet.conf'
  end
end

def package_name(host)
  if host['platform'].include? 'windows'
    'Puppet Agent*'
  else
    'puppet-agent'
  end
end

## Install Puppetserver
def install_puppetserver(host)
  print_stage("Installing Puppetserver on #{host}")
  configure_type_defaults_on host
  on(master, "echo -e 'minrate=5\ntimeout=500' >> /etc/yum.conf")
  install_puppetlabs_release_repo(master, CONFIG[:puppet_collection])
  install_puppetserver_on(master, version: CONFIG['puppetserver_version'], puppet_collection: CONFIG[:puppet_collection])
end

## Setup Puppet agent on el-|centos or windows
def setup_puppet_on(_host, opts = {})
  opts = { agent: true }.merge(opts)
  return unless opts[:agent]
  agents.each do |agent|
    agent_fqdn = agent.node_name
    print_stage("Configuring agent at #{agent.get_ip} #{agent_fqdn}")
    # on(agent, puppet('resource', 'host', MASTER_FQDN, 'ensure=present', "ip=#{MASTER_IP}"))
    agent['type'] = 'aio'
    puppet_opts = agent_opts(master.to_s)
    ## On el- or centos
    case agent['platform']
    when %r{el-|centos}
      ## Set class under test to console display. Requires restart of tty1 serivce to display without logon or reboot
      on(agent, "echo -e 'You are running an acceptance test of \e[1;32m#{CLASS}\e[0m\n\non this AGENT\t\e[1;36m#{agent_fqdn}\t#{agent.ip}\e[0m\nfrom MASTER\t\e[1;34m#{MASTER_FQDN}\t#{MASTER_IP}\e[0m\n\n' | tee /etc/motd /etc/issue")
      on(agent, 'systemctl restart getty@tty1')
      ## Check if puppet-agent is installed, otherwise install it
      result = on(agent, 'rpm -qa | grep puppet-agent', acceptable_exit_codes: [0, 1])
      if result.exit_code == 1
        install_puppet_agent agent
      end
      configure_puppet_on(agent, puppet_opts)
      stop_firewall_on agent
      print_stage("Disabling Puppet service so only manual runs occur on #{agent_fqdn}")
      on(agent, 'systemctl disable puppet --now', acceptable_exit_codes: [0])
      on(agent, "echo '#{MASTER_IP} #{MASTER_FQDN}' >> /etc/hosts")
    ## On windows
    when %r{windows}
      print_stage("Disabling Windows Update service to prevent updates during testing on #{agent_fqdn}")
      ## Disable and force kill Windows Update service if running
      on(agent, powershell('Set-Service wuauserv -StartupType Disabled'))
      on(agent, powershell("taskkill /f /t /fi 'SERVICES eq wuauserv'"), acceptable_exit_codes: [0, 1])
      on(agent, powershell('Stop-Service wuauserv -Force'), acceptable_exit_codes: [0, 1])
      ## Check if puppet-agent is installed, otherwise install it
      result = on(agent, powershell('if((gp HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*).DisplayName -Match \'Puppet Agent\') {exit 0} else {exit 1}'))
      if result.exit_code == 1
        on(agent, powershell('Invoke-WebRequest https://downloads.puppetlabs.com/windows/puppet7/puppet-agent-x64-latest.msi -OutFile c:\\puppet-agent-x64-latest.msi; Start-Process msiexec -ArgumentList \'/qn /norestart /i c:\\puppet-agent-x64-latest.msi\' -Wait'))
      end
      # Configure_puppet_on(agent, puppet_opts)
      on(agent, powershell("Set-Content -path c:\\ProgramData\\PuppetLabs\\puppet\\etc\\puppet.conf -Value \"[agent]`r`nserver=#{MASTER_FQDN}`r`nenvironment=#{ENVIRONMENT}\""))
      print_stage("Disabling Puppet service so only manual runs occur on #{agent_fqdn}")
      on(agent, powershell('Set-Service puppet -StartupType Disabled; Stop-Service puppet -Force'))
      on(agent, powershell("Add-Content -path c:\\windows\\system32\\drivers\\etc\\hosts -Value \"#{MASTER_IP}`t#{MASTER_FQDN}\""))
    end
  end
  on(master, "echo '*' > /etc/puppetlabs/puppet/autosign.conf")
end

## Setup Puppetserver
def setup_puppetserver_on(host, _opts = {})
  # opts = { master => true, agent: false }.merge(opts)
  print_stage("Configuring master at #{MASTER_IP} #{MASTER_FQDN} #{host}")
  ## Set the puppetserver to know it is its own master, so commands like 'puppetserver ca list' work
  on(master, 'puppet config set server `hostname`')
  ## Set class under test to console display. Requires restart of tty1 serivce to display without logon or reboot
  agent_names = agents.map do |agent|
    "#{agent['roles'].first.gsub('agent_', '').ljust(20)}#{agent.node_name.ljust(30)}#{agent.ip.ljust(40)}"
  end
  on host, "echo -e 'You are running an acceptance test of \e[1;32m#{CLASS}\e[0m\n\nfrom this MASTER\n\e[1;34m#{master['roles'].first.ljust(20)}#{MASTER_FQDN.ljust(30)}#{MASTER_IP.ljust(40)}\e[0m\n\nto AGENTS\n\e[1;36m#{agent_names.join("\n")}\e[0m\n\n' | tee /etc/motd /etc/issue"
  on host, 'systemctl restart getty@tty1'
  ## Create folder for module and dependencies
  on(master, "install -d -o puppet -g puppet /etc/puppetlabs/code/environments/#{ENVIRONMENT}/{modules,data,manifests}")
  host['type'] = 'aio'
  options['is_puppetserver'] = true
  master['puppetservice'] = 'puppetserver'
  master['puppetserver-confdir'] = '/etc/puppetlabs/puppetserver/conf.d'
  master['type'] = 'aio'
  result = on(master, 'rpm -qa | grep puppetserver', acceptable_exit_codes: [0, 1])
  if result.exit_code == 1
    install_puppetserver master
  end
  install_modules_on master
  ## Generate puppet types on master to overcome issue with some windows types on initial runs
  on(master, "/opt/puppetlabs/puppet/bin/puppet generate types --environment #{ENVIRONMENT}")
  on master, puppet('resource', 'service', 'puppetserver', 'ensure=running')
  stop_firewall_on master
end

## Copy test module and install dependencies on Puppetserver
def install_modules_on(host)
  print_stage("Copying module and installing dependencies on master at #{MASTER_IP} #{MASTER_FQDN}")
  install_dependencies_from DEPENDENCY_LIST
  copy_module_to(host, source: PROJECT_ROOT, target_module_path: "/etc/puppetlabs/code/environments/#{ENVIRONMENT}/modules/", protocol: 'rsync')
  on(master, "echo -e 'modulepath = /etc/puppetlabs/code/environments/#{ENVIRONMENT}/modules' > /etc/puppetlabs/code/environments/#{ENVIRONMENT}/environment.conf")
  on(master, 'puppet module list --tree')
end

## Determine and install dependencies
def install_dependencies_from(list)
  puts "\e[0;36m \n#{list} selected as list to determine dependencies \e[0m\n\n"
  if list == 'fixtures'
    ## Determine dependencies from .fixtures
    file = File.read(PROJECT_ROOT + '/.fixtures.yml')
    return unless file
    metadata = YAML.load_file(PROJECT_ROOT + '/.fixtures.yml')
    metadata['fixtures']['forge_modules'].each do |dependency|
      if dependency[1].instance_of? Hash
        dep_name = dependency[1]['repo'].sub(%r{/\//}, '-')
        dep_version = "--version #{dependency[1]['ref']}"
      else
        dep_name = dependency[1].sub(%r{/\//}, '-')
      end
      ## Install dependencies.  Environment and vardir are dynamically set to avoid modules being cleaned by concurrent tests
      on(master, "puppet module install #{dep_name} #{dep_version} --environment #{ENVIRONMENT} --vardir /etc/puppetlabs/code/environments/#{ENVIRONMENT}/tmp/", { acceptable_exit_codes: [0] }) do |result|
        if ENVIRONMENT == 'production'
          compile_dependency_versions(result.stdout)
        end
      end
    end
    # Update metadata.json with the latest installed dependencies unless static master in use with multiple environments
    if ENVIRONMENT == 'production'
      write_metadata_dot_json(ALL_DEPS)
    end
  elsif list == 'metadata'
    ## Determine dependencies from metadata.json
    file = File.read(PROJECT_ROOT + '/metadata.json')
    return unless file
    metadata = JSON.parse(File.read(PROJECT_ROOT + '/metadata.json'))
    return [] unless metadata.key?('dependencies')
    dependencies = []
    puts "\e[0;36m \nSourcing puppet modules from #{forge_api} \e[0m\n\n"
    metadata['dependencies'].each do |d|
      tmp = { module_name: d['name'].sub('/', '-') }
      if d.key?('version_requirement')
        tmp[:version] = module_version_from_requirement(tmp[:module_name], d['version_requirement'])
      end
      dependencies.push(tmp)
    end
    dependencies.each do |dep|
      dep_name = dep[:module_name]
      dep_version = "--version #{dep[:version]}"
      ## Install dependencies.  Environment and vardir are dynamically set to avoid modules being cleaned by concurrent tests
      on(master, "puppet module install #{dep_name} #{dep_version} --environment #{ENVIRONMENT} --vardir /etc/puppetlabs/code/environments/#{ENVIRONMENT}/tmp/", { acceptable_exit_codes: [0] })
    end
  else
    raise "Dependencies can only be determined from fixtures or metadata.  You selected #{list}"
  end
end

### ---------------- Call Functions ------------------- ###
unless ENV['BEAKER_provision'] == 'no'
  setup_puppetserver_on(master)
  setup_puppet_on(agents)
end

RSpec.configure do |c|
  ## Readable test descriptions
  c.formatter = :documentation
  ## Actions before suite
  c.before :suite do
  end
  ## Actions after suite
  c.after :suite do
    if master['hypervisor'] == 'none'
      print_stage("Cleaning up static-master at #{MASTER_IP} #{MASTER_FQDN}")
      ## Delete accumulating lines in sshd_conf and /etc/hosts when reusing master
      on(master, "sed -i '/PermitUserEnvironment yes/d' /etc/ssh/sshd_config")
      on(master, "echo -e \"127.0.0.1\tlocalhost localhost.localdomain\n#{MASTER_IP}\t#{MASTER_FQDN}\" > /etc/hosts")
      unless ENV['BEAKER_destroy'] == 'no'
        ## Clean up environment and certificates when using static-master
        on(master, "find /etc/puppetlabs/code/environments/#{ENVIRONMENT} ! -name production -type d -exec rm -rf {} +")
        agents.each do |agent|
          on(master, "/opt/puppetlabs/bin/puppetserver ca clean --certname #{agent.node_name}")
        end
      end
    end
  end
end
