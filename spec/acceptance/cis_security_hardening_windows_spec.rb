## references:
## https://github.com/puppetlabs/beaker/tree/master/lib/beaker
## https://github.com/voxpupuli/beaker/blob/master/docs/how_to/run_in_parallel.md
## https://relishapp.com/rspec/rspec-core/v/2-14/docs/example-groups/basic-structure-describe-it

require 'spec_helper_acceptance'
require 'parallel'

env_path = "/etc/puppetlabs/code/environments/#{ENVIRONMENT}"
# agent = only_host_with_role(hosts, 'agent')

# Load shared examples
Dir['./spec/acceptance/shared_examples/*.rb'].sort.each { |f| require f }

describe 'cis_security_hardening_windows acceptance testing' do
  context 'Configure the master and run puppet on agents' do
    print_stage('Adding agents and class to nodeset on Master')
    agents.each do |agent|
      pp = <<-SITE_PP
        node '#{agent.node_name}' {
          #class { 'cis_security_hardening_windows': }
          exec { 'set_network_profile':
            command  => 'Set-NetConnectionProfile -NetworkCategory private',
            unless   => 'if (Get-NetConnectionProfile | select NetworkCategory -ExpandProperty NetworkCategory | Select-String -Pattern private) { exit 0 } else { exit 1 }',
            provider => powershell,
          }
          include cis_security_hardening_windows
        }
      SITE_PP
      on(master, "echo -e \"#{pp}\" >> #{env_path}/manifests/site.pp")
    end

    # Copy environment specific overrides for acceptance testing
    if File.file?("#{PROJECT_ROOT}/spec/acceptance/overrides.yaml")
      print_stage('Copying environment specific hiera overrides from spec/acceptance/overrides.yaml to master')
      scp_to(master, "#{PROJECT_ROOT}/spec/acceptance/overrides.yaml", "/etc/puppetlabs/code/environments/#{ENVIRONMENT}/data/overrides.yaml")
      on(master, "echo -e \"  - name: 'Override hiera'\\n    path: 'overrides.yaml'\" >> /etc/puppetlabs/code/environments/#{ENVIRONMENT}/hiera.yaml")
    end

    # Chown and chmod testing environment
    on(master, "chown -R root:puppet #{env_path}")
    on(master, "chmod -R g+rX,o-rwX #{env_path}")

    # Run puppet on agents
    print_stage('Running Puppet on agents')
    include_examples 'run idempotently'
  end

  context 'Check if run in_parallel fix required' do
    agents.each do |agent|
      # The first test after in_parallel fails, so this overcomes that
      next unless agents.count > 1
      on(agent, 'This is an expected warning as connection is re-established after reboot', reset_connection: true) # similar alternative is 'expect_connection_failure: true'
    end
  end

  context 'Run tests according to platform' do
    agents.each do |agent|
      case agent['platform']
      # Run tests on Windows hosts
      when %r{windows}
        context 'run tests on windows agent', node: agent do
          # Allow PowerShell scripts to run on windows host, and include examples
          on(agent, 'powershell Set-ExecutionPolicy RemoteSigned')
          on(agent, 'powershell Get-ExecutionPolicy')
          # Set network zone to private to allow ssh connections etc
          on(agent, 'powershell Set-NetConnectionProfile -NetworkCategory private')
          include_examples 'windows tests', agent: agent, _agent_ip: agent.get_ip
        end
      end
    end
  end
end
