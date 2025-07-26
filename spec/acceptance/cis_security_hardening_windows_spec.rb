## references:
## https://github.com/puppetlabs/beaker/tree/master/lib/beaker
## https://github.com/voxpupuli/beaker/blob/master/docs/how_to/run_in_parallel.md
## https://relishapp.com/rspec/rspec-core/v/2-14/docs/example-groups/basic-structure-describe-it

require 'spec_helper_acceptance'
require 'parallel'

env_path = "/etc/puppetlabs/code/environments/#{ENVIRONMENT}"
overrides_file = "#{PROJECT_ROOT}/spec/acceptance/overrides.yaml"

# Load shared examples
Dir['./spec/acceptance/shared_examples/*.rb'].sort.each { |f| require f }

describe 'cis_security_hardening_windows acceptance testing' do
  context 'Configure the master and run puppet on agents' do
    print_stage('Adding agents and class to nodeset on Master')

    agents.each do |agent|
      pp = <<-SITE_PP
        node '#{agent.node_name}' {
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

    # Copy environment-specific overrides for acceptance testing
    if File.file?(overrides_file)
      print_stage('Copying environment specific hiera overrides from spec/acceptance/overrides.yaml to master')
      scp_to(master, overrides_file, "#{env_path}/data/overrides.yaml")
      on(master, "echo -e \"  - name: 'Override hiera'\\n    path: 'overrides.yaml'\" >> #{env_path}/hiera.yaml")
    end

    # Chown and chmod testing environment
    on(master, <<-SHELL)
      chown -R root:puppet #{env_path}
      chmod -R g+rX,o-rwX #{env_path}
    SHELL

    # Run puppet on agents
    print_stage('Running Puppet on agents')
    it_behaves_like 'run idempotently'
  end

  context 'Check if run in_parallel fix required' do
    agents.each do |agent|
      # The first test after in_parallel fails, so this overcomes that
      next unless agents.count > 1
      info_msg('This is an expected warning as connection is re-established after reboot')
      on(agent, 'waiting', reset_connection: true) # similar alternative is 'expect_connection_failure: true'
    end
  end

  context 'Run tests according to platform' do
    agents.each do |agent|
      case agent['platform']
      when %r{windows}
        context 'run tests on windows agent', node: agent do
          # Allow PowerShell scripts to run on windows host
          on(agent, [
            'powershell Set-ExecutionPolicy RemoteSigned',
            'powershell Get-ExecutionPolicy',
            'powershell Set-NetConnectionProfile -NetworkCategory private',
          ].join('; '))
          # Include test examples
          it_behaves_like 'windows tests', agent: agent
        end
      end
    end
  end
end
