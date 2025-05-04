require 'spec_helper'
require 'parallel_tests'

describe 'cis_security_hardening_windows' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      if facts[:os]['family'] == 'windows'
        case facts[:os]['release']['major']
        when '10'
          let(:facts) do
            facts.merge(
              windows: {
                release: '10'
              },
            )
          end
        when '11'
          let(:facts) do
            facts.merge(
              windows: {
                release: '11'
              },
            )
          end
        end

        ### Test expected failure by including hiera testcase with params unset
        context 'Without required values declared' do
          let(:facts) do
            super().merge(
              testcase: 'missing_data',
            )
          end

          # Write out catalogue
          # it { File.write("cis_security_hardening_windows_failure_catalog_dump_#{os}.json", JSON.pretty_generate(catalogue.to_resource)) }

          # fail tp compile with deps
          # it { pp catalogue.resources }
          it { is_expected.not_to compile.with_all_deps }
          it { is_expected.to raise_error(%r{The following parameters must be defined:\nlogon_banner\nlogon_message\nadministrator_newname\nadministrator_newpassword\ndisabled_guest_newname}) }
        end

        ### Test all defaults by including hiera testcase with minimum required additional data
        context 'With defaults' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          # Write out catalogue
          # it { File.write('cis_security_hardening_windows_defaults_catalog_dump.json', JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.not_to contain_class('cis_security_hardening_windows::remote_desktop') }

          ## Users
          users = ['Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount']
          users.each do |name|
            it do
              is_expected.not_to contain_user(name)
            end
          end

          # Local Security Policy
          it do
            is_expected.to contain_local_security_policy('Accounts: Administrator account status').with(
              'policy_value' => '0',
            )
          end

          # Resources
          it do
            is_expected.to contain_resources('user')
          end

          ## Execs
          execs = ['grouppolicy dir attributes']
          execs.each do |name|
            it do
              is_expected.to contain_exec(name)
            end
          end

          ## Reboot
          it do
            is_expected.to contain_reboot('after_run')
          end
        end

        context 'With misc options enabled' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'catalog_no_cache' => true,
              'performance_powerscheme' => true,
              'clear_temp_files' => true,
              'enable_administrator' => true,
              'purge_unmanaged_users' => true, }
          end
          # Write out catalogue
          # it { File.write('cis_security_hardening_windows_misc_catalog_dump.json', JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.not_to contain_class('cis_security_hardening_windows::remote_desktop') }

          ## Users
          users = ['Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'User']
          users.each do |name|
            it do
              is_expected.to contain_user(name)
            end
          end

          # Local Security Policy
          it do
            is_expected.to contain_local_security_policy('Accounts: Administrator account status').with(
              'policy_value' => '1',
            )
          end

          ## Execs
          execs = ['clear_user_temp', 'clear_windows_temp', 'grouppolicy dir attributes', 'power_scheme_high']
          execs.each do |name|
            it do
              is_expected.to contain_exec(name)
            end
          end

          ## Tidy
          it do
            is_expected.to contain_tidy('delete puppet catalog')
          end

          ## Ini_setting
          it do
            is_expected.to contain_ini_setting('set puppet.conf to not cache catalog')
          end

          ## Reboot
          it do
            is_expected.to contain_reboot('after_run')
          end
        end

        ### Test all hiera when set
        context 'CIS Level 2 BitLocker & NextGen domain' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'cis_profile_type' => 'domain',
              'cis_enforcement_level' => 2,
              'cis_include_bitlocker' => true,
              'cis_include_nextgen' => true,
              'cis_exclude_rules' => [], }
          end

          # Write out catalogue
          # it { File.write("cis_security_hardening_windows_cis_level2_domain_catalog_dump_#{os}.json", JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.not_to contain_class('cis_security_hardening_windows::remote_desktop') }

          ## File
          it do
            is_expected.to contain_file('C:/Windows/System32/GroupPolicy/')
          end

          ## Registry
          # Initialize an empty hash to store combined YAML data
          combined_yaml_data = {}
          # List of YAML files to load, dynamically using the Windows release version
          yaml_files = Dir["./data/windows/#{facts[:os]['release']['major']}/*.yaml"]

          # Iterate over each YAML file and merge its data into the combined hash
          yaml_files.each do |file|
            yaml_data = YAML.load_file(file)
            combined_yaml_data.merge!(yaml_data)
          end

          # List of specific hash titles to access
          hash_titles = [
            'cis_security_hardening_windows::cis_level_1',
            'cis_security_hardening_windows::cis_level_2',
            'cis_security_hardening_windows::cis_nextgen',
            'cis_security_hardening_windows::cis_bitlocker',
            '(cis_security_hardening_windows::cis_standalone_optout).to_h', # Standalone optouts should not be included but is allowed to verify its absence
          ]

          # Access and merge specified hashes from the hierarchy
          combined_data = hash_titles.map { |title| combined_yaml_data[title] || {} }.reduce(&:merge)

          # Iterate over the hash
          combined_data.each do |title, hash|
            hash.each do |value, properties|
              # Set default values if 'type' or 'data' is not present
              properties['type'] ||= 'dword'
              properties['data'] ||= 1

              describe "Registry value: #{title}" do
                it do
                  # Compare the heira values to those in the catalog
                  is_expected.to contain_registry_value(value).with(
                    'type' => properties['type'],
                    'data' => properties['data'],
                  )
                end
              end

              # Extract path of 'value' using regex and add it to an array
              extracted_keys = []
              extracted_key = value.gsub(%r{[\\\*]+[^\\\*]+$}, '')
              extracted_keys << extracted_key if extracted_key

              # Ensure that the registry keys are also specified, as these are created if they don't exit
              describe "Registry key: #{title}" do
                extracted_keys.each do |key|
                  it do
                    # Compare the heira values to those in the catalog
                    is_expected.to contain_registry_key(key)
                  end
                end
              end
            end
          end

          # Registry misc
          it do
            is_expected.to contain_registry_key('HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Puppet\\Puppet')
          end

          it do
            is_expected.to contain_registry_value('HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Puppet\\Puppet\\EventMessageFile').with(
              'type' => 'expand',
              'data' => 'C:\Program Files\Puppet Labs\Puppet\puppet\bin\puppetres.dll',
            )
          end

          ## Local Security Policy
          # List of YAML files to load, dynamically using the Windows release version
          yaml_file = YAML.load_file('./data/windows/secpol.yaml')

          # List of specific hash titles to access
          hash_titles = [
            'cis_security_hardening_windows::cis_secpol_level_1',
            'cis_security_hardening_windows::cis_secpol_level_2',
          ]

          # Access and merge specified hashes from the hierarchy
          combined_data = hash_titles.map { |title| yaml_file[title] || {} }.reduce(&:merge)

          # Iterate over the hash
          combined_data.each do |title, hash|
            hash.each do |key, properties|
              # Replace in-hiera lookups with the values they would resolve
              properties['policy_value'] = '"NewGuestName"' if properties['policy_value'] == '"%{lookup("cis_security_hardening_windows::disabled_guest_newname")}"'
              properties['policy_value'] = '"NewAdministratorName"' if properties['policy_value'] == '"%{lookup("cis_security_hardening_windows::administrator_newname")}"'
              properties['policy_value'] = '"notice and consent banner"' if properties['policy_value'] == '"%{lookup("cis_security_hardening_windows::logon_banner")}"'
              properties['policy_value'] = 'all activities performed on this system will be monitored.' if properties['policy_value'] == "%{lookup('cis_security_hardening_windows::logon_message')}"

              describe "Security Policy setting: #{title}" do
                it do
                  # Compare the heira values to those in the catalog
                  is_expected.to contain_local_security_policy(key).with(
                    'ensure' => properties['ensure'],
                    'policy_value' => properties['policy_value'],
                  )
                end
              end
            end
          end

          ## Audit Policy
          # List of YAML files to load, dynamically using the Windows release version
          yaml_file = YAML.load_file('./data/windows/auditpol.yaml')

          # List of specific hash titles to access
          hash_title = yaml_file['cis_security_hardening_windows::cis_auditpol']

          # Iterate over the hash
          hash_title.each do |title, hash|
            hash.each do |key, properties|
              describe "Audit Policy setting: #{title}" do
                it do
                  # Compare the hiera values to those in the catalog
                  is_expected.to contain_auditpol(key).with(
                    'success' => properties['success'],
                    'failure' => properties['failure'],
                  )
                end
              end
            end
          end
        end

        ### Test standalone hiera is used when set
        context 'CIS Level 2 BitLocker and NextGen standalone' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'cis_profile_type' => 'standalone',
              'cis_enforcement_level' => 2,
              'cis_include_bitlocker' => true,
              'cis_include_nextgen' => true,
              'cis_exclude_rules' => [], }
          end

          # Write out catalogue
          # it { File.write("cis_security_hardening_windows_standalone_catalog_dump_#{os}.json", JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.not_to contain_class('cis_security_hardening_windows::remote_desktop') }

          ## Sample of standalone rules expected to be absent
          absent_registry_values = [
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableBkGndGroupPolicy',
          ]

          absent_registry_values.each do |key|
            it { is_expected.not_to contain_registry_value(key) }
          end
        end

        ### Test Level 1 only hiera is used when set
        context 'CIS Level 1 standalone' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'cis_profile_type' => 'standalone',
              'cis_enforcement_level' => 1,
              'cis_include_bitlocker' => false,
              'cis_include_nextgen' => false,
              'cis_exclude_rules' => [], }
          end

          # Write out catalogue
          # it { File.write("cis_security_hardening_windows_level1_catalog_dump_#{os}.json", JSON.pretty_generate(catalogue.to_resource)) }

          ## Registry
          # Initialize an empty hash to store combined YAML data
          combined_yaml_data = {}
          # List of YAML files to load, dynamically using the Windows release version
          yaml_files = Dir["./data/windows/#{facts[:operatingsystemrelease]}/*.yaml"]

          # Iterate over each YAML file and merge its data into the combined hash
          yaml_files.each do |file|
            yaml_data = YAML.load_file(file)
            combined_yaml_data.merge!(yaml_data)
          end

          # List of specific hash titles to access
          hash_titles = [
            'cis_security_hardening_windows::cis_level_2',
            'cis_security_hardening_windows::cis_nextgen',
            'cis_security_hardening_windows::cis_bitlocker',
          ]

          # Access and merge specified hashes from the hierarchy
          combined_data = hash_titles.map { |title| combined_yaml_data[title] || {} }.reduce(&:merge)

          # Iterate over the hash
          combined_data.each do |title, hash|
            hash.each do |key, properties|
              # Set default values if 'type' or 'data' is not present
              properties['type'] ||= 'dword'
              properties['data'] ||= 1

              describe "Registry setting: #{title}" do
                it do
                  # compare the heira values to those in the catalog
                  is_expected.not_to contain_registry_value(key).with(
                    'type' => properties['type'],
                    'data' => properties['data'],
                  )
                end
              end
            end
          end

          ## Sample of standalone rules expected to be absent
          absent_registry_values = [
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableBkGndGroupPolicy',
          ]

          absent_registry_values.each do |key|
            it { is_expected.not_to contain_registry_value(key) }
          end
        end

        ### Test exclude_rules are absent
        context 'CIS Level 2 standalone with exclude_rules' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'cis_profile_type' => 'standalone',
              'cis_enforcement_level' => 2,
              'cis_include_bitlocker' => true,
              'cis_include_nextgen' => true,
              'cis_exclude_rules' => [
                "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'",
                "(L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'",
              ], }
          end

          # Write out catalogue
          # it { File.write("cis_security_hardening_windows_standalone_catalog_dump_#{os}.json", JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.not_to contain_class('cis_security_hardening_windows::remote_desktop') }

          ## Sample of standalone rules expected to be absent
          absent_registry_values = [
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableBkGndGroupPolicy',
          ]
          ## Sample of exclude_rules expected to be absent (these keys belong to the cis_exclude_rules titles in params above)
          excluded_registry_values = [
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen',
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel',
            'HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start',
          ]

          absent_registry_values.each do |absent_key|
            it { is_expected.not_to contain_registry_value(absent_key) }
          end

          excluded_registry_values.each do |excluded_key|
            it { is_expected.not_to contain_registry_value(excluded_key) }
          end
        end

        # Test Remote Desktop with trusted_rdp_subnets defined
        context 'Remote Desktop with trusted_rdp_subnets defined' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'enable_remote_desktop' => true,
              'trusted_rdp_subnets' => ['192.168.1.0/24', '10.2.0.0/16'] }
          end

          # Write out catalogue
          # it { File.write('cis_security_hardening_windows_remote_desktop_catalog_dump.json', JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.to contain_class('cis_security_hardening_windows::remote_desktop') }

          # Registry overrides
          it do
            is_expected.to contain_registry_value('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\fDenyTSConnections').with(
              'type' => 'dword',
              'data' => '0',
            )
          end
          it do
            is_expected.to contain_registry_value('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\UserAuthentication').with(
              'type' => 'dword',
              'data' => '0',
            )
          end
          it do
            is_expected.to contain_registry_value('HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Start').with(
              'type' => 'dword',
              'data' => '2',
            )
          end

          # Firewall
          it do
            is_expected.to contain_windows_firewall_rule('Remote Desktop - User Mode (TCP-In)').with(
              'description' => 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]',
              'action' => 'allow',
              'enabled' => 'true',
              'protocol' => 'tcp',
              'local_port' => '3389',
              'remote_address' => ['192.168.1.0/24', '10.2.0.0/16'],
              'remote_port' => 'any',
              'direction' => 'inbound',
              'profile' => '["domain", "private"]',
              'program' => 'C:\\Windows\\system32\\svchost.exe',
              'service' => 'termservice',
            )
          end
          it do
            is_expected.to contain_windows_firewall_rule('Remote Desktop - User Mode (UDP-In)').with(
              'description' => 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]',
              'action' => 'allow',
              'enabled' => 'true',
              'protocol' => 'udp',
              'local_port' => '3389',
              'remote_address' => ['192.168.1.0/24', '10.2.0.0/16'],
              'remote_port' => 'any',
              'direction' => 'inbound',
              'profile' => '["domain", "private"]',
              'program' => 'C:\\Windows\\system32\\svchost.exe',
              'service' => 'termservice',
            )
          end

          # Service
          it do
            is_expected.to contain_service('TermService').with(
              'ensure' => 'running',
              'enable' => 'true',
            )
          end
        end

        # Test without trusted_rdp_subnets defined
        context 'Remote Desktop without trusted_rdp_subnets defined' do
          let(:facts) do
            super().merge(
              testcase: 'minimum',
            )
          end

          let(:params) do
            { 'enable_remote_desktop' => true,
              'trusted_rdp_subnets' => :undef }
          end

          # Write out catalogue
          # it { File.write('cis_security_hardening_windows_remote_desktop_no_trusted_rdp_subnets_catalog_dump.json', JSON.pretty_generate(catalogue.to_resource)) }

          # compile with deps & create class
          # it { pp catalogue.resources }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('cis_security_hardening_windows') }
          it { is_expected.to contain_class('cis_security_hardening_windows::cis') }
          it { is_expected.to contain_class('cis_security_hardening_windows::remote_desktop') }

          # Registry overrides
          it do
            is_expected.to contain_registry_value('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\fDenyTSConnections').with(
              'type' => 'dword',
              'data' => '0',
            )
          end
          it do
            is_expected.to contain_registry_value('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\UserAuthentication').with(
              'type' => 'dword',
              'data' => '0',
            )
          end
          it do
            is_expected.to contain_registry_value('HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Start').with(
              'type' => 'dword',
              'data' => '2',
            )
          end

          # Firewall
          it do
            is_expected.to contain_windows_firewall_rule('Remote Desktop - User Mode (TCP-In)').with(
              'description' => 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]',
              'action' => 'allow',
              'enabled' => 'true',
              'protocol' => 'tcp',
              'local_port' => '3389',
              'remote_address' => 'any',
              'remote_port' => 'any',
              'direction' => 'inbound',
              'profile' => '["domain", "private"]',
              'program' => 'C:\\Windows\\system32\\svchost.exe',
              'service' => 'termservice',
            )
          end
          it do
            is_expected.to contain_windows_firewall_rule('Remote Desktop - User Mode (UDP-In)').with(
              'description' => 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]',
              'action' => 'allow',
              'enabled' => 'true',
              'protocol' => 'udp',
              'local_port' => '3389',
              'remote_address' => 'any',
              'remote_port' => 'any',
              'direction' => 'inbound',
              'profile' => '["domain", "private"]',
              'program' => 'C:\\Windows\\system32\\svchost.exe',
              'service' => 'termservice',
            )
          end

          # Service
          it do
            is_expected.to contain_service('TermService').with(
              'ensure' => 'running',
              'enable' => 'true',
            )
          end
        end
      end
    end
  end
end
