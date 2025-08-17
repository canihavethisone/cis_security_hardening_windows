shared_examples 'windows tests' do |agent:|
  # Number of combined registry entries to select
  reg_entries_to_test = 50

  describe 'Windows acceptance tests' do
    # Users tests
    describe user('user') do
      it { is_expected.to exist }
    end

    # Load registry YAML data once at the start
    registry_yaml_data = {}
    registry_yaml_files = Dir["./data/windows/#{agent['version']}/*.yaml"]
    registry_yaml_files.each { |file| registry_yaml_data.merge!(YAML.load_file(file)) }

    # Load exclusion YAML data
    exclude_yaml_data = YAML.load_file('./spec/acceptance/overrides.yaml')

    # Hash titles and combined data
    registry_hash_titles = [
      'cis_security_hardening_windows::cis_level_1',
      'cis_security_hardening_windows::cis_level_2',
      'cis_security_hardening_windows::cis_nextgen',
      'cis_security_hardening_windows::cis_bitlocker',
      '(cis_security_hardening_windows::cis_standalone_optout).to_h', # Standalone optouts should not be included but is allowed to verify its absence
    ]
    registry_combined_data = registry_hash_titles.map { |title| registry_yaml_data[title] || {} }.reduce(&:merge)

    # Exclude hash titles and combined data
    exclude_keys = exclude_yaml_data['cis_security_hardening_windows::cis_exclude_rules']
    registry_combined_data.reject! { |key, _| exclude_keys.include?(key) }

    # Default properties
    default_properties = { 'type' => 'dword', 'data' => 1 }
    previous_title = nil

    # Some exclusions are required as acceptance tests require remote access to be enabled, and a few others
    exclusion_patterns = Set.new([
      %r{Hardened UNC Paths}, # Multiple backslashes are not easily tested
      %r{Named Pipes that can be accessed anonymously}, # Yet to manage paths within array in data
      %r{Remotely accessible registry paths}, # Yet to manage paths within array in data
      %r{Turn off background refresh of Group Policy is set}, # Is set to absent in hiera
      %r{Require user authentication for remote connections by using Network Level Authentication},
      %r{Remote Desktop Services \(TermService\)},
      %r{Allow users to connect remotely by using Remote Desktop Services},
      %r{Remote Desktop Services UserMode Port Redirector},
    ])

    # Generate one test block for a batch of registry keys to avoid deep recursion
    describe 'Registry keys validation' do
      # Convert registry_combined_data to an array and randomly select entries
      random_registry_entries = registry_combined_data.to_a.sample([reg_entries_to_test, registry_combined_data.size].min)
      print_stage("Verifying registry with a random sample of #{random_registry_entries.size} entries")

      # Split into batches of 10 to reduce nesting
      random_registry_entries.each_slice(10) do |batch|
        it "validates a batch of #{batch.size} registry entries" do
          batch.each do |title, hash|
            # Skip if title matches any exclusion pattern
            next if exclusion_patterns.any? { |pattern| title.match?(pattern) }

            # Set title to 'as per previous' if it's empty or same as previous title
            local_title = previous_title || 'as per previous'
            local_title = title if title && !title.empty? && title != previous_title

            hash.each do |regkey, properties|
              # Helper method to process registry data
              processed_properties = default_properties.merge(properties)
              if processed_properties['data'].is_a?(Array)
                processed_properties['data'] = processed_properties['data'].map { |e| "'#{e}'" }.join(',')
              end
              processed_properties['data'] = processed_properties['data'].to_s

              # Extract registry key path and value name safely
              match_data = regkey.match(%r{^(.*)\\([^\\]*)$})
              next unless match_data
              extracted_key, extracted_value = match_data.captures

              # Run the check directly in this it block instead of nesting describe
              expect(windows_registry_key(extracted_key))
                .to have_property_value(extracted_value, ":type_#{processed_properties['type']}", processed_properties['data'])
            end

            previous_title = local_title
          end
        end
      end
    end

    # Networking - profile is private
    describe command('Get-NetConnectionProfile | select NetworkCategory -ExpandProperty NetworkCategory') do
      its(:stdout) { is_expected.to match(%r{Private}) }
    end

    # Secpol - renamed administrator disabled
    describe command('Get-LocalUser | Where-Object {$_.SID -like "S-1-5-21-*-500"} | Select -ExpandProperty Enabled') do
      its(:stdout) { is_expected.to match(%r{False}) }
    end

    # Exclude rules - ensure that exclusions in overrides are applying correctly
    # "(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    describe windows_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
      it { is_expected.not_to have_property_value('RequireSecuritySignature', :type_dword, '1') }
    end
  end
end