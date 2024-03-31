shared_examples 'windows tests' do |agent:, _agent_ip:|
  # Users tests
  describe user('user') do
    it { is_expected.to exist }
  end

  # Load registry YAML data
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

  # Remove exclude keys from registry combined data
  exclude_keys.each { |key| registry_combined_data.delete(key) }

  # Default properties
  default_properties = { 'type' => 'dword', 'data' => 1 }
  previous_title = nil

  # Some exclusions are required as acceptance tests require remote access to be enabled, and a few others
  exclusion_patterns = [
    %r{Named Pipes that can be accessed anonymously}, # Yet to manage paths within array in data
    %r{Remotely accessible registry paths and sub-paths}, # Yet to manage paths within array in data
    %r{Turn off background refresh of Group Policy is set}, # Is set to absent in hiera
    %r{Require user authentication for remote connections by using Network Level Authentication},
    %r{Remote Desktop Services \(TermService\)},
    %r{Allow users to connect remotely by using Remote Desktop Services},
    %r{Remote Desktop Services UserMode Port Redirector},
  ]

  # Iterate over combined data
  registry_combined_data.each do |title, hash|
    # Skip the iteration if the title matches any pattern in the exclusion list due to remote requirements for testing and complex data values
    next if exclusion_patterns.any? { |pattern| title.match?(pattern) }

    # Set title to 'as per previous' if it's empty or if it's the same as the previous title
    title = previous_title || 'as per previous' if title.nil? || title.empty? || title == previous_title

    hash.each do |regkey, properties|
      properties = default_properties.merge(properties)
      extracted_key, extracted_value = regkey.match(%r{^(.*)\\([^\\]*)$})&.captures

      # Check if properties['data'] is an array before processing
      if properties['data'].is_a?(Array)
        # Surround each component with single quotes and join with commas
        properties['data'] = properties['data'].map { |element| "'#{element}'" }.join(',')
      end

      # Ensure that properties['data'] is a string before proceeding or calling gsub
      properties['data'] = properties['data'].to_s unless properties['data'].is_a?(String)

      # Yet to address data with paths within an array
      # properties['data'] = properties['data'].gsub(/\\+/, '\\')

      # Ensure that the registry keys are also specified, as these are created if they don't exist
      describe "Registry key: #{title}" do
        describe windows_registry_key(extracted_key) do
          it { is_expected.to have_property_value(extracted_value, ":type_#{properties['type']}", properties['data']) }
        end
      end
    end

    # Update previous_title to the current title
    previous_title = title
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
  # Registry - online accounts allowed
  # "(L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'":
  describe windows_registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { is_expected.not_to have_property_value('NoConnectedUser', :type_dword, '3') }
  end
end
