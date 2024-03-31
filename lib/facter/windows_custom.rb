Facter.add('windows') do
  confine kernel: 'windows'

  # Initialise variables
  windows_currentbuildnumber = 'unknown'
  windows_displayversion = 'unknown'
  windows_releaseid = 'unknown'
  windows_version = 'unknown'

  begin
    if RUBY_PLATFORM.downcase.include?('mswin') || RUBY_PLATFORM.downcase.include?('mingw32')
      require 'win32/registry'
      require 'win32ole'
      wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')

      # Retrieve operatingsystem hash from WMI as registry values were not incremented by Microsoft
      windows_version = wmi.ExecQuery('SELECT * FROM Win32_operatingsystem').each.first

      # Get values for build, display and releaseid from registry
      Win32::Registry::HKEY_LOCAL_MACHINE.open('Software\Microsoft\Windows NT\CurrentVersion') do |reg|
        reg.each do |name, _type, data|
          if name.eql?('CurrentBuildNumber')
            windows_currentbuildnumber = data
          end
          if name.eql?('DisplayVersion')
            windows_displayversion = data
          end
          if name.eql?('ReleaseId')
            windows_releaseid = data
          end
        end
      end
    end
  rescue
    nil
  end

  # Windows_display_version determined by currentbuildnumber value to manage change from 20h2 to 21h1 onward
  windows_display_version = if windows_currentbuildnumber >= '19043'
                              windows_displayversion
                            else
                              windows_releaseid
                            end

  setcode do
    # Create hash for values
    value = {}
    # Get the product name but remove leading 'Microsoft'
    value['product_name']    = windows_version.Caption.split(' ')[1..-1].join(' ')
    value['release']         = windows_version.Caption.split(' ')[2]
    value['edition_id']      = windows_version.Caption.split(' ')[3]
    value['display_version'] = windows_display_version
    value['build_number']    = windows_version.BuildNumber

    # Return hash
    value
  end
end
