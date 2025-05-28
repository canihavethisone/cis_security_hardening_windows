Facter.add('windows') do
  # Only run this fact on Windows systems
  confine kernel: 'windows'

  require 'win32/registry'
  require 'win32ole'

  # Default values in case retrieval fails
  windows_currentbuildnumber = 'unknown'
  windows_displayversion     = 'unknown'
  windows_releaseid          = 'unknown'
  windows_version            = nil

  begin
    # Check if running on a supported Windows platform
    if RUBY_PLATFORM.match?(%r{mswin|mingw32}i)
      # Connect to WMI to get OS details
      wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')
      windows_version = wmi.ExecQuery('SELECT Caption, BuildNumber FROM Win32_OperatingSystem').each.first

      # Open registry path once and read needed values
      Win32::Registry::HKEY_LOCAL_MACHINE.open('Software\\Microsoft\\Windows NT\\CurrentVersion') do |reg|
        begin
          windows_currentbuildnumber = reg['CurrentBuildNumber']
        rescue StandardError
          windows_currentbuildnumber = 'unknown'
        end

        begin
          windows_displayversion = reg['DisplayVersion']
        rescue StandardError
          windows_displayversion = 'unknown'
        end

        begin
          windows_releaseid = reg['ReleaseId']
        rescue StandardError
          windows_releaseid = 'unknown'
        end
      end
    end
  rescue => e
    # Log errors without failing the fact
    Facter.debug("windows custom fact error: #{e.class}: #{e.message}")
  end

  # Microsoft moved from ReleaseId to DisplayVersion starting around build 19043
  windows_display_version = (windows_currentbuildnumber >= '19043') ? windows_displayversion : windows_releaseid

  setcode do
    if windows_version
      caption_parts = windows_version.Caption.to_s.split(' ')
      {
        'product_name'    => caption_parts[1..].join(' '), # Strip "Microsoft" prefix
        'release'         => caption_parts[2] || 'unknown',
        'edition_id'      => caption_parts[3] || 'unknown',
        'display_version' => windows_display_version,
        'build_number'    => windows_version.BuildNumber
      }
    else
      {}
    end
  end
end
