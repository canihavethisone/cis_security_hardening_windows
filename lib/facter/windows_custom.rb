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
    if RUBY_PLATFORM =~ /mswin|mingw32/i
      # Connect to WMI to get OS details
      wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')
      windows_version = wmi.ExecQuery('SELECT Caption, BuildNumber FROM Win32_OperatingSystem').each.first

      # Open registry path to retrieve build-related versioning info
      Win32::Registry::HKEY_LOCAL_MACHINE.open('Software\\Microsoft\\Windows NT\\CurrentVersion') do |reg|
        windows_currentbuildnumber = reg['CurrentBuildNumber'] rescue 'unknown'
        windows_displayversion     = reg['DisplayVersion']     rescue 'unknown'
        windows_releaseid          = reg['ReleaseId']          rescue 'unknown'
      end
    end
  rescue => e
    # Log errors without failing the fact
    Facter.debug("windows custom fact error: #{e.class}: #{e.message}")
  end

  # Microsoft moved from ReleaseId to DisplayVersion starting around build 19043
  windows_display_version = windows_currentbuildnumber >= '19043' ? windows_displayversion : windows_releaseid

  setcode do
    if windows_version
      # Safely split the caption string to extract product and edition info
      caption_parts = windows_version.Caption.to_s.split(' ')
      {
        'product_name'    => caption_parts[1..].join(' '),              # Strip "Microsoft" prefix
        'release'         => caption_parts[2] || 'unknown',             # e.g. "10"
        'edition_id'      => caption_parts[3] || 'unknown',             # e.g. "Pro"
        'display_version' => windows_display_version,                   # e.g. "22H2"
        'build_number'    => windows_version.BuildNumber                # e.g. "19045"
      }
    else
      {}
    end
  end
end
