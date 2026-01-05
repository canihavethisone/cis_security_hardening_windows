Facter.add(:windows) do
  confine kernel: 'windows'

  setcode do
    require 'win32/registry'
    require 'win32ole'

    windows_version = nil
    current_build_number = nil
    display_version = 'unknown'
    release_id = 'unknown'

    # Query WMI for OS information
    wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')
    windows_version = wmi.ExecQuery(
      'SELECT Caption, BuildNumber FROM Win32_OperatingSystem'
    ).each.first

    # Read registry values
    Win32::Registry::HKEY_LOCAL_MACHINE.open(
      'Software\\Microsoft\\Windows NT\\CurrentVersion'
    ) do |reg|
      current_build_number = reg['CurrentBuildNumber'].to_i rescue nil
      display_version      = reg['DisplayVersion'] rescue 'unknown'
      release_id           = reg['ReleaseId'] rescue 'unknown'
    end

    # Microsoft moved from ReleaseId to DisplayVersion around build 19043
    effective_display_version =
      if current_build_number && current_build_number >= 19043
        display_version
      else
        release_id
      end

    if windows_version
      # Strip "Microsoft" prefix
      caption = windows_version.Caption.to_s.sub(/^Microsoft\s+/i, '')
      caption_parts = caption.split(' ')

      {
        'product_name'    => caption,
        'release'         => caption_parts[1] || 'unknown',
        'edition_id'      => caption_parts[2] || 'unknown',
        'display_version' => effective_display_version,
        'build_number'    => windows_version.BuildNumber
      }
    else
      {}
    end
  rescue => e
    Facter.debug("windows custom fact error: #{e.class}: #{e.message}")
    {}
  end
end
