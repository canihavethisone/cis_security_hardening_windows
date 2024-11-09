#
# Windows remote_desktop class.  It is called from the cis_security_hardening_windows class when $allow_remote_desktop is true.
#
# @example Declaring the class
#   include cis_security_hardening_windows
#
# @param [Array]   trusted_rdp_subnets   Trusted subnets for inbound rdp connections for firewall rules. Undef will be converted to 'any'
# @param [Boolean] remote_local_accounts If local accounts are permitted to connect remotely. Required if not domain joined
#
class cis_security_hardening_windows::remote_desktop (
  $trusted_rdp_subnets,
  $remote_local_accounts,
) {
  $trusted_rdp_subnets_real = $trusted_rdp_subnets ? {
    default => $trusted_rdp_subnets,
    []      => 'any'
  }

  # Configure firewall
  windows_firewall_rule { 'Remote Desktop - User Mode (TCP-In)' :
    ensure                => 'present',
    description           => 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]',
    action                => 'allow',
    enabled               => true,
    local_address         => $facts[networking][ip],
    remote_address        => $trusted_rdp_subnets_real,
    local_port            => '3389',
    protocol              => 'tcp',
    remote_port           => 'any',
    direction             => 'inbound',
    profile               => ['domain', 'private'],
    program               => 'C:\Windows\system32\svchost.exe',
    service               => 'termservice',
    interface_type        => ['any'],
    edge_traversal_policy => 'block',
  }
  windows_firewall_rule { 'Remote Desktop - User Mode (UDP-In)' :
    ensure                => 'present',
    description           => 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]',
    action                => 'allow',
    enabled               => true,
    local_address         => $facts[networking][ip],
    remote_address        => $trusted_rdp_subnets_real,
    local_port            => '3389',
    protocol              => 'udp',
    remote_port           => 'any',
    direction             => 'inbound',
    profile               => ['domain', 'private'],
    program               => 'C:\Windows\system32\svchost.exe',
    service               => 'termservice',
    interface_type        => ['any'],
    edge_traversal_policy => 'block',
  }

  # Add registry overrides for RDP to function
  $rdp_registry_keys = {
    # Allow users to connect remotely by using Remote Desktop Services is NOT set to Disabled
    'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections' => 0,
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections' => 0,
    # Ensure 'Require user authentication for remote connections by using Network Level Authentication' is NOT set to 'Enabled'
    'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication' => 0,
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication' => 0,
    # Remote Desktop Services (TermService) is NOT set to Disabled
    'HKLM\SYSTEM\CurrentControlSet\Services\TermService\Start' => 2,
  }

  # Apply registry keys
  $rdp_registry_keys.each |$key, $value| {
    Registry_value <| title == $key |> { data => $value }
  }

  # Allow LOCAL_ACCOUNT to logon via RDP.  This ensures that non-domain joined computers can be remotely accesses
  if $remote_local_accounts {
    Local_security_policy <| title == 'Deny log on through Remote Desktop Services' |> { policy_value => 'Guests' }
    Local_security_policy <| title == 'Deny access to this computer from the network' |> { policy_value => 'Guests' }
  }

  # Ensure service is enabled and running
  service { 'TermService':
    ensure => running,
    enable => true,
  }
}
