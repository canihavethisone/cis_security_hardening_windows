## Windows main class.  The entry point with most parameters processed here.
# It applies CIS hardening
#
# @example Declaring the class
#   include cis_security_hardening_windows
#
# @param [Hash]                          users                    Any users to create
# @param [Boolean]                       purge_unmanaged_users    If unmanaged users should be purged. Requires users hash to be defined
# @param [Enum['domain', 'standalone']]  cis_profile_type         Apply domain or standalone CIS benchmark 
# @param [Integer[1, 2]]                 cis_enforcement_level    CIS level to apply. Level 2 includes level 1
# @param [Boolean]                       cis_include_bitlocker    If cis bitlocker rules should be included
# @param [Boolean]                       cis_include_nextgen      If cis nextgen rules should be included
# @param [Hash]                          cis_exclude_rules        Lookup of optional hash for cis_exclude_rules (to opt out of included rules)
# @param [Boolean]                       cis_include_hkcu         If true, CIS defined local group policy objects are copied in for users as puppetlabs/registry cannot apply HKCU
# @param [Hash]                          misc_registry            Lookup of misc registry items to apply.  Currently sets Puppet logging to event viewer and disables SMB1
# @param [Boolean]                       enable_administrator     If the local adminsitrator account is enabled. Note that account must be renamed if enabled or not
# @param [Boolean]                       enable_remote_desktop    If true the RDP service will be enabled and firewall rule created (false)
# @param [Array]                         trusted_rdp_subnets      Trusted subnets for inbound rdp connections for firewall rules. Undef will be converted to 'any'
# @param [Boolean]                       remote_local_accounts    If true and RDP is enabled, this allows local user accounts to connect remotely. Required if not domain joined (true)
# @param [Boolean]                       performance_powerscheme  If true, set the powerscheme to high performance to prevent sleep.
# @param [Boolean]                       clear_temp_files         If true clears user temp and system temp directories
# @param [Boolean]                       auto_restart             If true, restarts the host at the end of the puppet run when registry local_security_policy changes occur (recommended)
# @param [Boolean]                       catalog_no_cache         Do not cache the puppet catalog on disk, as passwords and other values are in plain text
#
class cis_security_hardening_windows (
# Variable                         ( 'Name',                     Type,                         Merge,  Default )
# --------------------------------------------------------------------------------------------------------------
  $users                   = lookup( 'users',                    Hash,                         'deep', {}),
  $purge_unmanaged_users   = lookup( 'purge_unmanaged_users',    Boolean,                      undef,    false ),
  $cis_profile_type        = lookup( 'cis_profile_type',         Enum['domain', 'standalone'], undef, 'domain' ),
  $cis_enforcement_level   = lookup( 'cis_enforcement_level',    Integer[1, 2],                undef,    2     ),
  $cis_include_bitlocker   = lookup( 'cis_include_bitlocker',    Boolean,                      undef,    true  ),
  $cis_include_nextgen     = lookup( 'cis_include_nextgen',      Boolean,                      undef,    true  ),
  $cis_exclude_rules       = lookup( 'cis_exclude_rules',        Array,                        'deep', []),
  $cis_include_hkcu        = lookup( 'cis_include_hkcu',         Boolean,                      undef,    true  ),
  $misc_registry           = lookup( 'misc_registry',            Hash,                         'deep', {}),
  $enable_administrator    = lookup( 'enable_administrator',     Boolean,                      undef,    false ),
  $enable_remote_desktop   = lookup( 'enable_remote_desktop',    Boolean,                      undef,    false ),
  $trusted_rdp_subnets     = lookup( 'trusted_rdp_subnets',      Array,                        undef, []),
  $remote_local_accounts   = lookup( 'remote_local_accounts',    Boolean,                      undef,    true  ),
  $performance_powerscheme = lookup( 'performance_powerscheme',  Boolean,                      undef,    false ),
  $clear_temp_files        = lookup( 'clear_temp_files',         Boolean,                      undef,    false ),
  $auto_restart            = lookup( 'auto_restart',             Boolean,                      undef,    true  ),
  $catalog_no_cache        = lookup( 'catalog_no_cache',         Boolean,                      undef,    false ),
) {
  # Check that the release is supported. These are backed by hiera directories
  if !($facts['windows']['release'] in ['10','11']) {
    fail("Your Windows release ${facts['windows']['release']} is not yet supported.")
  }

  # Define required parameters
  $required_params = {
    'logon_banner'              => lookup('cis_security_hardening_windows::logon_banner', { 'default_value' => undef }),
    'logon_message'             => lookup('cis_security_hardening_windows::logon_message', { 'default_value' => undef }),
    'administrator_newname'     => lookup('cis_security_hardening_windows::administrator_newname', { 'default_value' => undef }),
    'administrator_newpassword' => lookup('cis_security_hardening_windows::administrator_newpassword', { 'default_value' => undef }),
    'disabled_guest_newname'    => lookup('cis_security_hardening_windows::disabled_guest_newname', { 'default_value' => undef }),
  }

  # Check for any missing required parameters
  $missing_params = $required_params.filter |$key, $value| { $value == undef }
  if !$missing_params.empty {
    fail("\n\nThe following parameters must be defined:\n${missing_params.keys.join("\n")}\n\n")
  }

  # Fail if administrator disabled and users not defined
  if !$enable_administrator and $users.empty {
    fail('At least one user must be defined if the administrator account is disabled.')
  }

  # Fail if purge_unmanaged_users enabled and users not defined
  if $purge_unmanaged_users and $users.empty {
    fail('You cannot purge unmanaged users without defining a users hash to manage users.')
  }

  # Ensure that the local_security_policy for local Administrator is set
  local_security_policy { 'Accounts: Administrator account status':
    policy_value => $enable_administrator ? { true => 1, default => 0, } #lint:ignore:selector_inside_resource
  }

  # Configure Remote Desktop agent if true
  if $enable_remote_desktop {
    class { 'cis_security_hardening_windows::remote_desktop':
      remote_local_accounts => $remote_local_accounts,
      trusted_rdp_subnets   => $trusted_rdp_subnets,
    }
  }

  # Set power scheme to high performance to prevent sleep
  if $performance_powerscheme {
    exec { 'power_scheme_high':
      command   => 'powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c',
      unless    => 'if (powercfg.exe /getactivescheme | select-string "High performance") {exit 0} else {exit 1}',
      provider  => powershell,
      logoutput => true,
    }
  }

  # Include windows::cis class
  class { 'cis_security_hardening_windows::cis':
    cis_profile_type      => $cis_profile_type,
    cis_enforcement_level => $cis_enforcement_level,
    cis_include_bitlocker => $cis_include_bitlocker,
    cis_include_nextgen   => $cis_include_nextgen,
    cis_include_hkcu      => $cis_include_hkcu,
    cis_exclude_rules     => $cis_exclude_rules,
  }

  # Apply any misc registry hash values
  $misc_registry.each | String $key, Hash $value = {} | {

    # Ensure the registry path exists.  This will fail for duplicates with different CASE (capitalisation)!
    $regpath = regsubst($key, '[\\\*]+[^\\\*]+$', '')
    if !defined(Registry_key[$regpath]) and $value['ensure'] != 'absent' {
      registry_key { $regpath:
        ensure => 'present',
      }
    }
    registry_value { $key:
      * => $value,
    }
  }

  # Users need to be created after secpol has run (within CIS class) due to issue with renaming administrator (can only be done once)
  # Puppet 'unless_system_user' detection is incomplete in windows, so system_users are defined in module hiera
  if $purge_unmanaged_users {
    $users_real = $users + lookup(cis_security_hardening_windows::system_users)
  } else {
    $users_real = $users
  }

  resources { 'user': purge => $purge_unmanaged_users, unless_system_user => $purge_unmanaged_users }
  $users_real.each |String $key, $value| {
    user { $key:
      *          => $value,
      membership => 'inclusive',
    }
  }

  if $catalog_no_cache {
    # Delete the puppet catalog if it exists. This should only occur until a service restart as caching is unset by the following ini_setting
    tidy { 'delete puppet catalog':
      path    => 'C:/ProgramData/PuppetLabs/puppet/cache/client_data/catalog',
      recurse => 1,
    }
    # Set puppet.conf to not cache the puppet catalog
    ini_setting { 'set puppet.conf to not cache catalog':
      path    => 'C:/ProgramData/PuppetLabs/puppet/etc/puppet.conf',
      section => 'agent',
      setting => 'catalog_cache_terminus',
      value   => '""',
    }
  }

  if $clear_temp_files {
    # Clear user temp directory
    exec { 'clear_user_temp':
      command  => 'Remove-Item $env:temp\* -recurse -force -ErrorAction SilentlyContinue',
      onlyif   => 'if (Test-Path $env:temp\* -exclude aria*.*) { exit 0 } else { exit 1 }',
      provider => powershell,
    }

    # Clear windows(system) temp directory
    exec { 'clear_windows_temp':
      command  => 'Get-ChildItem ([Environment]::GetEnvironmentVariable("TEMP","Machine")) -recurse -exclude secedit.inf,vmware* | remove-item -recurse -force -ErrorAction SilentlyContinue',
      onlyif   => 'if (Get-ChildItem ([Environment]::GetEnvironmentVariable("TEMP","Machine")) -exclude secedit.inf,vmware*) { exit 0 } else { exit 1 }',
      provider => powershell,
    }
  }

  # Ensure that any registry_value or local_security_policy changes in any classes trigger a reboot to take affect
  if $auto_restart {
    Registry_value <| |> { notify  => Reboot['after_run'] }
    Local_security_policy <| |> { notify => Reboot['after_run'] }
    File <| title == 'C:/Windows/System32/GroupPolicy/' |> { notify => Reboot['after_run'] }
  }

  # Puppetlabs-reboot
  reboot { 'after_run':
    apply   => 'finished',
    timeout => 15,
  }
}
