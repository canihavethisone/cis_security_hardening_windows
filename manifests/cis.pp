## Windows cis class.  It is called from the cis_security_hardening_windows class.  Params are derived from in-module hiera and can be excluded.
#
# @example Declaring the class
#   include cis_security_hardening_windows
#
# @param [Enum['domain', 'standalone']]  cis_profile_type       Apply domain or standalone CIS benchmark 
# @param [Integer[1, 2]]                 cis_enforcement_level  CIS level to apply. Level 2 includes level 1
# @param [Boolean]                       cis_include_bitlocker  If cis bitlocker rules should be included
# @param [Boolean]                       cis_include_nextgen    If cis nextgen rules should be included
# @param [Hash]                          cis_exclude_rules      Lookup of optional array for cis_exclude_rules (to opt out of included rules)
# @param [Boolean]                       cis_include_hkcu       If true, lgpo is used to import group policy objects for HKCU as puppetlabs/registry cannot apply them
#
class cis_security_hardening_windows::cis (
  $cis_profile_type,
  $cis_enforcement_level,
  $cis_include_bitlocker,
  $cis_include_nextgen,
  $cis_include_hkcu,
  $cis_exclude_rules,
) {
  # Assign values to CIS hashes from in-module hiera.  Legacy lookup is used here to support testing
  # Variable                     ( 'Name',                                                  Type,  Merge, Default )
  # ---------------------------------------------------------------------------------------------------------------
  $cis_level_1           = lookup( 'cis_security_hardening_windows::cis_level_1',           Hash, 'deep', {})
  $cis_level_2           = lookup( 'cis_security_hardening_windows::cis_level_2',           Hash, 'deep', {})
  $cis_bitlocker         = lookup( 'cis_security_hardening_windows::cis_bitlocker',         Hash, 'deep', {})
  $cis_nextgen           = lookup( 'cis_security_hardening_windows::cis_nextgen',           Hash, 'deep', {})
  $cis_standalone_optout = lookup( 'cis_security_hardening_windows::cis_standalone_optout', Array, undef, undef )
  $cis_secpol_level_1    = lookup( 'cis_security_hardening_windows::cis_secpol_level_1',    Hash, 'deep', {})
  $cis_secpol_level_2    = lookup( 'cis_security_hardening_windows::cis_secpol_level_2',    Hash, 'deep', {})
  $cis_auditpol          = lookup( 'cis_security_hardening_windows::cis_auditpol',          Hash, 'deep', {})

  # Create auditpol entries
  # Remove the rule title from the hashes so the auditpol resource can apply them
  $cis_auditpol.each | String $title, Hash $rule = {} | {
    $rule.each | String $key, Hash $value = {} | {
      auditpol { $key:
        * => $value,
      }
    }
  }

  if $cis_include_hkcu {
    # Copy CIS recommended user registry settings, as HKCU not supported by puppetlabs/registry. This applies to all users.
    file { 'C:/Windows/System32/GroupPolicy/':
      ensure  => directory,
      recurse => true,
      source  => 'puppet:///modules/cis_security_hardening_windows/user_grouppolicy/',
      replace => false,
      notify  => Exec['grouppolicy dir attributes'],
    }
    # Ensure that the GroupPolicy directory is hidden as per default
    exec { 'grouppolicy dir attributes':
      command     => '(Get-Item C:/Windows/System32/GroupPolicy).Attributes += "Hidden"',
      unless      => 'if ((Get-Item C:/Windows/System32/GroupPolicy -Force).Attributes.HasFlag([System.IO.FileAttributes]::Hidden)) { exit 0 } else { exit 1 }',
      provider    => powershell,
      require     => File['C:/Windows/System32/GroupPolicy/'],
      refreshonly => true,
    }
  }

  # Set base_rules determined by enforcement_level
  $base_rules = $cis_enforcement_level ? {
    1 => $cis_level_1,
    2 => $cis_level_1 + $cis_level_2,
  }

  # Determine if cis_bitlocker rules are included
  $bitlocker_rules = $cis_include_bitlocker ? {
    true  => $cis_bitlocker,
    false => {},
  }

  # Determine if cis_nextgen rules are included
  $nextgen_rules = $cis_include_nextgen ? {
    true  => $cis_nextgen,
    false => {},
  }

  # Assemble total rules
  $total_rules = $base_rules + $bitlocker_rules + $nextgen_rules

  # Determine if exclude rules should be combined with standalone optouts
  $cis_exclude_rules_real = $cis_profile_type ? {
    'domain'     => $cis_exclude_rules,
    'standalone' => $cis_exclude_rules + $cis_standalone_optout,
  }

  # Create final enforced_rules by removing any excluded rules using description only
  $enforced_rules = $total_rules.filter | String $rule, Hash $value| {
    !($rule in $cis_exclude_rules_real)
  }

  # Remove the rule title from the hashes so the registry resource can apply them
  $enforced_rules.each | String $title, Hash $rule = {} | {
    $rule.each |String $key, Hash $value = {} | {
      # Ensure the registry path exists.  This will fail for duplicates with different CASE (capitalisation)!
      $regpath = regsubst($key, '[\\\*]+[^\\\*]+$', '')
      if !defined(Registry_key[$regpath]) and $value['ensure'] != 'absent' {
        registry_key { $regpath:
          ensure => 'present',
        }
      }
      # Create all the registry values using puppetlabs/registry
      registry_value {
        default:
          type => 'dword',
          data => '1',
        ;
        $key:
          * => $value,
        ;
      }
    }
  }

  # Local Security Policy settings
  # Set secpol_base_rules determined by enforcement_level
  $secpol_base_rules = $cis_enforcement_level ? {
    1 => $cis_secpol_level_1,
    2 => $cis_secpol_level_1 + $cis_secpol_level_2,
  }

  # Create final enforced_rules by removing any excluded rules using description only
  $enforced_secpol_rules = $secpol_base_rules.filter |$rule, $value| {
    !($rule in $cis_exclude_rules_real)
  }

  # Remove the rule title from the hashes so the local_security_policy resource can apply them
  $enforced_secpol_rules.each | String $title, Hash $rule = {} | {
    $rule.each |String $key, Hash $value = {} | {
      local_security_policy { $key:
        * => $value,
      }
    }
  }
}
