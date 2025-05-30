# Reference

<!-- DO NOT EDIT: This document was generated by Puppet Strings -->

## Table of Contents

### Classes

* [`cis_security_hardening_windows`](#cis_security_hardening_windows): Windows main class.  The entry point with all parameters processed here. It applies CIS hardening

## Classes

### <a name="cis_security_hardening_windows"></a>`cis_security_hardening_windows`

Windows main class.  The entry point with all parameters processed here.
It applies CIS hardening

#### Examples

##### Declaring the class

```puppet
include cis_security_hardening_windows
```

#### Parameters

The following parameters are available in the `cis_security_hardening_windows` class:

* [`users`](#-cis_security_hardening_windows--users)
* [`purge_unmanaged_users`](#-cis_security_hardening_windows--purge_unmanaged_users)
* [`cis_profile_type`](#-cis_security_hardening_windows--cis_profile_type)
* [`cis_enforcement_level`](#-cis_security_hardening_windows--cis_enforcement_level)
* [`cis_include_bitlocker`](#-cis_security_hardening_windows--cis_include_bitlocker)
* [`cis_include_nextgen`](#-cis_security_hardening_windows--cis_include_nextgen)
* [`cis_exclude_rules`](#-cis_security_hardening_windows--cis_exclude_rules)
* [`cis_include_hkcu`](#-cis_security_hardening_windows--cis_include_hkcu)
* [`misc_registry`](#-cis_security_hardening_windows--misc_registry)
* [`enable_administrator`](#-cis_security_hardening_windows--enable_administrator)
* [`enable_remote_desktop`](#-cis_security_hardening_windows--enable_remote_desktop)
* [`trusted_rdp_subnets`](#-cis_security_hardening_windows--trusted_rdp_subnets)
* [`remote_local_accounts`](#-cis_security_hardening_windows--remote_local_accounts)
* [`performance_powerscheme`](#-cis_security_hardening_windows--performance_powerscheme)
* [`clear_temp_files`](#-cis_security_hardening_windows--clear_temp_files)
* [`auto_restart`](#-cis_security_hardening_windows--auto_restart)
* [`catalog_no_cache`](#-cis_security_hardening_windows--catalog_no_cache)

##### <a name="-cis_security_hardening_windows--users"></a>`users`

Data type: `Hash`

Any users to create

Default value: `lookup( 'users',                    Hash,                         'deep', {})`

##### <a name="-cis_security_hardening_windows--purge_unmanaged_users"></a>`purge_unmanaged_users`

Data type: `Boolean`

If unmanaged users should be purged. Requires users hash to be defined

Default value: `lookup( 'purge_unmanaged_users',    Boolean,                      undef,    false )`

##### <a name="-cis_security_hardening_windows--cis_profile_type"></a>`cis_profile_type`

Data type: `Enum['domain', 'standalone']`

Apply domain or standalone CIS benchmark

Default value: `lookup( 'cis_profile_type',         Enum['domain', 'standalone'], undef, 'domain' )`

##### <a name="-cis_security_hardening_windows--cis_enforcement_level"></a>`cis_enforcement_level`

Data type: `Integer[1, 2]`

CIS level to apply. Level 2 includes level 1

Default value: `lookup( 'cis_enforcement_level',    Integer[1, 2],                undef,    2     )`

##### <a name="-cis_security_hardening_windows--cis_include_bitlocker"></a>`cis_include_bitlocker`

Data type: `Boolean`

If cis bitlocker rules should be included

Default value: `lookup( 'cis_include_bitlocker',    Boolean,                      undef,    true  )`

##### <a name="-cis_security_hardening_windows--cis_include_nextgen"></a>`cis_include_nextgen`

Data type: `Boolean`

If cis nextgen rules should be included

Default value: `lookup( 'cis_include_nextgen',      Boolean,                      undef,    true  )`

##### <a name="-cis_security_hardening_windows--cis_exclude_rules"></a>`cis_exclude_rules`

Data type: `Hash`

Lookup of optional hash for cis_exclude_rules (to opt out of included rules)

Default value: `lookup( 'cis_exclude_rules',        Array,                        'deep', [])`

##### <a name="-cis_security_hardening_windows--cis_include_hkcu"></a>`cis_include_hkcu`

Data type: `Boolean`

If true, CIS defined local group policy objects are copied in for users as puppetlabs/registry cannot apply HKCU

Default value: `lookup( 'cis_include_hkcu',         Boolean,                      undef,    true  )`

##### <a name="-cis_security_hardening_windows--misc_registry"></a>`misc_registry`

Data type: `Hash`

Lookup of misc registry items to apply.  Currently sets Puppet logging to event viewer and disables SMB1

Default value: `lookup( 'misc_registry',            Hash,                         'deep', {})`

##### <a name="-cis_security_hardening_windows--enable_administrator"></a>`enable_administrator`

Data type: `Boolean`

If the local adminsitrator account is enabled. Note that account must be renamed if enabled or not

Default value: `lookup( 'enable_administrator',     Boolean,                      undef,    false )`

##### <a name="-cis_security_hardening_windows--enable_remote_desktop"></a>`enable_remote_desktop`

Data type: `Boolean`

If true the RDP service will be enabled and firewall rule created (false)

Default value: `lookup( 'enable_remote_desktop',    Boolean,                      undef,    false )`

##### <a name="-cis_security_hardening_windows--trusted_rdp_subnets"></a>`trusted_rdp_subnets`

Data type: `Array`

Trusted subnets for inbound rdp connections for firewall rules. Empty will be converted to 'any'

Default value: `lookup( 'trusted_rdp_subnets',      Array,                        undef, [])`

##### <a name="-cis_security_hardening_windows--remote_local_accounts"></a>`remote_local_accounts`

Data type: `Boolean`

If true and RDP is enabled, this allows local user accounts to connect remotely. Required if not domain joined (true)

Default value: `lookup( 'remote_local_accounts',    Boolean,                      undef,    true  )`

##### <a name="-cis_security_hardening_windows--performance_powerscheme"></a>`performance_powerscheme`

Data type: `Boolean`

If true, set the powerscheme to high performance to prevent sleep.

Default value: `lookup( 'performance_powerscheme',  Boolean,                      undef,    false )`

##### <a name="-cis_security_hardening_windows--clear_temp_files"></a>`clear_temp_files`

Data type: `Boolean`

If true clears user temp and system temp directories

Default value: `lookup( 'clear_temp_files',         Boolean,                      undef,    false )`

##### <a name="-cis_security_hardening_windows--auto_restart"></a>`auto_restart`

Data type: `Boolean`

If true, restarts the host at the end of the puppet run when registry local_security_policy changes occur (recommended)

Default value: `lookup( 'auto_restart',             Boolean,                      undef,    true  )`

##### <a name="-cis_security_hardening_windows--catalog_no_cache"></a>`catalog_no_cache`

Data type: `Boolean`

Do not cache the puppet catalog on disk, as passwords and other values are in plain text

Default value: `lookup( 'catalog_no_cache',         Boolean,                      undef,    false )`

