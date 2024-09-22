![build status](https://github.com/canihavethisone/cis_security_hardening_windows/actions/workflows/ci.yml/badge.svg)

# cis_security_hardening_windows


#### Table of Contents

1. [Overview](#overview)
2. [Description](#description)
3. [Building on CIS controls](#building-on-cis-controls)
    * [Windows 10 / 11](#windows-10--11)
    * [Defence in-depth](#defence-in-depth)
5. [Beginning with os_hardening](#beginning-with-os_hardening)
6. [CIS Enforcement Levels](#cis-enforcement-levels)
7. [Reference](#reference)
8. [Development](#development)
9. [Release Notes](#release-notes)


## Overview

This module applies CIS benchmark hardening to:
- **Windows 10**: Configurable, defaulted to domain-joined Level 1 & 2 + NG + BL (currently v3.0.0)
- **Windows 11**: Configurable, defaulted to domain-joined Level 1 & 2 + BL (currently v3.0.0)


[It also configures additional system resources as described below](#building-on-cis-controls)


## Description

**Windows** CIS controls and other resources are applied using registry, security policy, audit policy, optional local group policy (for HKCU controls), execs and dependency modules.

This module uses a custom **windows** facts hash leveraging wmi, as reading the registry is unreliable for Windows 11

## Building on CIS controls

Additional resources are also defined, including:

### Windows 10 / 11
- users
- remote desktop
- firewall (limited)


Other Windows 10 / 11 parameters include:
- cis_profile_type
- cis_enforcement_level
- cis_include_bitlocker
- cis_include_nextgen
- cis_include_hkcu
- cis_exclude_rules
- catalog_no_cache
- clear_temp_files
- enable_administrator
- purge_unmanaged_users
- performance_powerscheme
- enable_remote_desktop


### Defence in-depth

This module takes a defence in-depth approach, with the following built-in functions:
- undefined users can be optionally purged (except system users)
- where CIS recommendations have more than 1 acceptable setting, the more stringent is used


## Beginning with cis_security_hardening_windows

To use this module, `include cis_security_hardening_windows` in your Node Classifier (ENC) or wrapping class.

**At minimum, the following hiera must be provided** to the module:

#### Windows 10 / 11:
- `cis_security_hardening_windows::logon_banner`  (string)
- `cis_security_hardening_windows::logon_message`  (string)
- `cis_security_hardening_windows::administrator_newname`  (string)
- `cis_security_hardening_windows::administrator_newpassword`  (string)
- `cis_security_hardening_windows::disabled_guest_newname`  (string)
- `cis_security_hardening_windows::users`  (hash) is required if the built-in administrator is disabled (default)



See example minimum hiera data [here](spec/fixtures/data/minimum.yaml)


## CIS Enforcement Levels

- All recommended domain-joined Level 1 & 2 + NG + BL CIS controls are enforced by default using module hiera (standalone selectable)
- HKCU registry entries are also optionally applied by copying a preconfigured `Registry.pol` file to `C:/Windows/System32/GroupPolicy/`
- Comments in module hiera identify the objective of each setting however CIS reference numbers are not shown as they are subject to change
- Profile Type, Enforcement Level (1 or 2 (1+2)), BitLocker (BL), NextGen (NG) and HKCU policy inclusion are parameterised:
  ```yaml
  cis_security_hardening_windows::cis_profile_type:      'domain'
  cis_security_hardening_windows::cis_enforcement_level: 2
  cis_security_hardening_windows::cis_include_bitlocker: true
  cis_security_hardening_windows::cis_include_nextgen:   true
  cis_security_hardening_windows::cis_include_hkcu:      true
  ```
- A reference list of rules enforced via the system registry is in the hiera folder for each Windows version, eg [here](data/windows/11/cis_include_rules.txt). Note that some additional rules are applied by Local Security Policy and Audit Policy resources however.
- Individual controls can be overridden by any of the following methods:
  - creating a optional hiera **array** for `cis_security_hardening_windows::cis_exclude_rules` containing rule titles to be subtracted from the default included hashes (note that some rules are managed by the local_security_policy or cis_auditpol):
    ```yaml
    cis_security_hardening_windows::cis_exclude_rules:
      - "(L1) Ensure 'Allow users to enable online speech recognition services is set to 'Disabled'"
      - "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    ```
  - creating a hiera hash containing keys with different values at a higher precedence (eg domain or node) and titled any of:
    ```yaml
    cis_security_hardening_windows::cis_level_1
    cis_security_hardening_windows::cis_level_2
    cis_security_hardening_windows::cis_bitlocker
    cis_security_hardening_windows::cis_nextgen
    cis_security_hardening_windows::cis_secpol_level_1
    cis_security_hardening_windows::cis_secpol_level_2
    cis_security_hardening_windows::cis_auditpol
    ```
   - other methods such as resource collectors to override registry key values if wrapping this module into your own class or control repo

 

## Reference

See the Puppet Strings [documentation](REFERENCE.md).



## Development

Github repo is available for contributions at https://github.com/canihavethisone/cis_security_hardening_windows


## Release Notes

See [changelog](CHANGELOG.md)
