# Changelog

All notable changes to this project will be documented in this file.

## Release 2.0.0

**Features**
- Update Windows 11 Enterprise benchamrk to CIS v4.0.0
-

**Bugfixes**
- Improve regex deriving regkey and move 2 hardcoded values to hiera


## Release 1.0.1

**Bugfixes**
- Add validation that the following required parameters are set by the implementer:
  - logon_banner
  - logon_message
  - administrator_newname
  - administrator_newpassword
  - disabled_guest_newname


## Release 1.0.0

**Breaking Changes**
- Rename 'disabled_administrator' references and hiera to 'administrator' as enabling is configurable

**Features**
- Update dependency versions

**Bugfixes**
- Remove references to legacy facts that were breaking testing
- Improve Puppet 8 compatibility testing


## Release 0.2.3

**Features**

**Bugfixes**
- Correct cis_level_1 filename in /data/windows/11
- Correct wrong registry keys from CIS benchmark
- Enable Defender enforcement on Windows 11 (still disabled on Windows 10 due to idempotency issue after Windows Update)


## Release 0.2.2

**Features**

**Bugfixes**
- Correct commented secpol title


## Release 0.2.1

**Features**

**Bugfixes**
- Correct references in readme

**Known Issues**


## Release 0.2.0

**Features**
- Enhance user management including local Administrator account

**Bugfixes**

**Known Issues**


## Release 0.1.1

**Features**
Initial release

**Bugfixes**

**Known Issues**
