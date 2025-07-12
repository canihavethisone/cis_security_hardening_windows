# Changelog

All notable changes to this project will be documented in this file.

## Release 2.1.1

**Features**
- Add missing Windows 10 key not shown in CIS v4.0.0 changelog
- Correct Windows 10 regkey for 'LSASS to run as a protected process' as per documented ADMX template bug (see CIS PDF)


## Release 2.1.0

**Features**
- Update Windows 10 Enterprise benchmark to CIS v4.0.0
- Update Windows 11 Standalone benchmark to CIS v4.0.0
- Improve selector in remote_desktop class
- Reduce documentation to main init class

**Bugfixes**
- Fix missing single quote in 'LxssManager' rule title (10 & 11)


## Release 2.0.0

**Features**
- Update Windows 11 Enterprise benchmark to CIS v4.0.0
- Switched to OpenVox for acceptance testing framework and added to metadata.json
- New values have been excluded from standalone profile as there is no standalone v4.0.0 benchmark at this time
- Update dependencies to current

**Bugfixes**
- Improve regex deriving regkey to allow 2 hardcoded keys with backslash values to move into hiera
- Remove duplicate rules
- Fix incorrect benchmark rule titles


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
