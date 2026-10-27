# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-27

### Added
- `deploy/install.sh <ref>`: installs a tag, branch or commit as a hardened systemd service, with
  one virtualenv per commit, an atomic switch, removal of units a release no longer ships, and
  rollback by installing an older ref. `deploy/uninstall.sh` reverses it.
- `deploy/check-host.sh`: read-only report of what Netwatch depends on in a host.
- `netwatch-skeleton.service`: placeholder service that proves the deployment path (Phase 0).
- `netwatch --version`, including the deployed git revision.
- SQLite storage in WAL mode with schema versioning.
- Logging to the journal with syslog priorities.
- CI: ruff, pytest on Python 3.12 to 3.14 (Linux) and 3.14 (Windows), shellcheck, a unit
  hardening threshold, and an install, run and uninstall on a real systemd host.

[Unreleased]: https://github.com/iMovingTarget/netwatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/iMovingTarget/netwatch/releases/tag/v0.1.0
