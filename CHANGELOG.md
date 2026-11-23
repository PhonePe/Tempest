# Changelog

All notable changes to Tempest are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-23

### Added

- Initial public release of Tempest, a release-coherent TFTP and HTTP
  network-boot artifact server.
- TFTP serves only artifacts that belong to a published release. A client
  without a live boot session receives only members of the active `default`
  boot profile release, and a pinned session resolves strictly within its
  manifest. Files placed under the artifact root are not served over TFTP
  until they are published, and no setting restores unrestricted root
  serving. See [`UPGRADING.md`](UPGRADING.md).

[Unreleased]: https://github.com/PhonePe/Tempest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PhonePe/Tempest/tree/v0.1.0
