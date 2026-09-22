# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Raising verification methods with distinct invalid-token, expired-token, and invalid-code errors.
- Configuration and issuance validation, including payload types and code length limits.
- Rails boot and PostgreSQL lifecycle tests for single use, retries, and resend replacement.
- Concise usage documentation with session and database integration examples.

### Changed

- Tokens carry an authenticated expiry checked by OtpCourier. Older token formats are unsupported.
- Key maps are read-only. Configure secrets through setters or the key management methods.

### Fixed

- Retired Rails fallback keys no longer decrypt tokens or return during application boot.

## [0.1.0] - 2026-09-21

### Added

- Initial release.
