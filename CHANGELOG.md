# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.2.2] - 2027-09-23
- Ci updates

## [0.2.1] - 2027-09-23
- Ci updates

## [0.2.0] - 2027-09-23

- Add multiple TSIG authentication keys
- TSIG configuration now requires `TSIG_FILE`; legacy `TSIG_KEY` / `TSIG_SECRET` / `TSIG_ALGORITHM` environment variables were removed.
- Kubernetes deployment manifest now mounts TSIG YAML from secret as `TSIG_FILE`.
- Documentation/examples updated to TSIG-file-only configuration.

## [0.1.0] - 2026-04-02

### Added
- Initial implementation of RFC2136 DNS UPDATE server
- TSIG authentication support (HMAC-SHA256, HMAC-SHA512, HMAC-SHA1)
- DNS UPDATE message parser for A and AAAA records
- Kubernetes client for creating/updating/deleting DNSEndpoint resources
- Zone-scoped security with allowed zones configuration
- UDP and TCP listeners on port 53
- Comprehensive test suite
- Docker containerization support
- Kubernetes deployment manifests
- Detailed documentation (README, EXAMPLES, CONTRIBUTING)
- Makefile for common development tasks
- GitHub Actions CI/CD pipeline

### Features
- ✅ RFC2136 DNS UPDATE protocol support (UDP & TCP)
- ✅ TSIG authentication and validation
- ✅ A and AAAA record support
- ✅ Create, update, and delete operations
- ✅ Zone-scoped access control
- ✅ Kubernetes DNSEndpoint CRD integration
- ✅ ExternalDNS compatibility
- ✅ Stateless and idempotent design
- ✅ Secure by default

### Security
- TSIG authentication required for all updates
- Zone-based authorization
- Minimal RBAC permissions
- Kubernetes secrets for sensitive data
- Input validation and sanitization

[Unreleased]: https://github.com/tJouve/ddnsbridge4extdns/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tJouve/ddnsbridge4extdns/releases/tag/v0.1.0
