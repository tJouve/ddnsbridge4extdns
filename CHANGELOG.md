# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of RFC2136 DNS UPDATE server
- TSIG authentication support (HMAC-SHA256, HMAC-SHA512, HMAC-SHA1, HMAC-MD5)
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

## [0.1.0] - 2024-XX-XX

### Added
- Initial release

[Unreleased]: https://github.com/tJouve/ddnstoextdns/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tJouve/ddnstoextdns/releases/tag/v0.1.0
