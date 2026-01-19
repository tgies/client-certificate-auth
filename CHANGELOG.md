# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-24

### Breaking Changes

- **Node.js 18+ required** (previously supported Node 0.6-0.10)
- **ES Modules by default** — use `import` instead of `require`
- **`req.socket` instead of `req.connection`** — aligns with Node.js core API changes
- **No automatic HTTP→HTTPS redirect** — removed `redirectInsecure` option entirely

### Added

- **Reverse proxy/load balancer support** — extract certificates from HTTP headers
  - Presets: `aws-alb`, `envoy`, `cloudflare`, `traefik`
  - Custom headers with configurable encoding (`url-pem`, `base64-der`, `xfcc`, `rfc9440`)
  - `fallbackToSocket` option for hybrid deployments
- **Certificate attached to request** — `req.clientCertificate` available in downstream handlers
- **Authorization helpers** — pre-built callbacks via `client-certificate-auth/helpers`
  - `allowCN`, `allowFingerprints`, `allowOU`, `allowOrganization`, `allowEmail`
  - `allowSerial`, `allowSAN`, `allowIssuer`, `allowSubject`
  - `allOf`, `anyOf` combinators
- **Granular authorization feedback** — throw custom errors for specific rejection reasons
- **Certificate chain access** — `includeChain` option for PKI scenarios
- **Verification header support** — `verifyHeader` and `verifyValue` for defense-in-depth
- TypeScript type declarations with `ClientCertRequest` interface
- ES Module support with conditional exports
- Promise/async callback support (callback receives `(cert, req)` signature)
- CommonJS wrapper with option validation
- GitHub Actions CI (Node 18, 20, 22, 24)
- 100% test coverage enforced via Codecov
- Automated npm publishing with provenance on version tags
- SECURITY.md with GitHub Private Vulnerability Reporting
- CONTRIBUTING.md with development guidelines

### Changed

- Migrated from Travis CI to GitHub Actions
- Migrated test runner from Mocha to Jest
- Updated all dependencies to latest versions
- Replaced `should` assertion library with Node.js built-in `assert`
- Improved error messages with authorization error details

### Removed

- Support for Node.js < 18
- Legacy callback signature (`function(cert, done)`) — use Promises instead
- `redirectInsecure` option — use reverse proxy or separate middleware if needed

### Security

- Removed automatic HTTPS redirect to prevent MITM exposure on initial HTTP request
- Added `verifyHeader`/`verifyValue` options to validate proxy certificate verification status

## [0.3.0] - 2013-04-30

- Initial stable release
- Support for Node.js 0.6, 0.8, 0.10
- Synchronous and callback-based authorization
