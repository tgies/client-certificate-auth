# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-02-07

### Fixed

- **`allowFingerprints` SHA-256 support** — fingerprints with `SHA256:` prefix are now correctly compared against `cert.fingerprint256` instead of `cert.fingerprint` (SHA-1), fixing silent match failures when using SHA-256 fingerprints
- **TypeScript type definitions** — `ClientCertResponse` aligned to `ServerResponse` (removed vestigial `redirect()`), `ValidationCallback` signature corrected in helpers declarations

### Changed

- Added troubleshooting section and expanded CommonJS documentation in README
- Added `npm audit --audit-level=moderate` security gate to publish workflow
- Pinned GitHub Actions to SHA hashes for supply chain security
- Pinned Docker test infrastructure images to specific versions with healthchecks
- Added Dependabot configuration for npm and GitHub Actions
- Added security-focused ESLint rules (`no-eval`, `no-implied-eval`, `no-new-func`)
- Added Stryker mutation score thresholds
- Added GitHub issue and pull request templates
- Optimized npm package metadata for discoverability

## [1.1.1] - 2026-02-07

### Fixed

- **Partial `verifyHeader`/`verifyValue` throws** — providing only one of the pair now throws at construction instead of silently skipping the verification check
- **Multi-element Envoy XFCC headers** — `parseXfcc()` now uses quote-aware comma splitting to extract the first proxy hop's certificate, fixing incorrect parsing in multi-hop Envoy deployments and headers with quoted `Subject` fields containing commas
- **CJS `load()` return type** — the TypeScript declaration for `require('client-certificate-auth').load()` now correctly reflects the full ESM options (e.g., `certificateSource`, `fallbackToSocket`)
- **`req` passed to authorization callback** — the callback now receives `(cert, req)` as documented, enabling per-request authorization logic
- **`allOf`/`anyOf` forward `req` to sub-callbacks** — combinator helpers now pass `req` through to composed validation callbacks, matching the `ValidationCallback` type contract

### Changed

- Publish workflow uses `lts/*` Node.js instead of hardcoded `25.x`
- Publish workflow runs `npm run typecheck` before tests
- Added `.editorconfig` for consistent editor settings
- Added callback type validation (throws `TypeError` if callback is not a function)
- Updated copyright year in `parsers.js` and `parsers.d.ts` to 2026
- Added `onAuthenticated`/`onRejected` to JSDoc `@typedef` for `ClientCertificateAuthOptions`
- Added ESM-only note for `/helpers` and `/parsers` subpath exports in README

## [1.1.0] - 2026-02-05

### Added

- **Audit logging hooks** — `onAuthenticated` and `onRejected` callbacks for logging authentication decisions
  - Fire-and-forget: hooks don't block request processing
  - Error-safe: hook errors are caught and logged, never affect the request
  - Async-friendly: async hooks run in background
- **WebSocket support documentation** — examples for `ws` and Socket.IO libraries
- WebSocket integration tests verifying mTLS works with upgrade requests

### Fixed

- **TypeScript type augmentation** — `Error.status` now visible to external consumers
  - Replaced `/// <reference path>` directive with inline `declare global` syntax

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

## [0.3.0] - 2014-03-17

### Added
- Support for asynchronous authorization callback

## [0.2.1] - 2013-05-04

- Initial stable release
- Support for Node.js 0.6, 0.8, 0.10
- Synchronous and callback-based authorization
- Fix handling of empty certificates
- Unit testing with mocks

[1.1.2]: https://github.com/tgies/client-certificate-auth/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/tgies/client-certificate-auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/tgies/client-certificate-auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/tgies/client-certificate-auth/compare/0.3.0...v1.0.0
[0.3.0]: https://github.com/tgies/client-certificate-auth/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/tgies/client-certificate-auth/releases/tag/0.2.1
