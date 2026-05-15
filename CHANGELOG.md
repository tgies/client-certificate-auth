# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-05-15

### Changed (BREAKING)

- **Validation callbacks must return or resolve exactly `true`** ([#105](https://github.com/tgies/client-certificate-auth/pull/105)) — previously the middleware authorized on any truthy value, so callbacks returning a non-empty string, a number, an object, or a thenable resolving to a truthy non-boolean would silently pass authentication. Both the ESM and CJS paths now require strict `=== true`; all other values (including non-`true` truthy values and `Promise<truthy-non-boolean>`) cause a 401. The fix also closes a fail-open with non-native thenables: `instanceof Promise` is replaced with a duck-typed `isThenable` check (matching Promises/A+ §1.2, an object or function with a callable `.then`), so both `{ then(resolve) { resolve(false); } }` and function-valued thenables correctly reject rather than being passed through as truthy values. Migration: callbacks that previously returned ad-hoc truthy values (e.g., `return cert.subject.CN`) must now explicitly return `true`/`false`. The helper composition functions in `lib/helpers.js` (`allOf`, `anyOf`) already enforced strict-true, so middleware behavior is now consistent with helpers.

### Added

- **Constructor-time validation of header options** ([#106](https://github.com/tgies/client-certificate-auth/pull/106)) — `clientCertificateAuth()` now throws at construction when `certificateSource` is not a known preset, when `headerEncoding` is not a documented value, or when `certificateHeader` is set without `headerEncoding` (and no `certificateSource` preset to supply one). Uses `Object.hasOwn` for the preset allow-list so inherited `Object.prototype` keys (`toString`, `constructor`, etc.) are also rejected. Mirrors the existing `verifyHeader`/`verifyValue` pairing check. Typos that previously caused silent header-extraction failure (falling through to socket extraction when `fallbackToSocket: true`, or returning 401 otherwise) now surface as a clear error at app startup.

### Types

- **`ValidationCallback` widened to `PromiseLike<boolean>`** ([#105](https://github.com/tgies/client-certificate-auth/pull/105)) — both `.d.ts` and `.d.cts` change the async return type from `Promise<boolean>` to `PromiseLike<boolean>` to match the now-permissive runtime. TypeScript consumers returning a `PromiseLike<boolean>` or any custom/third-party thenable no longer need a cast. Native `Promise` extends `PromiseLike`, so existing code that returned `Promise<boolean>` continues to typecheck unchanged.

### Tests

- Inverted the three truthy-non-boolean tests in `test-unit-clientCertificateAuth.js` to assert 401 rejection.
- Added thenable coverage for both ESM and CJS: an object thenable resolving to `true` authorizes, resolving to `false` rejects, resolving to a truthy non-boolean rejects.
- Added function-valued thenable coverage (both true and false branches) in both ESM and CJS.
- Added a `constructor option validation` describe block covering unknown `certificateSource`, unknown `headerEncoding`, `certificateHeader` without an encoding source, and inherited `Object.prototype` key rejection (`toString`, `constructor`, `hasOwnProperty`, `__proto__`).
- Added a TypeScript type test that returns a plain `PromiseLike<boolean>` (not a native `Promise`) to lock in the widened contract.

## [1.3.4] - 2026-04-30

### Fixed

- **`parseXfcc` chain handling for Envoy** ([#85](https://github.com/tgies/client-certificate-auth/pull/85)) — Envoy's text-format XFCC header carries the leaf cert in `Cert=` and (when chain-forwarding is enabled) the full chain in `Chain=`. Pre-fix, `parseXfcc` handed multi-block PEM to `X509Certificate` directly; on Node 22+ this returns just the leaf with no `issuerCertificate`, silently losing chain data for `includeChain: true` consumers. The parser now scans for PEM block boundaries via `indexOf` and links the chain via `issuerCertificate`, mirroring the AWS path. When XFCC carries both `Cert` and `Chain`, the parser prefers `Chain` because per the Envoy spec it carries strictly more information. The shared `splitPemBlocks` and `chainFromMultiBlockPem` helpers are now factored out so the AWS and XFCC paths share one tested chain-parsing implementation.
- **`allOf()` zero-callback vacuous truth** ([#87](https://github.com/tgies/client-certificate-auth/pull/87)) — calling `allOf()` with no callbacks no longer silently authorizes all certificates. `[].every(...)` returns `true` in JavaScript (vacuous truth), so an empty composed policy reaching `allOf()` would authorize any certificate. Empty callback lists now return `() => false`, matching the v1.3.2 fix for `allowIssuer({})` and `allowSubject({})`. `anyOf()` was already safe because `[].some(...)` returns `false`.

### Tests

- Added XFCC parser tests covering multi-block chain parsing, prefer-Chain semantic in both field orders, mid-chain bad block, all-blocks-bad, unterminated trailing block, and malformed URL encoding.
- Added a 3-tier intermediate chain test infrastructure (`generateIntermediateChain()` in `test-helpers.js`) and a chain-only Envoy listener (`docker/envoy/envoy-chain-only.yaml`) so E2E tests observe `issuerCertificate` preservation through real proxies.
- Inverted the existing zero-callback pinning test for `allOf()` to assert fail-closed behavior.

## [1.3.3] - 2026-04-28

### Fixed

- **`parseUrlPemAws` chain handling for AWS API Gateway and ALB** ([#82](https://github.com/tgies/client-certificate-auth/issues/82), [#83](https://github.com/tgies/client-certificate-auth/pull/83)) — AWS sends the full client cert chain as concatenated URL-encoded PEM blocks in `X-Amzn-Mtls-Clientcert`. Node's `X509Certificate` constructor throws on multi-block PEM input, so `parseUrlPemAws` was returning `null` for any AWS deployment with intermediate CAs, silently failing authentication entirely. The parser now scans the decoded blob for PEM block boundaries via `indexOf` (O(N) in input length) and links the chain via `issuerCertificate`, mirroring the chain handling in `parseBase64Der` for Traefik and Cloudflare.

### Tests

- Added integration tests in `test-unit-extractor.js` exercising the AWS-documented multi-PEM format end-to-end (with and without `includeChain`).
- Added parser-level tests in `test-unit-parsers.js` for the new chain-parsing path: a chain with one bad block, a chain where every block is bad, malformed URL encoding, and a truncated final block with no END marker.

## [1.3.2] - 2026-02-23

### Fixed

- **`allowIssuer({})` / `allowSubject({})` vacuous truth** — passing an empty match object no longer silently accepts all certificates. `Object.entries({}).every(...)` returns `true` in JavaScript (vacuous truth), causing these helpers to authorize any certificate with an issuer/subject field. Empty match objects now return `() => false`, consistent with all other helpers (`allowCN([])`, `allowOU([])`, etc.)

### Tests

- Added empty match object tests for `allowIssuer` and `allowSubject`

## [1.3.1] - 2026-02-17

### Fixed

- **Multi-valued DN field handling** — Node.js returns `string[]` (not `string`) for certificate DN attributes with multiple values (e.g. `OU=Engineering, OU=DevTeam`). `allowCN`, `allowOU`, `allowOrganization`, `allowIssuer`, `allowSubject`, and `allowEmail` silently returned `false` for such certificates. Added a `toArray()` normalizer that coerces `string | string[]` to `string[]` before comparison. Ref: [DefinitelyTyped/DefinitelyTyped#74538](https://github.com/DefinitelyTyped/DefinitelyTyped/issues/74538).

### Tests

- Added 17 tests covering multi-valued and null/undefined field scenarios.

## [1.3.0] - 2026-02-16

### Added

- **CJS subpath exports for `/helpers`, `/parsers`, `/extractor`** — CJS consumers can now access submodule exports via async `load()` wrappers, matching the established pattern from the main module's CJS wrapper. Each wrapper dynamically imports the ESM original, avoiding code duplication across ~750 lines of implementation.

### Tests

- Added 12 CJS unit tests for the three subpath wrappers and CJS type tests in `test-typescript-types.ts`.

## [1.2.0] - 2026-02-09

### Added

- **Certificate extractor module** — `extractClientCertificate()` function exported from `client-certificate-auth/extractor` provides framework-agnostic certificate extraction
  - Returns structured `{ success, certificate, reason }` result object instead of using middleware pattern
  - Supports all certificate sources: socket-based and header-based (AWS ALB, Envoy, Cloudflare, Traefik, custom)
  - Same configuration options as middleware (`certificateSource`, `fallbackToSocket`, `includeChain`, `verifyHeader`, etc.)
  - Enables building adapters for non-Express frameworks (Koa, Fastify, Hapi, etc.)
  - Useful for custom authentication flows that need certificate extraction without middleware overhead

### Tests

- Added comprehensive unit tests for `extractClientCertificate()` covering all extraction modes and error paths

## [1.1.3] - 2026-02-09

### Fixed

- **Duplicate header injection guard** — `getCertificateFromHeaders` now rejects `string[]` header values (caused by duplicate HTTP headers) instead of passing them to parsers, which would produce undefined behavior. The `verifyHeader` check also explicitly rejects array values, failing closed with a clear error message.

### Tests

- Added malformed header + `fallbackToSocket: true` test to verify fallback when the certificate header is present but unparseable
- Added mixed valid/invalid chain tests for `parseBase64Der` to pin the "accept partial" semantic (invalid certs are silently dropped, valid certs are chained)
- Added CJS `load()` full-feature contract test verifying header-based options work end-to-end through the async ESM bridge

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

[1.3.4]: https://github.com/tgies/client-certificate-auth/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/tgies/client-certificate-auth/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/tgies/client-certificate-auth/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/tgies/client-certificate-auth/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/tgies/client-certificate-auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/tgies/client-certificate-auth/compare/v1.1.3...v1.2.0
[1.1.3]: https://github.com/tgies/client-certificate-auth/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/tgies/client-certificate-auth/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/tgies/client-certificate-auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/tgies/client-certificate-auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/tgies/client-certificate-auth/compare/0.3.0...v1.0.0
[0.3.0]: https://github.com/tgies/client-certificate-auth/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/tgies/client-certificate-auth/releases/tag/0.2.1
