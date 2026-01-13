# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-24

### ⚠️ Breaking Changes

- **Node.js 18+ required** (previously supported Node 0.6-0.10)
- **ES Modules by default** — use `import` instead of `require`
- **`req.socket` instead of `req.connection`** — aligns with Node.js core API changes
- **HTTPS redirect is now opt-in** — pass `{ redirectInsecure: true }` to enable

### Added

- TypeScript type declarations
- ES Module support with conditional exports
- Promise/async callback support
- `options` parameter with `redirectInsecure` option
- GitHub Actions CI (Node 18, 20, 22)
- 100% test coverage

### Changed

- Migrated from Travis CI to GitHub Actions
- Updated all dependencies to latest versions
- Replaced `should` assertion library with Node.js built-in `assert`
- Improved error messages with authorization error details

### Removed

- Support for Node.js < 18
- Legacy callback signature (`function(cert, done)`) — use Promises instead
- Automatic HTTP→HTTPS redirect (now opt-in)

### Security

- HTTPS redirect behavior is now opt-in to prevent MITM exposure on initial HTTP request

## [0.3.0] - 2013-04-30

- Initial stable release
- Support for Node.js 0.6, 0.8, 0.10
- Synchronous and callback-based authorization
