# Contributing

Thanks for your interest in contributing to client-certificate-auth!

## Development Setup

```bash
git clone https://github.com/tgies/client-certificate-auth.git
cd client-certificate-auth
npm install
```

## Running Tests

```bash
# Unit tests
npm test

# Unit tests with coverage (must maintain 100% branches/functions/lines/statements!)
npm run test:coverage

# E2E proxy tests (requires Docker)
npm run test:e2e

# All tests
npm run test:all

# Full check (lint + typecheck + coverage)
npm run check
```

## Code Style

- Run `npm run lint` before committing
- TypeScript strict mode is enabled
- All public APIs should have JSDoc comments

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure tests pass and coverage stays at 100%
5. Commit with conventional commit messages (e.g., `feat:`, `fix:`, `docs:`)
6. Push and open a pull request

## Adding New Features

- Add tests for any new functionality
- Update README.md if adding user-facing features
- Update TypeScript types as needed
- Add entries to CHANGELOG.md under `## [Unreleased]`

## Reporting Bugs

Open an issue with:
- Node.js version
- Minimal reproduction case
- Expected vs actual behavior

## Security Issues

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
