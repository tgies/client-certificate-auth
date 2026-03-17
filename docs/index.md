---
layout: home

hero:
  name: client-certificate-auth
  text: mTLS for Node.js
  tagline: Express middleware, reverse proxy support, and authorization helpers for client certificate authentication
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /api/
    - theme: alt
      text: View on GitHub
      link: https://github.com/tgies/client-certificate-auth

features:
  - title: Direct TLS & Reverse Proxy
    details: Works with socket-based mTLS and header-based cert extraction from AWS ALB, Envoy, Cloudflare, Traefik, nginx, HAProxy, and more.
  - title: Authorization Helpers
    details: Pre-built validators for CN, fingerprint, issuer, OU, SAN, email, and serial — with allOf/anyOf combinators.
  - title: Framework Agnostic
    details: Express middleware out of the box. Use extractClientCertificate() to build adapters for Koa, Fastify, Hapi, or any Node.js framework.
  - title: Battle-Tested
    details: 100% test coverage, mutation testing, and E2E tests against real proxy containers. Dual ESM/CJS with full TypeScript types.
---
