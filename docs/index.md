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

## What is this?

`client-certificate-auth` authenticates HTTP clients by their TLS client certificates (mutual TLS, or mTLS). Instead of a password, API key, or bearer token, the client presents an X.509 certificate during the TLS handshake, and the server checks that it was issued by a CA it trusts. The certificate is the credential.

Typical uses: service-to-service APIs where each caller holds its own certificate, machine and device authentication (CI runners, IoT fleets), restricting sensitive internal endpoints to known clients, and certificate-based user login in enterprise PKI environments.

The library extracts the verified certificate from the request wherever your TLS terminates (a Node.js `https` server, a reverse proxy or load balancer that forwards it in a header, an [AWS Lambda event](/guide/lambda), or a [Web-standard `Request`](/guide/fetch)) and passes it to your authorization logic as a standard `tls.PeerCertificate` object. Start with the [Getting Started guide](/guide/getting-started).
