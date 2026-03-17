# End-to-End mTLS Example

Demonstrates mutual TLS authentication with `client-certificate-auth`.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Generate CA, server, and client certificates
npm run generate-certs

# 3. Start the server (in one terminal)
npm start

# 4. Run the test client (in another terminal)
npm test
```

## What Happens

- `generate-certs.sh` creates a CA and signs a server + client certificate
- `server.js` starts an HTTPS server that requires client certs on `GET /`
- `test-client.js` makes requests with and without a client cert, verifying:
  - `GET /` with cert → **200** (authenticated)
  - `GET /` without cert → **401** (rejected)
  - `GET /health` without cert → **200** (public route)
