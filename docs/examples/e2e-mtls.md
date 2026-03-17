# End-to-End mTLS Demo

This example demonstrates a complete mutual TLS authentication flow: generating certificates, configuring an HTTPS server with `client-certificate-auth`, and connecting with an authenticated client. You can run it locally to see mTLS in action from certificate generation to authenticated request.

## What You'll Need

- **Node.js >= 20**
- **OpenSSL** (for certificate generation; installed by default on most systems)

No external services or Docker containers are required. Everything runs locally.

## What the Example Does

The example consists of three parts:

1. **Certificate generation script** - Creates a CA (Certificate Authority), a server certificate signed by that CA, and a client certificate signed by the same CA. This simulates a real PKI setup where both sides trust the same authority.

2. **HTTPS server** - An Express application that uses `client-certificate-auth` middleware to require and validate client certificates. It demonstrates per-route protection (one protected route, one public route) and certificate inspection via `req.clientCertificate`.

3. **Test client** - A Node.js script that connects to the server with a client certificate and makes authenticated requests, showing both successful and failed authentication scenarios.

## Running It

From the repository root:

```bash
cd examples/e2e-mtls
npm install

# Generate certificates
npm run generate-certs

# Start the server
npm start

# In another terminal, run the test client
npm test
```

The server starts on `https://localhost:3443`. The test client makes requests with and without a client certificate, verifying both successful and rejected authentication.

## Understanding the Certificates

The certificate generation script creates a minimal PKI:

- **`ca.pem` / `ca.key`** - The Certificate Authority. Both the server and client trust this CA. In production, this would be your organization's internal CA or a trusted third-party CA.
- **`server.pem` / `server.key`** - The server's TLS certificate, signed by the CA. This identifies the server to clients.
- **`client.pem` / `client.key`** - The client's certificate, signed by the same CA. This is what `client-certificate-auth` validates. The subject CN is set to a known value that the server's authorization callback checks.

All certificates are self-signed by the example CA and valid for a short period. They are meant for local testing only.

## Understanding the Server

The server demonstrates several `client-certificate-auth` features:

- **Basic setup** - HTTPS server with `requestCert: true` and `rejectUnauthorized: false`, letting the middleware handle authorization decisions.
- **Per-route protection** - A protected route (`GET /`) requires a valid client certificate, while a public route (`GET /health`) does not.
- **Certificate inspection** - The protected route returns information from the authenticated client's certificate via `req.clientCertificate`.

This matches the patterns described in the [Getting Started](../guide/getting-started) guide, but as runnable code you can experiment with.

## Understanding the Test Client

The client script demonstrates:

- **Successful authentication** - Connecting with a valid client certificate and receiving a response.
- **Missing certificate** - Connecting without a certificate to show the middleware's rejection behavior.
- **Inspecting the response** - Reading certificate details that the server extracted and returned.

The client uses Node.js's built-in `https` module with TLS options (`cert`, `key`, `ca`) to present its client certificate during the handshake.

## Next Steps

After running the example, try modifying it to explore different features:

- Add [authorization helpers](../guide/helpers) like `allowCN()` or `allowFingerprints()` instead of a manual callback
- Enable [`includeChain: true`](../guide/getting-started#certificate-chain-access) to inspect the issuer certificate
- Add [audit logging hooks](../guide/getting-started#audit-logging-hooks) to see authentication events in the console
- Put the server behind a reverse proxy and switch to [header-based extraction](../guide/reverse-proxy)
