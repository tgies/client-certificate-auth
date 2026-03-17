# Troubleshooting

## Security Notes

- Set `rejectUnauthorized: false` on your HTTPS server to let this middleware provide helpful error messages, rather than dropping connections silently.
- **When using header-based auth**, ensure your proxy strips certificate headers from external requests. See [Reverse Proxy Security Considerations](./reverse-proxy#security-considerations).
- Use `verifyHeader`/`verifyValue` as defense-in-depth when using header-based authentication. See [Verification Header](./reverse-proxy#verification-header-defense-in-depth).

## DEPTH_ZERO_SELF_SIGNED_CERT Error

This error occurs when the TLS layer rejects a self-signed client certificate. Set `rejectUnauthorized: false` in your HTTPS server options to let the middleware handle authorization instead of dropping the connection:

```javascript
const opts = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),
  requestCert: true,
  rejectUnauthorized: false  // Required for self-signed certs
};

https.createServer(opts, app).listen(443);
```

::: warning
In production, prefer certificates signed by your own CA rather than self-signed certificates. If you must use self-signed certs, ensure you set `ca` to the self-signed certificate so Node.js can verify the chain.
:::

## Certificate Not Reaching Middleware

If the middleware always rejects with "socket not authorized", verify that your HTTPS server has `requestCert: true` set. Without this option, Node.js will not ask clients for a certificate during the TLS handshake:

```javascript
const opts = {
  // ...
  requestCert: true,           // Must be true
  rejectUnauthorized: false
};
```

Also confirm that the client is actually sending a certificate. Tools like `openssl s_client` can verify this:

```bash
openssl s_client -connect localhost:443 -cert client.pem -key client.key
```

## Reverse Proxy Headers Not Working

When using header-based certificate extraction behind a reverse proxy:

1. **Verify the proxy is setting the correct header.** Check your proxy logs or use a test endpoint to inspect incoming headers.

2. **Ensure the `certificateSource` or `certificateHeader`/`headerEncoding` options match your proxy's configuration.** A mismatch will result in unparseable or missing certificate data.

3. **Confirm the proxy strips certificate headers from external requests.** If external clients can set these headers directly, they can bypass authentication. See [Security Considerations](./reverse-proxy#security-considerations).

4. **Consider using `verifyHeader`/`verifyValue`** for defense-in-depth, so the middleware validates that the proxy actually verified the certificate. See [Verification Header](./reverse-proxy#verification-header-defense-in-depth).

## WebSocket Authentication Failing

For WebSocket connections using the `ws` library with `noServer: true`, you must handle the `upgrade` event yourself and run the middleware manually. The middleware needs a response-like object and a `next` callback:

```javascript
server.on('upgrade', (req, socket, head) => {
  const middleware = clientCertificateAuth(checkAuth);
  const res = { writeHead: () => {}, end: () => {}, redirect: () => {} };

  middleware(req, res, (err) => {
    if (err) {
      socket.write(`HTTP/1.1 ${err.status} ${err.message}\r\n\r\n`);
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });
});
```

See the [WebSocket Support](./websocket) page for complete examples with both `ws` and Socket.IO.

## ESM vs CJS Import Differences

This package is an ES module with a CJS compatibility wrapper. The sync `require()` entry only supports socket-based mTLS; reverse proxy options require the async `load()` function. Subpath exports (`/helpers`, `/extractor`, `/parsers`) also need `load()` in CJS.

For a full breakdown of what's available in each mode, see the [TypeScript & CJS](./typescript) page.
