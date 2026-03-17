# WebSocket Support

WebSocket connections work seamlessly with mTLS because the TLS handshake occurs before the HTTP upgrade request. The middleware authenticates the upgrade request just like any other HTTP request, so your WebSocket connections are protected by the same certificate checks as your REST endpoints.

## With the `ws` Library

When using the [`ws`](https://github.com/websockets/ws) library with `noServer: true`, you handle the `upgrade` event yourself and run the middleware manually. The middleware needs a response-like object and a `next` callback:

```javascript
import https from 'node:https';
import { WebSocketServer } from 'ws';
import clientCertificateAuth from 'client-certificate-auth';

const server = https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),
  requestCert: true,
  rejectUnauthorized: false,
});

const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws, req) => {
  // Certificate is available on req.clientCertificate
  console.log(`Client connected: ${req.clientCertificate.subject.CN}`);

  ws.on('message', (data) => {
    ws.send(`Echo: ${data}`);
  });
});

// Authenticate upgrade requests
server.on('upgrade', (req, socket, head) => {
  const middleware = clientCertificateAuth((cert) => {
    return cert.subject.CN === 'trusted-client';
  });

  // Minimal response object for middleware compatibility
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

server.listen(443);
```

The key details in this pattern:

- **`noServer: true`** tells `ws` not to bind to a server directly, so you can intercept the upgrade.
- The **stub `res` object** satisfies the middleware's Express-compatible interface without sending any real HTTP response.
- On authentication failure, the raw socket is used to write an HTTP error response and then destroyed.
- On success, `wss.handleUpgrade` completes the WebSocket handshake and the `req.clientCertificate` is available in the connection handler.

## With Socket.IO

Socket.IO provides its own middleware mechanism. Use it to run certificate authentication before connections are established:

```javascript
import https from 'node:https';
import { Server } from 'socket.io';
import clientCertificateAuth from 'client-certificate-auth';

const server = https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('ca.pem'),
  requestCert: true,
  rejectUnauthorized: false,
});

const io = new Server(server);

// Socket.IO middleware for mTLS authentication
io.use((socket, next) => {
  const req = socket.request;
  const res = { writeHead: () => {}, end: () => {}, redirect: () => {} };

  const middleware = clientCertificateAuth((cert) => {
    return cert.subject.CN === 'trusted-client';
  });

  middleware(req, res, (err) => {
    if (err) {
      return next(new Error('Authentication failed'));
    }
    // Attach certificate info to socket for later use
    socket.clientCert = req.clientCertificate;
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.clientCert.subject.CN}`);
});

server.listen(443);
```

In this pattern, the certificate is attached to the Socket.IO `socket` object so it's accessible in all event handlers for that connection. Socket.IO's middleware converts any `Error` passed to `next()` into a connection rejection.
