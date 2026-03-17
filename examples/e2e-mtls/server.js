import express from 'express';
import https from 'node:https';
import fs from 'node:fs';
import clientCertificateAuth from 'client-certificate-auth';

const app = express();

// Only allow clients with CN=trusted-client
const checkAuth = (cert) => cert.subject.CN === 'trusted-client';

// Protected route — requires valid client certificate
app.get('/', clientCertificateAuth(checkAuth), (req, res) => { // lgtm[js/missing-rate-limiting]
  res.json({
    message: 'Authenticated!',
    client: req.clientCertificate.subject.CN,
    fingerprint: req.clientCertificate.fingerprint256,
  });
});

// Public route — no certificate required
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const server = https.createServer(
  {
    key: fs.readFileSync('certs/server.key'),
    cert: fs.readFileSync('certs/server.pem'),
    ca: fs.readFileSync('certs/ca.pem'),
    requestCert: true,
    rejectUnauthorized: false, // lgtm[js/disabling-certificate-validation]
  },
  app
);

const PORT = process.env.PORT || 3443;
server.listen(PORT, () => {
  console.log(`mTLS server listening on https://localhost:${PORT}`);
  console.log('  GET /       — requires client certificate');
  console.log('  GET /health — public (no cert needed)');
});
