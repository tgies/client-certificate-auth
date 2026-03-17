import https from 'node:https';
import fs from 'node:fs';

const PORT = process.env.PORT || 3443;
const BASE = `https://localhost:${PORT}`;

const ca = fs.readFileSync('certs/ca.pem');
const cert = fs.readFileSync('certs/client.pem');
const key = fs.readFileSync('certs/client.key');

function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      `${BASE}${path}`,
      { ca, ...options },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on('error', reject);
  });
}

async function main() {
  console.log('Testing mTLS authentication...\n');

  // Test 1: Request WITH client certificate → should get 200
  const authenticated = await request('/', { cert, key });
  const pass1 = authenticated.status === 200;
  console.log(
    `${pass1 ? 'PASS' : 'FAIL'} — GET / with client cert: ${authenticated.status}`
  );
  if (pass1) {console.log(`       Response: ${authenticated.body}`);}

  // Test 2: Request WITHOUT client certificate → should get 401
  const unauthenticated = await request('/');
  const pass2 = unauthenticated.status === 401;
  console.log(
    `${pass2 ? 'PASS' : 'FAIL'} — GET / without client cert: ${unauthenticated.status}`
  );

  // Test 3: Public endpoint without cert → should get 200
  const health = await request('/health');
  const pass3 = health.status === 200;
  console.log(`${pass3 ? 'PASS' : 'FAIL'} — GET /health without cert: ${health.status}`);

  console.log(`\n${pass1 && pass2 && pass3 ? 'All tests passed!' : 'Some tests FAILED.'}`);
  process.exit(pass1 && pass2 && pass3 ? 0 : 1);
}

main().catch((err) => {
  console.error('Error:', err.message);
  console.error('Is the server running? Start it with: npm start');
  process.exit(1);
});
