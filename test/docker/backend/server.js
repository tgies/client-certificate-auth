/**
 * Backend server for E2E tests that uses our actual middleware.
 * 
 * Uses path-based routing to determine which header configuration to use:
 * - /nginx → X-SSL-Client-Cert (url-pem)
 * - /envoy → X-Forwarded-Client-Cert (xfcc)
 * - /traefik → X-Forwarded-Tls-Client-Cert (url-pem)
 */

import http from 'node:http';
import clientCertificateAuth from 'client-certificate-auth';

// Path-based configuration
const PATH_CONFIGS = {
    '/nginx': {
        certificateHeader: 'x-ssl-client-cert',
        headerEncoding: 'url-pem',
    },
    '/envoy': {
        certificateHeader: 'x-forwarded-client-cert',
        headerEncoding: 'xfcc',
    },
    '/traefik': {
        certificateHeader: 'x-forwarded-tls-client-cert',
        headerEncoding: 'base64-der',
    },
};

const server = http.createServer((req, res) => {
    // Extract the proxy type from the path
    const pathMatch = req.url.match(/^\/(nginx|envoy|traefik)/);

    if (!pathMatch) {
        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 400;
        res.end(JSON.stringify({
            success: false,
            error: 'Unknown path. Use /nginx, /envoy, or /traefik',
            status: 400,
        }));
        return;
    }

    const proxyType = pathMatch[1];
    const config = PATH_CONFIGS[`/${proxyType}`];

    // Create middleware with the appropriate config
    const middleware = clientCertificateAuth(
        (cert) => {
            req.clientCN = cert.subject.CN;
            return true;
        },
        config
    );

    middleware(req, res, (err) => {
        res.setHeader('Content-Type', 'application/json');

        if (err) {
            res.statusCode = err.status || 500;
            res.end(JSON.stringify({
                success: false,
                error: err.message,
                status: err.status,
            }));
        } else {
            res.statusCode = 200;
            res.end(JSON.stringify({
                success: true,
                clientCN: req.clientCN,
                proxyType: proxyType,
                headerUsed: config.certificateHeader,
            }));
        }
    });
});

server.listen(3000, '0.0.0.0', () => {
    console.log('E2E Backend with path-based routing listening on port 3000');
});
