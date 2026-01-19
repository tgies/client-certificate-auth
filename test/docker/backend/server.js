/**
 * Backend server for E2E tests that uses our actual middleware.
 * 
 * Uses path-based routing to determine which header configuration to use:
 * - /nginx → X-SSL-Client-Cert (url-pem)
 * - /envoy → X-Forwarded-Client-Cert (xfcc)
 * - /traefik → X-Forwarded-Tls-Client-Cert (url-pem)
 * - /helpers/... → Tests using authorization helper functions
 */

import http from 'node:http';
import clientCertificateAuth from 'client-certificate-auth';
import { allowCN, allowIssuer, allOf, anyOf } from 'client-certificate-auth/helpers';

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

// Helper-based validation configurations (using nginx headers)
const HELPER_CONFIGS = {
    '/helpers/allow-cn': {
        headerConfig: PATH_CONFIGS['/nginx'],
        validator: allowCN(['Test Client']),
    },
    '/helpers/allow-cn-reject': {
        headerConfig: PATH_CONFIGS['/nginx'],
        validator: allowCN(['Wrong Client']),
    },
    '/helpers/allow-issuer': {
        headerConfig: PATH_CONFIGS['/nginx'],
        validator: allowIssuer({ CN: 'Test CA' }),
    },
    '/helpers/all-of': {
        headerConfig: PATH_CONFIGS['/nginx'],
        validator: allOf(allowCN(['Test Client']), allowIssuer({ CN: 'Test CA' })),
    },
    '/helpers/any-of': {
        headerConfig: PATH_CONFIGS['/nginx'],
        validator: anyOf(allowCN(['Wrong Client']), allowCN(['Test Client'])),
    },
    // Verification header test routes
    '/helpers/verify-header': {
        headerConfig: {
            ...PATH_CONFIGS['/nginx'],
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'SUCCESS',
        },
        validator: () => true,
    },
    '/helpers/verify-header-wrong-value': {
        headerConfig: {
            ...PATH_CONFIGS['/nginx'],
            verifyHeader: 'X-SSL-Client-Verify',
            verifyValue: 'WRONG_VALUE', // This should always fail
        },
        validator: () => true,
    },
};

const server = http.createServer((req, res) => {
    // Check for helper routes first
    const helperMatch = req.url.match(/^\/helpers\/[a-z-]+/);
    if (helperMatch) {
        const helperPath = helperMatch[0];
        const helperConfig = HELPER_CONFIGS[helperPath];

        if (!helperConfig) {
            res.setHeader('Content-Type', 'application/json');
            res.statusCode = 400;
            res.end(JSON.stringify({
                success: false,
                error: `Unknown helper path: ${helperPath}`,
                status: 400,
            }));
            return;
        }

        const middleware = clientCertificateAuth(helperConfig.validator, helperConfig.headerConfig);

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
                    clientCN: req.clientCertificate?.subject?.CN,
                    helperPath: helperPath,
                    headerUsed: helperConfig.headerConfig.certificateHeader,
                }));
            }
        });
        return;
    }

    // Extract the proxy type from the path
    const pathMatch = req.url.match(/^\/(nginx|envoy|traefik)/);

    if (!pathMatch) {
        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 400;
        res.end(JSON.stringify({
            success: false,
            error: 'Unknown path. Use /nginx, /envoy, /traefik, or /helpers/*',
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

