/*!
 * client-certificate-auth - node.js Connect/Express middleware to perform
 *   authentication based on a client SSL certificate
 * Copyright (C) 2013 Tony Gies
 */

/**
 * Enforce SSL client authorization and provide a `callback(clientcert)` which
 * will be passed the client certificate information (as obtained through
 * `req.connection.getPeerCertificate()` for additional validation, e.g. to
 * check it against a whitelist. `callback(cert)` must return `true` for the
 * request to proceed.
 *
 * @param {Function} callback
 */

module.exports = function clientCertificateAuth(callback) {
  return function(req, res, next) {
    // Try to do an SSL redirect if this doesn't look like an SSL request.
    // The weird header check is necessary for this to work on Heroku.
    if (!req.secure || req.header('x-forwarded-proto') != 'https') {
      res.redirect('https://' + req.header('host') + req.url);
    }

    // Ensure that the certificate was validated
    if (!req.connection.authorized) unauthorized();

    var cert = req.connection.getPeerCertificate();
    if (!cert) next(new Error('Client certificate was authenticated but certificate information could not be retrieved.'));

    // Fire the callback. If it returns true, authorize the user and set
    // req.remoteUser to the Common Name of the certificate subject. If it
    // returns false, bail out with a 401 Unauthorized.
    if (callback(cert)) {
      req.remoteUser = cert.subject.CN;
      next();
    } else {
      unauthorized();
    }
  };
};

unauthorized = function() {
  res.statusCode = 401;
  res.end('Unauthorized');
};
