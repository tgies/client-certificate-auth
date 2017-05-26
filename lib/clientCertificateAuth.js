/*!
 * client-certificate-auth-v2 - node.js Connect/Express middleware to perform
 *   authentication based on a client SSL certificate
 *  MIT License
 */

/**
 * Enforce SSL client authorization and provide a `callback(cert)` which will
 * be passed the client certificate information (as obtained through
 * `req.connection.getPeerCertificate()`) for additional validation, e.g. to
 * check it against a whitelist. `callback(cert)` must return `true` for the
 * request to proceed.
 *
 * @param {Function} callback
 */

module.exports = function clientCertificateAuth(callback) {
  return function middleware(req, res, next) {
    // Try to do an SSL redirect if this doesn't look like an SSL request.
    // The weird header check is necessary for this to work on Heroku.
    if (!req.secure && req.header('x-forwarded-proto') != 'https') {
      return res.redirect('https://' + req.header('host') + req.url);
    }
    // Ensure that the certificate was validated at the protocol level
    if (!req.client.authorized) {
      var e = req.client.authorizationError;
      return res.status(401).send(e);
    }
    // Obtain certificate details
    var cert = req.connection.getPeerCertificate();
    if (!cert || !Object.keys(cert).length) {
      // Handle the bizarre and probably not-real case that a certificate was
      // validated but we can't actually inspect it
      var e = 'Client certificate was authenticated but certificate ' + 'information could not be retrieved.';

      return res.status(500).send(e);
    }

    function doneAuthorizing(authorized) {
      if (authorized) {
        return next();
      } else {
        var e = 'Unauthorized';
        return res.status(401).send(e);
      }
    }
    // console.log(callback);
    // Fire the callback. If it returns true, the request may proceed. If it
    // returns false, bail out with a 401 Unauthorized.
    if (callback.length === 2) {
      callback(cert, doneAuthorizing);
    } else {
      doneAuthorizing(callback(cert));
    }
  };
};
