client-certificate-auth
========

middleware for Node.js implementing client SSL certificate
authentication/authorization

Copyright © 2013 Tony Gies

April 30, 2013

[![Build Status](https://travis-ci.org/tgies/client-certificate-auth.png)](https://travis-ci.org/tgies/client-certificate-auth)

installing
----------

client-certificate-auth is available from [npm](https://npmjs.org/package/client-certificate-auth.).

    $ npm install client-certificate-auth

requirements
------------

client-certificate-auth is tested against Node.js versions 0.6, 0.8, and 0.10.
It has no external dependencies (other than any middleware framework with which
you may wish to use it); however, to run the tests, you will need [mocha](https://npmjs.org/package/mocha) and
[should](https://npmjs.org/package/should).

synopsis
--------

client-certificate-auth provides HTTP middleware for Node.js (in particular
Connect/Express) to require that a valid, verifiable client SSL certificate is
provided, and passes information about that certificate to a callback which must
return `true` for the request to proceed; otherwise, the client is considered 
unauthorized and the request is aborted.

usage
-----

The https server must be set up to request a client certificate and validate it 
against an issuer/CA certificate. What follows is a typical example using
[Express](http://expressjs.com):

```javascript
var express = require('express');
var fs = require('fs');
var https = require('https');
var clientCertificateAuth = require('client-certificate-auth');

var opts = {
  // Server SSL private key and certificate
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  // issuer/CA certificate against which the client certificate will be
  // validated. A certificate that is not signed by a provided CA will be
  // rejected at the protocol layer.
  ca: fs.readFileSync('cacert.pem'),
  // request a certificate, but don't necessarily reject connections from
  // clients providing an untrusted or no certificate. This lets us protect only
  // certain routes, or send a helpful error message to unauthenticated clients.
  requestCert: true,
  rejectUnauthorized: false
};

var app = express();

// add clientCertificateAuth to the middleware stack, passing it a callback
// which will do further examination of the provided certificate.
app.use(clientCertificateAuth(checkAuth));
app.use(app.router);
app.use(function(err, req, res, next) { console.log(err); next(); });

app.get('/', function(req, res) {
  res.send('Authorized!');
});

var checkAuth = function(cert) {
 /*
  * allow access if certificate subject Common Name is 'Doug Prishpreed'.
  * this is one of many ways you can authorize only certain authenticated
  * certificate-holders; you might instead choose to check the certificate
  * fingerprint, or apply some sort of role-based security based on e.g. the OU
  * field of the certificate. You can also link into another layer of
  * auth or session middleware here; for instance, you might pass the subject CN
  * as a username to log the user in to your underlying authentication/session
  * management layer.
  */
  return cert.subject.CN === 'Doug Prishpreed';
};

https.createServer(opts, app).listen(4000);
```

Or secure only certain routes:

```javascript
app.get('/unsecure', function(req, res) {
  res.send('Hello world');
});

app.get('/secure', clientCertificateAuth(checkAuth), function(req, res) {
  res.send('Hello authorized user');
});
```

`checkAuth` can also be asynchronous:

```javascript
function checkAuth(cert, callback) {
  callback(true);
}

app.use(checkAuth);
```
