client-certificate-auth
========

middleware for Node.js implementing client SSL certificate
authentication/authorization

Copyright © 2013 Tony Gies

April 30, 2013

[![Build Status](https://travis-ci.org/tgies/client-certificate-auth.png)](https://travis-ci.org/tgies/client-certificate-auth)

installing
----------

client-certificate-auth is available from [npm](http://npmjs.org).

    $ npm install client-certificate-auth

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
against an issuer/CA cert:

```javascript
var express = require('express');
var fs = require('fs');
var https = require('https');
var clientCertificateAuth = require('client-certificate-auth');

var opts = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.pem'),
  ca: fs.readFileSync('cacert.pem'),
  requestCert: true,
  rejectUnauthorized: false
};

var app = express();

app.use(clientCertificateAuth(checkAuth));
app.use(app.router);
app.use(function(err, req, res, next) { console.log(err); next(); });

app.get('/', function(req, res) {
  res.send('Authorized!');
});

var checkAuth = function(cert) {
  // allow access if certificate subject Common Name is 'Tony Gies'
  return cert.subject.CN == 'Tony Gies';
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
