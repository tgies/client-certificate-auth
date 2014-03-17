var clientCertificateAuth = require('../lib/clientCertificateAuth.js');
var should = require('should');

var getMockPeerCertificate = function() {
  return {
    subject: {
      C: 'US',
      ST: 'Texas',
      L: 'Waco',
      O: 'SHOE',
      OU: 'Upstairs',
      CN: 'Proctor Davenport'
    },
    issuer: {
      C: 'US',
      ST: 'Texas',
      L: 'Waco',
      O: 'SHOE',
      OU: 'Computers',
      CN: 'SHOE Computers Dept. of Very Big Prime Numbers' 
    },
    valid_from: 'Jun 19 03:26:11 2004 GMT',
    valid_to:   'Jan 19 03:14:07 2038 GMT', // scheduled heat death of universe
    fingerprint: 'BA:DA:DD:EA:DB:EE:FC:CC:CC:CC:07:15:19:88:C0:FF:EE:00:12:00'
  };
};

describe('clientCertificateAuth', function() {
  it('should be a function taking one argument', function() {
    clientCertificateAuth.should.be.a('function').and.have.lengthOf(1);
  });

  it('should return a function taking three arguments -- the middleware', function() {
    clientCertificateAuth(function() {}).should.be.a('function').and.have.lengthOf(3);
  });

  describe('(clientCertificateAuth(cb))(req, res, next)', function() {
    /*
     * The objects mockGoodReq, mockUnsecureReq, and mockUnauthReq imitate the
     * expected properties and behavior of the real request object of the type
     * supported by this software, in the case of a secure and authorized
     * request; an unsecure (cleartext) request; and a secure but unauthorized
     * (untrusted or absent client certificate) request, respectively.
     */
    var mockGoodReq = {
      secure: true,
      client: { authorized: true },
      connection: { getPeerCertificate: getMockPeerCertificate }
    };

    var mockUnsecureReq = {
      secure: false,
      client: { authorized: false },
      connection: { getPeerCertificate: function() { return {}; } }
    };

    var mockUnauthReq = {
      secure: true,
      client: { authorized: false },
      connection: { getPeerCertificate: getMockPeerCertificate }
    };

    var mockRes = {};

    describe('when the request is secure and the client certificate validates', function() {
      it('should call cb', function(done) {
        (clientCertificateAuth(function() { done(); }))(mockGoodReq, mockRes, function() {});
      });

      it('should call next() to pass control successfully if cb(cert) returns true', function(done) {
        (clientCertificateAuth(function() { return true; }))(mockGoodReq, mockRes, done);
      });

      it('should call next() to pass control successfully if async cb(cert) returns true', function(done) {
        (clientCertificateAuth(function(cert, callback) { callback(true); }))(mockGoodReq, mockRes, done);
      });

      it('should pass a 401 error to next() if cb(cert) returns false', function(done) {
        (clientCertificateAuth(function() { return false; }))(mockGoodReq, mockRes, function(e) {
          e.should.be.an.instanceOf(Error).and.have.property('status', 401);
          done();
        });
      });
    });

    describe('when the request is secure but the client certificate does not validate', function() {
      it('should pass a 401 error to next()', function(done) {
        (clientCertificateAuth(function() { return true; }))(mockUnauthReq, mockRes, function(e) {
          e.should.be.an.instanceOf(Error).and.have.property('status', 401);
          done();
        });
      });
    });
  });
});
