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
      CN: 'Proctor Davenport' },
    issuer: {
      C: 'US',
      ST: 'Texas',
      L: 'Waco',
      O: 'SHOE',
      OU: 'Computers',
      CN: 'SHOE Computers Dept. of Very Big Prime Numbers' },
    valid_from: 'Jun 19 03:26:11 2004 GMT',
    valid_to:   'Jan 19 03:14:07 2038 GMT', // scheduled heat death of universe
    fingerprint: 'BA:DA:DD:EA:DB:EE:FC:CC:CC:CC:07:15:19:88:C0:FF:EE:00:12:00'
  };
};

describe('clientCertificateAuth', function() {
  it('should be a function taking one argument', function() {
    clientCertificateAuth.should.be.a('function').and.have.lengthOf(1);
  });

  it('should return a function taking three arguments -- the middleware',
      function() {
          clientCertificateAuth(function() {}).should.be.a('function').and.have.lengthOf(3);
      }
    );

  describe('(clientCertificateAuth(cb))(req, res, next)', function() {
    var mockReq = { secure: true,
      client: { authorized: true },
      connection: { getPeerCertificate: getMockPeerCertificate }
    };
    var mockRes = {};

    describe('when the request is secure and the client is authorized', function() {

      it('should call cb', function(done) {
        (clientCertificateAuth(function() { done(); }))(mockReq, mockRes, function() {});
      });

      it('should call next() with no arguments to pass control if cb(cert) returns true',
        function(done) {
          (clientCertificateAuth(function() { return true; }))(mockReq, mockRes, done);
        }
      );
    });
  });
});
