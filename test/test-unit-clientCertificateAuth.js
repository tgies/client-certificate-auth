import assert from 'node:assert/strict';
import clientCertificateAuth from '../lib/clientCertificateAuth.js';

const getMockPeerCertificate = () => ({
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
  valid_to: 'Jan 19 03:14:07 2038 GMT',
  fingerprint: 'BA:DA:DD:EA:DB:EE:FC:CC:CC:CC:07:15:19:88:C0:FF:EE:00:12:00'
});

describe('clientCertificateAuth', function () {
  it('should be a function taking callback and options arguments', function () {
    assert.equal(typeof clientCertificateAuth, 'function');
    // Note: Function.length is 1 because `options` has a default value
    assert.equal(clientCertificateAuth.length, 1);
  });

  it('should return a middleware function taking three arguments', function () {
    const middleware = clientCertificateAuth(() => true);
    assert.equal(typeof middleware, 'function');
    assert.equal(middleware.length, 3);
  });

  describe('middleware(req, res, next)', function () {
    const mockGoodReq = {
      secure: true,
      socket: { authorized: true, getPeerCertificate: getMockPeerCertificate },
      headers: {}
    };

    const mockUnsecureReq = {
      secure: false,
      socket: { authorized: false, getPeerCertificate: () => ({}) },
      headers: {}
    };

    const mockUnauthReq = {
      secure: true,
      socket: { authorized: false, authorizationError: 'CERT_UNTRUSTED', getPeerCertificate: getMockPeerCertificate },
      headers: {}
    };

    const mockRes = {
      redirect: () => { }
    };

    describe('when the request is secure and the client certificate validates', function () {
      it('should call the validation callback with the certificate', function (done) {
        const middleware = clientCertificateAuth((cert) => {
          assert.equal(cert.subject.CN, 'Proctor Davenport');
          done();
          return true;
        });
        middleware(mockGoodReq, mockRes, () => { });
      });

      it('should call next() if callback returns true (sync)', function (done) {
        const middleware = clientCertificateAuth(() => true);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should call next() if callback returns Promise<true> (async)', function (done) {
        const middleware = clientCertificateAuth(async () => true);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.equal(err, undefined);
          done();
        });
      });

      it('should pass 401 error to next() if callback returns false', function (done) {
        const middleware = clientCertificateAuth(() => false);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          assert.equal(err.message, 'Unauthorized');
          done();
        });
      });

      it('should pass 401 error to next() if async callback returns false', function (done) {
        const middleware = clientCertificateAuth(async () => false);
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          done();
        });
      });

      it('should pass error to next() if callback throws', function (done) {
        const middleware = clientCertificateAuth(() => {
          throw new Error('Validation failed');
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Validation failed');
          done();
        });
      });

      it('should pass error to next() if async callback rejects', function (done) {
        const middleware = clientCertificateAuth(async () => {
          throw new Error('Async validation failed');
        });
        middleware(mockGoodReq, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'Async validation failed');
          done();
        });
      });
    });

    describe('when the client certificate does not validate', function () {
      it('should pass 401 error to next() without calling callback', function (done) {
        let callbackCalled = false;
        const middleware = clientCertificateAuth(() => {
          callbackCalled = true;
          return true;
        });
        middleware(mockUnauthReq, mockRes, (err) => {
          assert.equal(callbackCalled, false);
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          assert.ok(err.message.includes('CERT_UNTRUSTED'));
          done();
        });
      });
    });

    describe('when req.socket.authorized is falsy', function () {
      it('should pass 401 error to next()', function (done) {
        const reqNoAuth = { ...mockGoodReq, socket: { authorized: undefined, getPeerCertificate: getMockPeerCertificate } };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqNoAuth, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 401);
          done();
        });
      });
    });

    describe('when certificate cannot be retrieved', function () {
      it('should pass 500 error to next()', function (done) {
        const reqEmptyCert = {
          ...mockGoodReq,
          socket: { authorized: true, getPeerCertificate: () => ({}) }
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(reqEmptyCert, mockRes, (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.status, 500);
          done();
        });
      });
    });

    describe('redirectInsecure option', function () {
      it('should NOT redirect by default', function (done) {
        let redirectCalled = false;
        const res = {
          redirect: () => { redirectCalled = true; }
        };
        const middleware = clientCertificateAuth(() => true);
        middleware(mockUnsecureReq, res, (err) => {
          assert.equal(redirectCalled, false);
          // Should fail due to unauthorized, not redirect
          assert.ok(err instanceof Error);
          done();
        });
      });

      it('should redirect when redirectInsecure is true', function () {
        let redirectUrl = null;
        let redirectStatus = null;
        const req = {
          secure: false,
          socket: {},
          headers: {
            'host': 'example.com'
          },
          url: '/protected'
        };
        const res = {
          redirect: (status, url) => {
            redirectStatus = status;
            redirectUrl = url;
          }
        };
        const middleware = clientCertificateAuth(() => true, { redirectInsecure: true });
        middleware(req, res, () => { });

        assert.equal(redirectStatus, 301);
        assert.equal(redirectUrl, 'https://example.com/protected');
      });

      it('should NOT redirect if x-forwarded-proto is https', function (done) {
        const req = {
          secure: false,
          socket: { authorized: true, getPeerCertificate: getMockPeerCertificate },
          headers: {
            'x-forwarded-proto': 'https'
          }
        };
        let redirectCalled = false;
        const res = {
          redirect: () => { redirectCalled = true; }
        };
        const middleware = clientCertificateAuth(() => true, { redirectInsecure: true });
        middleware(req, res, () => {
          assert.equal(redirectCalled, false);
          done();
        });
      });
    });
  });
});
