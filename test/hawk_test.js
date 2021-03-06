/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* jshint expr: true */
"use strict";

var express = require("express");
var expect = require("chai").expect;
var addHawk = require("superagent-hawk");
var supertest = addHawk(require("supertest"));

var hawk = require("../lib/hawk");
var Token = require("../lib/token").Token;
var app = express();

describe("hawk middleware", function() {

  var createSessionArguments, credentials;
  var _getExistingSession = function(tokenId, cb) {
    cb(null, {
      key: credentials.key,
      algorithm: "sha256"
    });
  };

  var _getNonExistingSession = function(tokenId, cb) {
    cb(null, null);
  };

  var _createSession = function(id, key, cb) {
    createSessionArguments = arguments;
    cb();
  };

  var ok_200 = function(req, res) {
    res.status(200).json({"key": "value"});
  };

  var setUser = function(req, res, credentials, done) {
    done();
  };

  var router = express.Router();
  if (router) {
    router.get('/require-session',
      hawk.getMiddleware({
        hawkOptions: {},
        getSession: _getExistingSession,
        setUser: setUser
      }),
      ok_200
    );
    app.use("/router", router);
  }

  app.post('/require-session',
    hawk.getMiddleware({
      hawkOptions: {},
      getSession: _getExistingSession,
      setUser: setUser
    }),
    ok_200
  );
  app.post('/require-or-create-session',
    hawk.getMiddleware({
      hawkOptions: {}, 
      getSession: _getExistingSession,
      createSession: _createSession,
      setUser: setUser
    }),
    ok_200
  );

  app.post('/require-invalid-session',
    hawk.getMiddleware({
      hawkOptions: {},
      getSession: _getNonExistingSession,
      setUser: setUser
    }),
    ok_200
  );

  app.post('/require-or-create-invalid-session',
    hawk.getMiddleware({
      hawkOptions: {},
      getSession: _getNonExistingSession,
      createSession: _createSession,
      setUser: setUser
    }),
    ok_200
  );

  beforeEach(function(done) {
    createSessionArguments = undefined;
    var token = new Token();
    token.getCredentials(function(tokenId, authKey) {
      credentials = {
        id: tokenId,
        key: authKey,
        algorithm: "sha256"
      };
      done();
    });
  });

  describe("requireSession", function() {
    it("should challenge the client if no auth is provided", function(done) {
      supertest(app).post('/require-session').expect(401).end(done);
    });

    it("should accept a valid hawk session", function(done) {
      supertest(app)
        .post('/require-session')
        .hawk(credentials)
        .expect(200)
        .expect('Content-Type', /json/)
        .end(function(err, res) {
          if (err) throw err;
          expect(res.body).to.eql({key: "value"});
          done();
        });
    });

    (router ? it : it.skip)("should accept a valid hawk session behind a router", function(done) {
      supertest(app)
        .get('/router/require-session')
        .hawk(credentials)
        .expect(200)
        .end(done);
    });

    it("should reject an invalid hawk session", function(done) {
      supertest(app)
        .post('/require-invalid-session')
        .hawk(credentials)
        .expect(401)
        .end(done);
    });

    it("should 400 on malformed headers", function(done) {
      supertest(app)
        .post('/require-session')
        .set('authorization', 'Hawk MALFORMED')
        .expect(400)
        .end(done);
    });
  });

  describe("requireOrCreateSession", function() {
    it("should create a session if none is provided", function(done) {
      supertest(app)
        .post('/require-or-create-session')
        .expect(200)
        .end(function(err, res) {
          if (err) throw err;
          expect(createSessionArguments).to.not.be.undefined;
          expect(res.header['hawk-session-token']).to.not.be.undefined;
          done();
        });
    });

    it("should accept a valid hawk session", function(done) {
      supertest(app)
        .post('/require-or-create-session')
        .hawk(credentials)
        .expect(200)
        .end(done);
    });

    it("should reject an invalid hawk session", function(done) {
      supertest(app)
        .post('/require-or-create-invalid-session')
        .hawk(credentials)
        .expect(401)
        .end(function(err, res) {
          done();
        });
    });
  });
});
