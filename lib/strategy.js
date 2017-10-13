'use strict';

/**
 * Module dependencies.
 */
var passport = require('passport-strategy'),
  util = require('util'),
  lookup = require('./utils').lookup,
  jwt = require('jsonwebtoken'),
  assign = require('./helpers/assign.js');


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new JwtStrategy(opts,
 *       function(payload, done) {
 *         User.findOne({ id: payload.sub }, function (err, user) {
 *           if (err) {
 *          return done(err, false);
 *      }
 *       if (user) {
 *           return done(null, user);
 *       } else {
 *           return done(null, false);
 *           // or you could create a new account
 *       }
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  passport.Strategy.call(this);
  this.name = 'jwt';

  if (typeof options === 'function') {
    verify = options;
    options = {};
  }

  this.secretOrKey = options.secretOrKey || 'our biggest secret';

  this._verify = verify;
  if (!this._verify) { throw new TypeError('JwtStrategy requires a verify callback'); }

  this._passReqToCallback = options.passReqToCallback;

  var jsonWebTokenOptions = options;
  //for backwards compatibility, still allowing you to pass
  //audience / issuer / algorithms / ignoreExpiration
  //on the options.
  this._verifOpts = assign({}, jsonWebTokenOptions);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.verify = require('./verify-jwt');

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  // check header or url parameters or post parameters for token
  var token = req.body.token || req.query.token || req.headers['x-access-token'];

  if (!token) {
    return self.fail(new Error('No auth token'));
  }


  // verifies secret and checks exp
  Strategy.verify(token, this.secretOrKey, self._verifOpts, function (err, payload) {
    if (err) {
      return self.fail(err);
    } else {
      // Pass the parsed token to the user
      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        } else if (!user) {
          return self.fail(info);
        } else {
          return self.success(user, info);
        }
      };

      try {
        if (self._passReqToCallback) {
          self._verify(req, payload, verified);
        } else {
          self._verify(payload, verified);
        }
      } catch (ex) {
        self.error(ex);
      }
    }
  });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
