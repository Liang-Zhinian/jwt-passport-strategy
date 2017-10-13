
#jwt-possport-strategy

===========


## Introduction
**jwt-possport-strategy** is a possport-strategy using jsonwebtoken.

## Table of Contents
- [Examples](#examples)


# Examples

## Start instance
```javascript
var passport = require('passport'),
    JwtStrategy = require('jwt-passport-strategy').Strategy;
var opts = {};
    opts.secretOrKey = 'secretOrKey';
    passport.use(new JwtStrategy(opts,
        function (payload, done) {
            User.findOne({
                username: payload.username
            }, function (err, user) {
                if (err) {
                    return done(err, false);
                }
                if (user) {
                    return done(null, user);
                } else {
                    return done(null, false);
                    // or you could create a new account
                }

            });
        }
    ));
