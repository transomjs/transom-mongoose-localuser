"use strict";
const BearerStrategy = require('passport-http-bearer').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const JwtUtils = require('./jwtUtils');
const jwt = require('jsonwebtoken');
const debug = require('debug')('transom:mongoose:localuser:stratgies');
const deleteValue = require('del-value');

module.exports = function (server, options) {
	const passport = server.registry.get('passport');
	const mongoose = server.registry.get('mongoose');
	const idleSessionLimit = options.idleSessionLimit || (60 * 60000); // 60 minutes
	const rememberMeLimit = options.rememberMeLimit || (14 * 24 * 60 * 60000) // 14 days
	const sessionIdleTolerance = options.sessionIdleTolerance || (10 * 60000); // 10 minutes
	const sanitizeProps = options.sanitize || [];
	const jwtOptions = options.jwt || {};
	const jwtUtils = new JwtUtils(jwtOptions);
	const AclUser = mongoose.model("TransomAclUser");

	// =========================================================================
	// LOCAL LOGIN =============================================================
	// =========================================================================
	passport.use('local', new LocalStrategy({
			passReqToCallback: true
		},
		function (req, email, password, next) {
			email = email.toLowerCase();

			const qry = {};
			if (email.indexOf('@') === -1) {
				qry.username = email;
			} else {
				qry.email = email;
			}
			AclUser.findOne(qry)
				.then((user) => {
					if (!user) {
						// User not found.
						return next(null, false, {
							message: 'Incorrect username or password.'
						});
					}
					if (!user.verified_date) {
						// User not verified yet.
						return next(null, false, {
							message: 'Account has not been verified.'
						});
					}
					user.authenticate(password, function (err, user, info) {
						if (err || !user) {
							return next(info);
						}
						if (jwtOptions.createPayload && jwtOptions.secret) {
							jwtOptions.createPayload(server, user)
							.then((payload) => {
								return jwtUtils.payloadRequiredAttribs(payload);
							}).then((payload) => {
								// Pass along the logged-in User and the token
								// they should use in future authenticated requests.
								req.locals.user = payload;
								req.locals.basic_login_token = jwt.sign(payload, jwtOptions.secret, {
									algorithm: jwtOptions.algorithm || "HS256",
									expiresIn: jwtOptions.expireSeconds || 600
								});
								next(null, payload);
							}).catch((err) => {
								next(null, false, err);
							});
						} else {
							// Maintain a list of no more that 10 Bearer tokens / User.
							// Do the bearer housekeeping
							user.finalizeLogin({
								req
							}, next);
						}
					});
				}).catch(function (err) {
					next(err);
				});
		}));

	// =========================================================================
	// BEARER TOKEN - AFTER Login ==============================================
	// =========================================================================
	passport.use('bearer', new BearerStrategy({
			passReqToCallback: true
		},
		function (req, token, next) {
			// If a session hasn't been used in ~60 minutes, consider it expired.
			const now = new Date();
			const sessionExpiry = now - idleSessionLimit; // ~60 minutes ago
			const rememberMeExpiry = now - rememberMeLimit; // ~2 weeks ago
			const idleSince = now - sessionIdleTolerance; // ~10 minutes ago (don't update a session's last_request date constantly.)

			// Find a single bearer array element with both token & a valid last_request.
			const qry = {
				local_auth_type: "password"
			};
			const tokenPrefix = token.substr(0, 3);
			switch (tokenPrefix) {
				case "svc":
					qry.local_auth_type = "user-secret";
					qry.user_secret = token;
					break;
				case "rem":
					qry.bearer = {
						$elemMatch: {
							'token': token,
							'last_request': {
								$gte: rememberMeExpiry
							}
						}
					};
					break;
				default:
					qry.bearer = {
						$elemMatch: {
							'token': token,
							'last_request': {
								$gte: sessionExpiry
							}
						}
					};
					break;
			};

			AclUser.findOne(qry)
				.then((user) => {
					if (!user) {
						// If no user is found, return the message
						return next(null, false, {
							message: 'Incorrect or expired credentials.'
						});
					}
					if (!user.verified_date) {
						return next(null, false, {
							message: 'Account has not been verified.'
						});
					}
					const serviceLogin = qry.local_auth_type === "user-secret";
					if (!serviceLogin) {
						for (let bearerObj of user.bearer) {
							if (bearerObj.token === token) {
								if ((bearerObj.last_request * 1) < idleSince) {
									// If last request was outside the tolerance, touch the session last_request date.
									bearerObj.last_request = now;
									user.modifiedBy = "bearer";
									user.save().catch((err) => {
										console.error('Error saving bearer to db:', err);
									});
								}
								break;
							}
						}
					}

					// Remove the mongoose functionality & delete private attributes.
					const versionKey = user.schema.options.versionKey;
					const result = user.toObject();
					const privates = [versionKey, 'password', 'password_salt', 'bearer', 'verified_date', 'user_secret'];
					sanitizeProps.map(item => privates.push(item));
					for (let key of privates) {
						// deleteValue supports nested properties like "social.google.token"
						deleteValue(result, key);
					}

					req.locals = req.locals || {};
					req.locals.user = result;
					return next(null, result);
				})
				.catch((err) => {
					console.error("Error in BearerStrategy:", err);
					return next(err);
				});
		}));


	// =========================================================================
	// LOCAL SIGNUP ============================================================
	// =========================================================================
	passport.use('local-signup', new LocalStrategy({
			// by default, local strategy uses username and password, we will override with email
			usernameField: 'email',
			passwordField: 'password',
			passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
		},
		function (req, email, password, next) {
			const username = (req.params['username'] || email).toLowerCase();
			const displayName = req.params['display_name'] || email;
			email = email.toLowerCase(); // Lower-case to avoid case-sensitive matching

			// Make sure user is not already registered.
			AclUser.findOne({
				$or: [{
					'email': email
				}, {
					'username': username
				}]
			}, function (err, user) {
				if (err) {
					return next(err);
				}
				if (user) {
					return next(null, false, 'That username / email address is already registered.');
				}

				const newUser = new AclUser();
				newUser.username = username;
				newUser.display_name = displayName;
				newUser.email = email;
				newUser.verify_token = newUser.generateVerifyHash();
				newUser.local_auth_type = "password";

				newUser.setPassword(password, function (err, user) {
					user.modifiedBy = 'local-signup';
					user.save().then((user) => {
						next(null, user);
					}).catch(function (err) {
						return next(err);
					});
				});
			});
		}));


	// =========================================================================
	// LOCAL VERIFY ============================================================
	// =========================================================================
	passport.use('local-verify', new LocalStrategy({
			usernameField: 'token', // Name of the query parameter containing the verify token
			passwordField: 'token', // Not used - but we need *something* for Passport.
			passReqToCallback: true // allows us to pass back the request to the callback
		},
		function (req, token, dummy, next) { // callback with token and a dummy password from email verification url
			AclUser.findOne({
				'verify_token': token
			}, function (err, usr) {
				if (err) {
					return next(err);
				}
				if (!usr) {
					return next("Verify user not found");
				}
				usr.verified_date = new Date();
				usr.verify_token = "verified-" + usr.generateVerifyHash();

				usr.modifiedBy = 'local-verify';
				usr.save().then(function (user) {
					if (jwtOptions.createPayload) {
						// reply with a JWT!
						jwtOptions.createPayload(server, user).then((jwt) => {
							// Pass along  the logged-in User and the token
							// they should use in future authenticated requests.
							req.locals.user = user;
							req.locals.basic_login_token = jwt;
							next(null, user);
						}).catch((err) => {
							next(null, false, err);
						})
					} else {
						// Maintain a list of no more that 10 Bearer tokens / User.
						user.finalizeLogin({ user, req }, next);
					}
				}).catch((err) => {
					return next(err);
				});
			});
		}));

	// =========================================================================
	// JWT =====================================================================
	// =========================================================================
    passport.use('jwt', new JwtStrategy({
        jwtFromRequest: ExtractJwt.fromExtractors([ExtractJwt.fromAuthHeaderAsBearerToken(), ExtractJwt.fromUrlQueryParameter('access_token'), jwtUtils.cookieExtractor(jwtOptions.cookie || 'access_token')]),
        secretOrKey: jwtOptions.secret || `random-${Math.random().toString(36).slice(-8)}`,
        passReqToCallback: true,
        // maxAge: 15 // seconds!
        // issuer: 'accounts.examplesoft.com',
        // audience: 'yoursite.net'
    }, (req, token, next) => {
        try {
			const issuedAt = new Date(token.iat * 1000);
			const maxAgeSec = jwtOptions.maxAgeSeconds || 500;
			const needsRefresh = (new Date() - issuedAt)/1000 > maxAgeSec;
			if (needsRefresh) {
				debug(`JWT is more than ${maxAgeSec} seconds old, verify and refresh.`);

				AclUser.findOne({
					_id: token._id,
					active: true
					}).then((user) => {
						if (!user) {
							return Promise.reject({
								message: 'Token could not be reissued.'
							});
						}
						return jwtOptions.createPayload(server, user);
					})
					.then((payload) => {
						return jwtUtils.payloadRequiredAttribs(payload);
					})
					.then((payload) => {
						// Pass along  the logged-in User and the token
						// to be used in future authenticated requests.
						req.locals.user = payload;
						req.locals.newToken = {
							token: jwt.sign(payload, jwtOptions.secret, {
								algorithm: jwtOptions.algorithm || "HS256",
								expiresIn: jwtOptions.expireSeconds || 600,
							})};
						next(null, payload);
					}).catch((err) => {
						debug(`JWT refresh failed:`, err);
						next(null, false, err);
					});
            } else {
				debug(`JWT decoded for User: ${token.email}`);
				req.locals.user = token;

                next(null, token);
            }
        } catch (error) {
            console.log(error);
            next(error);
        }
    }));
};