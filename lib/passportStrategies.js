'use strict';
const BasicStrategy = require('passport-http').BasicStrategy;
const BearerStrategy = require('passport-http-bearer').Strategy;
const LocalStrategy = require('passport-local').Strategy;

module.exports = function (options) {
	const passport = options.passport;
	const mongoose = options.mongoose;
	const idleSessionLimit = options.idleSessionLimit || (60 * 60000); // 60 minutes
	const rememberMeLimit = options.rememberMeLimit || (14 * 24 * 60 * 60000) // 14 days
	const sessionIdleTolerance = options.sessionIdleTolerance || (10 * 60000); // 10 minutes

	const AclUser = mongoose.model("TransomAclUser");

	// =========================================================================
	// BASIC LOGIN =============================================================
	// =========================================================================
	passport.use('basic', new BasicStrategy({
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
						// Do the bearer housekeeping
						user.finalizeLogin({
							req
						}, next);
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

			var now = new Date();

			// If a session hasn't been used in 60 minutes, consider it expired.
			var sessionExpiry = now - idleSessionLimit; // 60 minutes ago
			var rememberMeExpiry = now - rememberMeLimit; // 2 weeks ago

			// lastRequestTolerance is used so that we don't update a session's last_request date constantly.
			var idleSince = now - sessionIdleTolerance; // 10 minutes ago

			// Find a single bearer array element with both token & a valid last_request.
			var qry = {};
			var tokenPrefix = token.substr(0, 3);
			var serviceLogin = false;
			switch (tokenPrefix) {
				case "svc":
					serviceLogin = true;
					qry.local_auth_type = "user-secret";
					qry.user_secret = token;
					break;
				case "rem":
					qry.local_auth_type = "password";
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
					qry.local_auth_type = "password";
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

			const selectFields = "email username display_name active groups privs bearer" +
				" _id created_by created_date updated_by updated_date verified_date";

			var q = AclUser.findOne(qry, selectFields)
				.then((user) => {
					if (!user) {
						// if no user is found, return the message
						return next(null, false, {
							message: 'Incorrect or expired credentials.'
						});
					}
					if (!user.verified_date) {
						return next(null, false, {
							message: 'Account has not been verified.'
						});
					}
					if (!serviceLogin) {
						for (let bearerObj of user.bearer) {
							if (bearerObj.token == token) {
								if ((bearerObj.last_request * 1) < idleSince) {
									// If last request was outside the tolerance, touch the session last_request date.
									console.log("Updating session last request date!");
									bearerObj.last_request = now;
									user.modifiedBy = "bearer";
									user.save(function (err, ignored) {
										if (err) {
											console.error('Error saving bearer to db:', err);
										}
									});
								}
								break;
							}
						}
					}
					req.locals = req.locals || {};

					// Remove the mongoose functionality & delete private attributes.
					const result = user.toObject();
					delete result.bearer; // Don't share these!
					delete result.verified_date;

					req.locals.user = result;
					return next(null, result);
				})
				.catch((err) => {
					console.log("Error in BearerStrategy: " + err);
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
			// lastLoginField: 'last_login_date',
			// attemptsField: 'login_attempts',
			// limitAttempts: true,
			passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
		},
		function (req, email, password, next) {

			var username = req.params['username'] || email;
			var displayName = req.params['display_name'] || email;

			email = email.toLowerCase(); // Lower-case to avoid case-sensitive matching
			username = username.toLowerCase(); // Lower-case to avoid case-sensitive matching

			// AclUser is not already logged in:
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

				// create the AclUser
				var newUser = new AclUser();
				newUser.username = username;
				newUser.display_name = displayName;
				newUser.email = email;
				newUser.verify_token = newUser.generateVerifyHash(); // use the generateVerifyHash function in our user model
				newUser.local_auth_type = "password";

				newUser.setPassword(password, function (err, user) {
					user.modifiedBy = 'local-signup';
					user.save(function (err, user, numAffected) {
						if (err) {
							return next(err);
						}
						next(null, user);
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
			passReqToCallback: true // allows us to pass back the entire request to the callback
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
				usr.save(function (err, verifiedUser) {
					if (err) {
						return next(err);
					}
					var opts = {
						user: verifiedUser,
						req: req
					};
					verifiedUser.finalizeLogin(opts, next);
				});
			});
		}));
};