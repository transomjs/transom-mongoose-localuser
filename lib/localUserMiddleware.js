"use strict";
const createError = require('http-errors');
const debug = require('debug')('transom:mongoose:localuser:LocalUserMiddleware');

module.exports = function (options) {

	const passport = options.passport;
	const mongoose = options.mongoose;
	const localuser = options.localuserOptions; // api configs

	/**
	 * Create a middleware that confirms whether a 
	 * logged in user has one of the specified Groups.
	 * 
	 * @param {string or Array} groups one or more Group codes that are required for this route.
	 */
	function groupMembershipMiddleware(groups) {
		if (typeof groups === 'string') {
			groups = [groups];
		}
		return function hasGroupMembership(req, res, next) {
			if (req.locals.user) {
				const userGroups = req.locals.user.groups || [];
				for (let group of groups) {
					if (userGroups.indexOf(group) !== -1) {
						debug(`User has the '${group}' Group.`);
						return next();
					}
				}
			}
			debug(`User is not a member of one of [${groups.join(',')}] Group(s).`);
			next(createError(403, 'No execute permissions on endpoint'));
		}
	};

	/**
	 * Create middleware that requires a valid Bearer token.
	 */
	function isLoggedInMiddleware() {
		return function isLoggedIn(req, res, next) {
			const AclUser = mongoose.model("TransomAclUser");
			const jwtOpts = localuser.jwt || {};
			const cookieName = jwtOpts.cookie || "access_token";

			if ((req.headers && req.headers.authorization) 
						|| (req.body && req.body.access_token) 
						|| (req.query && req.query.access_token)
						|| (req.cookies && req.cookies[cookieName])) {

				if (jwtOpts.secret) {
					debug("Authenticating using JWT strategy.");
					passport.authenticate('jwt', { session : false }, function (err, user, info) {
						if (err) {
							return next(err);
						}
						if (!user || (info && info.indexOf("invalid_token") > -1)) {
							// Something didn't work out.  Token Expired / Denied.
							debug("NOT LoggedIn - Invalid JWT", info);
							return next(createError(401, "Incorrect or expired credentials"));
						} else {
							// Properly authenticated!
							if (req.locals.newToken) {
								debug("Handling the new token and adding 'x-new-token' Header", req.locals.user);
								const exposeHeaders = res.getHeader('access-control-expose-headers') + ', x-new-token';
								res.setHeader('access-control-expose-headers', exposeHeaders);
								res.setHeader('x-new-token', req.locals.newToken.token);
							}
							return next();
						}
					})(req, res, next);
				} else {
					// Authenticate using a basic Bearer token, verify the authorization token or fail.
					debug("Authenticating using a Bearer strategy.");
					passport.authenticate('bearer', {
						session: false
					}, function (err, user, info) {
						if (err) {
							return next(err);
						}
						if (!user || (info && info.indexOf("invalid_token") >= 0)) {
							// Something didn't work out.  Token Expired / Denied.
							debug("NOT LoggedIn - Invalid Bearer", info);
							return next(createError(401, "Incorrect or expired credentials"));
						} else {
							// Properly authenticated!
							return next();
						}
					})(req, res, next);
				}
			} else {
				// debug("No Authorization header or query access_token. Trying Anonymous.");
				if (localuser.anonymous !== false) {
					// Attempt anonymous login, if possible;
					AclUser.findOne({
						'username': 'anonymous',
						'active': true
					}, function (err, user) {
						if (err) {
							return next(err);
						}
						if (user) {
							req.locals = req.locals || {};
							req.locals.user = user;
							return next();
						}
						// Oh no, not authenticated
						debug("No bearer token provided or query access_token. No Anonymous user available.");
						return next(createError(401, "No bearer token provided or query access_token. No Anonymous user available."));
					});
				} else {
					debug("No bearer token provided or query access_token.");
					return next(createError(401, "No bearer token provided or query access_token."));
				}
			}
		}
	}

	return {
		groupMembershipMiddleware,
		isLoggedInMiddleware
	};
};