"use strict";
var restifyErrors = require('restify-errors');

module.exports = function (options) {

	const passport = options.passport;
	const mongoose = options.mongoose;

	function isLoggedIn(req, res, next) {

		const AclUser = mongoose.model("TransomAclUser");

		if ((req.headers && req.headers.authorization) || (req.body && req.body.access_token) || (req.query && req.query.access_token)) {
			// Verify the authorization token or fail.
			passport.authenticate('bearer', {
				session: false
			}, function (err, user, info) {
				if (err) {
					console.error("************ NOT isLoggedIn - Error *************", err);
					return next(err);
				}
				if (!user || (info && info.indexOf("invalid_token") >= 0)) {
					// Something didn't work out.  Token Expired / Denied.
					console.error("************ NOT LoggedIn - Invalid *************");
					return next(new restifyErrors.InvalidCredentialsError("Incorrect or expired credentials"));
				} else {
					// Properly authenticated!
					return next();
				}
			})(req, res, next);
		} else {
			console.warn("************ No Authorization header or query access_token. Trying Anonymous *************");
			// Attempt anonymous login, if possible;
			const qry = {
				'username': 'anonymous',
				'active': true
			};
			AclUser.findOne(qry, function (err, anonUser) {
				if (err) {
					return next(err);
				}
				if (anonUser) {
					req.locals = req.locals || {};
					req.locals.user = anonUser;
					return next();
				} else {
					// Oh no, not authenticated
					return next(new restifyErrors.InvalidCredentialsError("No bearer token provided or query access_token. No Anonymous user available"));
				}
			});
		}
	};

	return {
		isLoggedIn
	};
};