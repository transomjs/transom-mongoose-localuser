"use strict";
const restifyErrors = require('restify-errors');
const debug = require('debug')('transom:mongoose:localuser:LocalUserClient');

module.exports = function (options) {

	const passport = options.passport;
	const mongoose = options.mongoose;

	/**
	 * Create a middleware that confirms whether a 
	 * logged in user has one of the specified Groups.
	 * 
	 * @param {string or Array} groups one or more Group codes that are required.
	 */
	function getGroupMembershipCheck(groups) {
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
			debug(`User is not a member of '${groups.join(',')}' Group(s).`);
            next(new restifyErrors.ForbiddenError('No execute permissions on endpoint'));
        }
    };

	function getLoggedInCheck() {
		return isLoggedIn;
	}
	/**
	 * 
	 * @param {*} req 
	 * @param {*} res 
	 * @param {*} next 
	 */
	function isLoggedIn(req, res, next) {
		const AclUser = mongoose.model("TransomAclUser");

		if ((req.headers && req.headers.authorization) || (req.body && req.body.access_token) || (req.query && req.query.access_token)) {
			// Verify the authorization token or fail.
			passport.authenticate('bearer', {
				session: false
			}, function (err, user, info) {
				if (err) {
					return next(err);
				}
				if (!user || (info && info.indexOf("invalid_token") >= 0)) {
					// Something didn't work out.  Token Expired / Denied.
					debug("NOT LoggedIn - Invalid");
					return next(new restifyErrors.InvalidCredentialsError("Incorrect or expired credentials"));
				} else {
					// Properly authenticated!
					return next();
				}
			})(req, res, next);
		} else {
			// debug("No Authorization header or query access_token. Trying Anonymous.");
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
					debug("No bearer token provided or query access_token. No Anonymous user available.");
					return next(new restifyErrors.InvalidCredentialsError("No bearer token provided or query access_token. No Anonymous user available."));
				}
			});
		}
	};

	return {
		getGroupMembershipCheck,
		getLoggedInCheck,
		isLoggedIn
	};
};