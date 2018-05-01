"use strict";

module.exports = function (options) {

	function isLoggedIn(req, res, next) {
		console.error('isLoggedIn is deprecated, use localUserMiddleware.isLoggedInMiddleware() instead.');
		return next(new restifyErrors.InvalidCredentialsError("This middleware is expired!"));

	};

	return {
		isLoggedIn
	};
};