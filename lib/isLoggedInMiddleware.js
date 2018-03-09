"use strict";
const localUserMiddleware = require('./localUserMiddleware');

module.exports = function (options) {
	const middleware = localUserMiddleware(options);

	function isLoggedIn(req, res, next) {
		console.log('isLoggedIn is deprecated, use localUserMiddleware.isLoggedInMiddleware() instead.');
		middleware.isLoggedInMiddleware()(req, res, next);
	};

	return {
		isLoggedIn
	};
};