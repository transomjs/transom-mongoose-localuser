'use strict';

const passport = require('passport');
const debug = require('debug')('transom:mongoose:localuser');
const localAclGroupSchema = require('./lib/localAclGroupSchema');
const localAclUserSchema = require('./lib/localAclUserSchema');
const LocalUserHandler = require('./lib/localUserHandler');
const passportStrategies = require('./lib/passportStrategies');
const isLoggedInMiddleware = require('./lib/isLoggedInMiddleware');
const initializeAcl = require('./lib/initializeAcl');

const TransomLocalUser = function() {
	debug("Initializing Transom-localUser");

	this.initialize = function(server, options) {

		debug("Initializing Transom-localUser...");

		server.registry.set('passport', passport);

		const mongoose = server.registry.get('mongoose');
		mongoose.model('TransomAclUser', localAclUserSchema.AclUserSchema(mongoose));
		mongoose.model('TransomAclGroup', localAclGroupSchema.AclGroupSchema(mongoose));

		if (process.env.NODE_ENV !== 'production') {
			initializeAcl.createGroups(server);
			initializeAcl.createDefaultUser(server);
		}

		const localUserHandler = LocalUserHandler(server);

		// *After* creating the required Mongoose models!
		passportStrategies({
			mongoose,
			passport
		});

		const preMiddleware = options.preMiddleware || [];
		const postMiddleware = options.postMiddleware || [];

		server.post('/v1/:__api_code/:__version/user/signup', preMiddleware, localUserHandler.handleSignup, postMiddleware);
		server.post('/v1/:__api_code/:__version/user/verify', preMiddleware, localUserHandler.handleVerify, postMiddleware);
		server.post('/v1/:__api_code/:__version/user/login', preMiddleware, localUserHandler.handleLogin, postMiddleware);
		server.post('/v1/:__api_code/:__version/user/forgot', preMiddleware, localUserHandler.handleForgot, postMiddleware);
		server.post('/v1/:__api_code/:__version/user/reset', preMiddleware, localUserHandler.handleReset, postMiddleware);

		// Check isLoggedIn first on the following routes.
		const mware = isLoggedInMiddleware({
			mongoose: server.registry.get('mongoose'),
			passport: server.registry.get('passport')
		});
		server.registry.set('isLoggedIn', mware.isLoggedIn);

		let preMiddlewareAlt = [server.registry.get('isLoggedIn'), ...preMiddleware];

		server.get('/v1/:__api_code/:__version/user/me', preMiddlewareAlt, localUserHandler.handleUserMe, postMiddleware);
		server.get('/v1/:__api_code/:__version/user/sockettoken', preMiddlewareAlt, localUserHandler.handleSocketToken, postMiddleware);
		server.post('/v1/:__api_code/:__version/user/logout', preMiddlewareAlt, localUserHandler.handleLogout, postMiddleware);
	}
}

module.exports = new TransomLocalUser();
