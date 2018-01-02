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
	debug("Creating Transom-mongoose-localUser");

	this.initialize = function(server, options) {

		debug("Initializing Transom-mongoose-localUser...");

		server.registry.set('passport', passport);

		const mongoose = server.registry.get('mongoose');
		mongoose.model('TransomAclUser', localAclUserSchema.AclUserSchema(mongoose));
		mongoose.model('TransomAclGroup', localAclGroupSchema.AclGroupSchema(mongoose));

		if (process.env.NODE_ENV !== 'production') {
			initializeAcl.createGroups(server);
			initializeAcl.createDefaultUser(server);
		}

		const localUserHandler = LocalUserHandler(server, {
			emailHandler: options.emailHandler || 'transomSmtp',
			templateHandler: options.templateHandler || 'transomTemplate',
			nonceHandler: options.nonceHandler || 'transomNonce'
		});

		// Create strategies *after* creating the required Mongoose models!
		passportStrategies({
			mongoose,
			passport
		});

		const preMiddleware = options.preMiddleware || [];
		const postMiddleware = options.postMiddleware || [];

		const uriPrefix = server.registry.get('transom-config.definition.uri.prefix');		

		server.post(`${uriPrefix}/user/signup`, preMiddleware, localUserHandler.handleSignup, postMiddleware);
		server.post(`${uriPrefix}/user/verify`, preMiddleware, localUserHandler.handleVerify, postMiddleware);
		server.post(`${uriPrefix}/user/login`, preMiddleware, localUserHandler.handleLogin, postMiddleware);
		server.post(`${uriPrefix}/user/forgot`, preMiddleware, localUserHandler.handleForgot, postMiddleware);
		server.post(`${uriPrefix}/user/reset`, preMiddleware, localUserHandler.handleReset, postMiddleware);
		server.post(`${uriPrefix}/user/logout`, preMiddleware, localUserHandler.handleLogout, postMiddleware);

		// Check isLoggedIn first on the following routes.
		const mware = isLoggedInMiddleware({
			mongoose: server.registry.get('mongoose'),
			passport: server.registry.get('passport')
		});
		server.registry.set('isLoggedIn', mware.isLoggedIn);

		let preMiddlewareAlt = [server.registry.get('isLoggedIn'), ...preMiddleware];

		server.get(`${uriPrefix}/user/me`, preMiddlewareAlt, localUserHandler.handleUserMe, postMiddleware);
		server.get(`${uriPrefix}/user/sockettoken`, preMiddlewareAlt, localUserHandler.handleSocketToken, postMiddleware);
	}
}

module.exports = new TransomLocalUser();
