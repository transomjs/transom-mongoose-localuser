'use strict';

const passport = require('passport');
const debug = require('debug')('transom:mongoose:localuser');
const localAclGroupSchema = require('./lib/localAclGroupSchema');
const localAclUserSchema = require('./lib/localAclUserSchema');
const LocalUserHandler = require('./lib/localUserHandler');
const passportStrategies = require('./lib/passportStrategies');
const isLoggedInMiddleware = require('./lib/isLoggedInMiddleware');
const initializeAcl = require('./lib/initializeAcl');
const localUserClient = require('./lib/localUserClient');

const TransomLocalUser = function () {

	debug("Creating Transom-mongoose-localUser");

	this.initialize = function (server, options) {
		return new Promise(function (resolve, reject) {

			var modelIndexCount = 0;
			const finalizeIndexCreation = function (err) {
				if (err) {
					return reject(err);
				}
				modelIndexCount++;
				if (modelIndexCount == 2) {
					resolve();
				}
			};

			debug("Initializing Transom-mongoose-localUser...");


			server.registry.set('passport', passport);

			const mongoose = server.registry.get('mongoose');
			const transomAclUser = mongoose.model('TransomAclUser', localAclUserSchema.AclUserSchema(mongoose));
			const transomAclGroup = mongoose.model('TransomAclGroup', localAclGroupSchema.AclGroupSchema(mongoose));

			transomAclUser.on('index', finalizeIndexCreation);

			transomAclGroup.on('index', finalizeIndexCreation);

			//initializeAcl.createGroups(server); each plugin should call transomLocalUserClient.setGroups(server, groups)
			initializeAcl.createDefaultUser(server);

			server.registry.set('transomLocalUserClient', localUserClient);

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

			// Only users with the 'sysadmin' group can do this!
			server.post(`${uriPrefix}/user/:id/forceLogout`, preMiddlewareAlt, localUserHandler.handleForceLogout, postMiddleware);
		});
	}
}

module.exports = new TransomLocalUser();