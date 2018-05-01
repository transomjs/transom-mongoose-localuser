'use strict';
const assert = require('assert');
// const debug = require('debug')('transom:mongoose:localuser:initializeAcl');

module.exports = function AclInitialiser() {
	const sysAdminGroup = 'sysadmin';

	function createDefaultUser(server, options) {
		const mongoose = server.registry.get('mongoose');
		const AclUserModel = mongoose.model("TransomAclUser");

		if (options.administrator !== false) {
			const administratorOpts = options.administrator || {};
			const newUser = new AclUserModel({
				email: administratorOpts.email || 'administrator@localhost',
				username: administratorOpts.username || 'administrator',
				display_name: administratorOpts.displayName || 'Administrator',
				groups: administratorOpts.groups || [sysAdminGroup],
				active: administratorOpts.active === undefined ? true : administratorOpts.active,
				modifiedBy: 'initialize-acl',
				verified_date: new Date()
			});
			newUser.verify_token = 'initialized-' + newUser.generateVerifyHash();

			newUser.setPassword('password', function(err, user) {
				user.save(function(err, user, numAffected) {
					if (err && err.code !== 11000) {
						console.error(`Error creating ${user.email} User.`, err);
					}
				});
			});
		}

		if (options.anonymous !== false) {
			const anonymousOpts = options.anonymous || {};
			const anonUser = new AclUserModel({
				email: anonymousOpts.email || 'anonymous@localhost',
				username: 'anonymous', // not configurable!
				display_name: anonymousOpts.displayName || 'Anonymous',
				groups: [],
				active: anonymousOpts.active === undefined ? true : anonymousOpts.active,
				modifiedBy: 'initialize-acl',
				verified_date: new Date()
			});
			anonUser.verify_token = 'initialized-' + anonUser.generateVerifyHash();

			anonUser.setPassword('password', function(err, user) {
				user.save(function(err, user, numAffected) {
					if (err && err.code !== 11000) {
						console.error(`Error creating ${user.email} User.`, err);
					}
				});
			});
		}
	};

	return {
		createDefaultUser
	};
}();
