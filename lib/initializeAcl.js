'use strict';
const assert = require('assert');
// const debug = require('debug')('transom:mongoose:localuser:initializeAcl');

module.exports = function AclInitialiser() {
	const sysAdminGroup = 'sysadmin';

	function createDefaultUser(server) {
		const mongoose = server.registry.get('mongoose');
		const AclUserModel = mongoose.model("TransomAclUser");

		const newUser = new AclUserModel({
			email: server.registry.get('transom-config.administrator_email', 'administrator@localhost'),
			username: 'administrator',
			display_name: 'Administrator',
			groups: [sysAdminGroup],
			active: true,
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

		const anonUser = new AclUserModel({
			email: server.registry.get('transom-config.anonymous_email', 'anonymous@localhost'),
			username: 'anonymous',
			display_name: 'Anonymous',
			groups: [],
			active: true,
			modifiedBy: 'initialize-acl',
			verified_date: new Date()
		});
		anonUser.verify_token = 'initialized-' + newUser.generateVerifyHash();

		anonUser.setPassword('password', function(err, user) {
			user.save(function(err, user, numAffected) {
				if (err && err.code !== 11000) {
					console.error(`Error creating ${user.email} User.`, err);
				}
			});
		});
	};

	return {
		createDefaultUser
	};
}();
