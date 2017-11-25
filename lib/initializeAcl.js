'use strict';
const assert = require('assert');
// const debug = require('debug')('transom:mongoose:localuser:initializeAcl');

module.exports = function AclInitialiser() {
	const sysAdminGroup = 'sysadmin';

	function createGroups(server) {
		const mongoose = server.registry.get('mongoose');
		const AclGroupModel = mongoose.model("TransomAclGroup");
		const dbMongoose = server.registry.get('transom-config.definition.mongoose', null);

		if (dbMongoose) {
			// Create Mongoose models from the API definition.
			const groups = [sysAdminGroup];
			Object.keys(dbMongoose).forEach(function(key) {
				const acl = dbMongoose[key].acl;
				if (typeof acl.create === 'string') {
					acl.create = [acl.create];
				}
				groups.push(...acl.create);

				if (acl.default && acl.default.groups) {
					groups.push(...Object.keys(acl.default.groups));
				}
			});
			// Build a list of distinct group codes.
			const distinctGroups = {};
			groups.map(function(group) {
				group = group.toLowerCase().trim();
				distinctGroups[group] = true;
			});
			// Attempt to insert Groups, existing ones will fail on a unique constraint.
			Object.keys(distinctGroups).map(function(group) {
				const newGroup = new AclGroupModel({
					code: group,
					name: group,
					active: true
				});
				newGroup.modifiedBy = 'initialize-acl';
				newGroup.save().catch(function(err) {
					if (err.code !== 11000) {
						console.error(`Error creating ${group} Group.`, err);
					}
				});
			});
		}
	};

	function createDefaultUser(server) {
		const mongoose = server.registry.get('mongoose');
		const AclUserModel = mongoose.model("TransomAclUser");

		const newUser = new AclUserModel({
			email: server.registry.get('transom-options.administrator_email', 'administrator@localhost'),
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
	};

	return {
		createGroups,
		createDefaultUser
	};
}();
