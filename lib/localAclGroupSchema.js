
// const auditablePlugin = require('../transom-mongoose/plugins/auditablePlugin');
const auditablePlugin = require('@transomjs/transom-mongoose/lib/plugins/auditablePlugin');

const { Schema } = require('mongoose');

module.exports = function() {

	function AclGroupSchema() {
		var aclGroupSchema = new Schema({
			code: {
				type: 'string',
				required: true,
				set: function(val) {
					// Code is non-editable as it gets used in ACL data!
					if (this.isNew || !this.code) {
						return val.trim().toLowerCase();
					}
					return this.code;
				}
			},
			name: {
				type: 'string',
				required: true
			},
			active: {
				type: 'Boolean',
				required: true,
				default: true
			},
			note: String,
			source_entity: String,
			source_ref: Schema.Types.ObjectId
		}, {
			safe: {
				w: 1,
				wtimeout: 5000
			},
			collection: 'acl_groups',
			autoIndex: true
		});

		aclGroupSchema.index({
			code: 1
		}, {
			unique: true
		});
		aclGroupSchema.index({
			name: 1
		}, {
			unique: true
		});

		aclGroupSchema.plugin(auditablePlugin);

		return aclGroupSchema;
	}

	return {
		AclGroupSchema
	}
}();
