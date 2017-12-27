module.exports = function() {

	var passportLocalMongoose = require('passport-local-mongoose');
	var bcrypt = require('bcrypt');
	var uuid = require('uuid');
	const auditablePlugin = require('@transomjs/transom-mongoose/lib/plugins/auditablePlugin');
	const { Schema } = require('mongoose');
	
	function AclUserSchema() {
		var aclUserSchema = new Schema({
			email: {
				type: String,
				required: true
			},
			username: {
				type: String,
				required: true
			},
			password: String,
			password_salt: String,
			display_name: String,
			verify_token: String,
			verified_date: Date,
			local_auth_type: {
				type: String,
				required: true,
				enum: ['password', 'user-secret'],
				default: 'password'
			},
			user_secret: String,
			active: {
				type: 'Boolean',
				required: true,
				default: true
			},
			groups: [{
				type: String
			}],
			// last_device_id: String,
			last_login_date: Date,
			last_logout_date: Date,
			login_attempts: {
				type: Number,
				default: 0
			},
			// login_cookie: String,
			// csrf_token: String,
			// privs: {},
			bearer: [{
				_id: false,
				token: String,
				last_request: Date
			}]
			// autoIndex: Dev = true, Prod = false
		}, {
			safe: {
				w: 1,
				wtimeout: 5000
			},
			timestamps: {
				createdAt: 'created_date',
				updatedAt: 'updated_date'
			},
			collection: 'acl_users',
			autoIndex: true
		});

		aclUserSchema.index({
			email: 1
		}, {
			unique: true
		});
		aclUserSchema.index({
			username: 1
		}, {
			unique: true
		});

		aclUserSchema.plugin(auditablePlugin, {
			requireModifiedBy: false
		});

		aclUserSchema.path('email').set(function(value) {
			return value.toLowerCase();
		});

		aclUserSchema.path('username').set(function(value) {
			return value.toLowerCase();
		});

		aclUserSchema.plugin(passportLocalMongoose, {
			usernameField: "email",
			saltField: "password_salt",
			hashField: "password",
			usernameLowerCase: true,
			lastLoginField: 'last_login_date',
			attemptsField: 'login_attempts',
			maxAttempts: 20, // Requires a call to user.resetAttempts(cb) or a manual update.
			interval: 500, // default = 100 ms
			maxInterval: 5 * 60 * 1000, // 1 minute, default  300000 (5 min)
			limitAttempts: true,
			findByUsername: function(model, query) {
				// Add additional query parameter - AND condition - active: true
				query.active = true; // Only active Users can login!
				return model.findOne(query);
			}
		});

		// Strip out mongoose properties we don't want to share!
		aclUserSchema.options.toJSON = {
			transform: function(doc, ret, options) {

				const whitelist = "email,username,display_name,active,groups,privs" +
					",_id,created_by,created_by_id,created_date,updated_by,updated_by_id,updated_date";
				const whitelistArray = whitelist.split(',');

				const sanitized = {};
				for (var field of whitelistArray) {
					sanitized[field] = ret[field];
				}
				return sanitized;
			}
		};

		// methods ======================
		/**
		 * Used to hash passwords for new and authenticating AppUsers.
		 * @param  {[type]} password [description]
		 * @return {[type]}          [description]
		 */
		aclUserSchema.methods.generateHash = function(password) {
			return bcrypt.hashSync(password, bcrypt.genSaltSync(12), null);
		};

		aclUserSchema.methods.generateSaltedHash = function(password, salt) {
			return bcrypt.hashSync(password, salt, null);
		};

		/**
		 * Used during new TransomAclUSer signup & verification.
		 * @method generateVerifyHash
		 * @return CallExpression
		 */
		aclUserSchema.methods.generateVerifyHash = function() {
			return require('crypto').randomBytes(32).toString('hex');
		};

		aclUserSchema.methods.bearerHousekeeping = function() {
			// TODO: Is this still required to prune the bearer array?
		}

		aclUserSchema.methods.finalizeLogin = function(options, done) {
			const user = this;
			const req = options.req;

			// All is well, set the bearer token on the user record and
			// return the user. The user is expected to use provide the
			// token in the BEARER http headers (Authorization: Bearer mytoken123)

			// First make sure that the groups and roles are fully populated, so that
			// the assigned privs can get rolled up to the app user when the new
			// bearer token is recorded on the appuser document.

			// *********************************************************
			// Housekeeping on the bearer array removing dead sessions.
			// *********************************************************
			const idleSessionLimit = (60 * 60000); // 60 minutes
			const sessionExpiry = new Date() - idleSessionLimit; // 60 minutes ago
			let b = user.bearer.length;
			while (b--) {
				if ((user.bearer[b].last_request * 1) < sessionExpiry) {
					user.bearer.splice(b, 1); // Discard the tokens that have expired.
				}
			}
			// Limited to 10 active sessions per named user!!
			if (user.bearer.length > 9) {
				user.bearer.shift(); // Discard the first (oldest) one!
			}
			// End of housekeeping.
			// *********************************************************

			// *********************************************************
			// Fully populated...now create a token and put it on this user.
			// *********************************************************
			const bearerToken = {
				"token": new Buffer(uuid.v4()).toString('base64'),
				"last_request": new Date()
			};
			user.bearer.push(bearerToken);
			// *********************************************************

			user.modifiedBy = user.email;
			user.save(function(err, updatedUser) {
				if (err) {
					console.error('Error updating user during finalizeLogin:', err);
					return done(null, false, {
						message: 'Internal error during login.'
					});
				}
				// Pass along  the logged-in User and the token
				// they should use in future authenticated requests.
				req.locals.user = updatedUser;
				req.locals.basic_login_token = bearerToken.token;

				return done(null, updatedUser);
			});
		};
		return aclUserSchema;
	}

	return {
		AclUserSchema
	}
}();
