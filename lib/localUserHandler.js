'use strict';
const createError = require('http-errors');
const passport = require('passport');
const debug = require('debug')('transom:mongoose:localuser');

module.exports = function LocalUserHandler(server, options) {
	const mongoose = server.registry.get('mongoose');
	const AclUser = mongoose.model("TransomAclUser");
	const emailHandler = options.emailHandler;
	const templateHandler = options.templateHandler;
	const passwordResetSubject = options.passwordResetSubject || "Password reset request";
	const validationSubject = options.validationSubject || "Validation email";

	// Nonce is used to authenticate socket connections
	const nonceHandler = options.nonceHandler;
	const nonceExpirySeconds = options.nonceExpiry || 5;

	function handleForgot(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			const reply = {
				"success": true,
				"message": "An email will be dispatched with instructions to reset your password."
			};
			const qry = {
				local_auth_type: 'password',
				active: true,
				email: req.body.email
			};

			AclUser.findOne(qry, function (err, usr) {
				if (err) {
					debug('Error finding forgot password user ', err);
					return reject(new restify.InternalError(err));
				}
				if (!usr) {
					// ** Always** Send success, don't let people guess our email addresses.
					debug('Forgot password user not found!');
					return resolve(reply);
				}
				usr.verify_token = usr.generateVerifyHash(); // Make a new 'forgot' token...
				usr.modifiedBy = usr;

				usr.save().then(function (err, user) {
					const data = {
						email: user.email,
						display_name: user.display_name,
						verify_token: user.verify_token
					};
					const transomEmail = server.registry.get(emailHandler);
					const transomTemplate = server.registry.get(templateHandler);

					debug(`Sending forgot password message to ${user.email}`);
					transomEmail.sendFromNoreply({
						subject: passwordResetSubject,
						to: user.email,
						html: transomTemplate.renderEmailTemplate("ForgotPassword.html", data),
						text: transomTemplate.renderEmailTemplate("ForgotPassword.text", data)
					});
					resolve(reply);
				}).catch((err) => {
					debug('Error finding forgot password user ', err);
					return reject(new restify.InternalError(err));
				})
			});
		}).then((item) => {
			res.json(item);
			next();
		}).catch((err) => {
			debug(`Forgot password request failed`, err);
			next(err);
		});
	}; // handleForgot

	// *********************************************************
	function handleReset(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			const currentToken = req.params.token || 'missing';
			const email = req.params.email || 'missing@email.com';
			const password = req.params.password;
			if (!password) {
				return reject(createError(400, "New password is missing"));
			}
			const qry = {
				local_auth_type: 'password',
				active: true,
				email: email,
				verify_token: currentToken
			};
			AclUser.findOne(qry, function (err, usr) {
				if (err) {
					debug(`Error finding user for password reset`, err);
					return reject(createError(400, err));
				}
				if (!usr) {
					debug(`Password reset email address and reset token did not match`, email);
					return reject(createError(401, "Email address and reset token did not match"));
				}
				usr.verify_token = "password-reset:" + usr.generateVerifyHash();
				usr.modifiedBy = 'password-reset';

				debug(`Updating ${email} with a password reset`);
				usr.setPassword(password, () => {
					usr.save().then(() => {
						const data = {
							'success': true,
							'message': "Password updated"
						};
						resolve(data);
					}).catch((err) => {
						debug(`Error updating user during password reset`, err);
						return reject(createError(400, err));
					});
				});
			});
		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
			debug(`Password reset request failed`, err);
			next(err);
		});
	}; // handleReset

	/**********************************************************/
	function handleSignup(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			if (req.user) {
				debug(`User is already logged in, ignore signup.`);
				return resolve(null, req.user);
			}
			const postSignupResponse = function (err, user, info) {
				if (err) {
					debug(`New user signup request failed`, err);
					return reject(createError(400, err.message || err));
				}
				if (!user) {
					debug(`User is already registered, or request failed`, info);
					return reject(createError(400, info || "Signup failed."));
				}
				const data = {
					email: user.email,
					verify_token: user.verify_token
				};
				const transomEmail = server.registry.get(emailHandler);
				const transomTemplate = server.registry.get(templateHandler);

				debug(`Sending signup validation email to ${user.email}`);
				transomEmail.sendFromNoreply({
					subject: validationSubject,
					to: user.email,
					html: transomTemplate.renderEmailTemplate("Verification.html", data),
					text: transomTemplate.renderEmailTemplate("Verification.text", data)
				});
				// Signup should NOT include logging in!
				debug(`Sending post-signup response #1`);
				resolve({
					'success': true,
					"which": 1
				});
			};

			passport.authenticate('local-signup', postSignupResponse)(req, res, function () {
				debug(`Sending post-signup response #2`, {
					arguments
				});
				return resolve({
					'success': true,
					"which": 2
				});
			});
		}).then(function (item) {
			res.json(item);
			next();
		}).catch(function (err) {
			debug(`Error during new signup request`, err);
			next(err);
		});
	}; // handleSignup

	/**********************************************************/
	function handleUserMe(req, res, next) {
		Promise.resolve(req.locals.user || {})
		.then(function (me) {
			debug(`Handling user/me request for ${me.display_name}.`, me);
			res.json({
				me
			});
			next();
		}).catch(function (err) {
			debug(`Error during user/me request`, err);
			next(err);
		});
	}; // handleUserMe

	/**********************************************************/
	function handleSocketToken(req, res, next) {
		const transomNonce = server.registry.get(nonceHandler);

		function loggable(token) {
			if (typeof transomNonce.loggableToken === 'function') {
				return transomNonce.loggableToken(token);
			}
			return `${token.substr(0, 4)}***${token.substr(-4)}`;
		}

		var p = new Promise(function (resolve, reject) {
			// Create the nonce with req.locals.user as the payload.
			transomNonce.createNonce(req.locals.user, nonceExpirySeconds, function (err, nonce) {
				if (err) {
					debug('Error creating nonce', err);
					return reject(err);
				}
				debug(`Created nonce ${loggable(nonce.token)}`);
				resolve(nonce);
			});
		}).then(function (nonce) {
			debug(`Replying with ${loggable(nonce.token)}`);
			res.json({
				token: nonce.token
			});
			next();
		}).catch(function (err) {
			debug('Error in handleSocketToken', err);
			next(err);
		});
	}; // handleSocketToken

	/**********************************************************/
	function handleForceLogout(req, res, next) {
		var p = new Promise(function (resolve, reject) {

			// Lookup the user by Id and do the logout.
			AclUser.findOne({
				_id: req.params.id,
				local_auth_type: 'password'
			}, function (err, user) {
				if (err) {
					return reject(createError(400, err));
				}
				if (!user) {
					return reject(createError(404));
				}
				user.modifiedBy = req.locals.user;
				user.last_logout_date = new Date();

				// Destroy ALL the current Bearer tokens 
				user.bearer = [];

				// Save the User back to the database
				debug(`Forcing logout of ${user.email}`);
				user.save().then((result) => {
					resolve({
						success: true,
						message: 'success'
					});
				}).catch((err) => {
					debug('Error in force logout', err);
					return reject(createError(400, err));
				});
			});
		}).then((data) => {
			res.json(data);
			next();
		}).catch((err) => {
			debug('Error in force logout', err);
			next(err);
		});
	}; // handleForceLogout

	/**********************************************************/
	function handleLogout(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			// Return success even if not currently logged in.
			if (!req.locals.user) {
				debug(`Request is not authenticated, nobody to logout.`);
				return resolve({
					success: true,
					message: 'not logged in'
				});
			}

			// Lookup current user and do the logout.
			debug(`Logging out the current authenticated session for User ${req.locals.user}`);
			AclUser.findOne({
				_id: req.locals.user._id,
				local_auth_type: 'password',
				active: true
			}, function (err, user) {
				if (err) {
					debug(`Error finding User during logout request.`, err);
					return reject(createError(400, err));
				}
				if (!user) {
					debug(`User not found during logout request.`);
					return resolve({
						success: true,
						message: 'not found'
					});
				}
				user.modifiedBy = 'logout';
				user.last_logout_date = new Date();

				// Destroy the current Bearer token 
				for (var i = user.bearer.length - 1; i > -1; i--) {
					if (req.headers.authorization == `Bearer ${user.bearer[i].token}`) {
						user.bearer.splice(i, 1);
						break;
					}
				}

				// Save the User back to the database
				user.save().then(() => {
					resolve({
						success: true,
						message: 'success'
					});
				}).catch((err) => {
					debug(`Error updating user during logout request.`, err);
					return reject(createError(400, err));
				});
			});
		}).then(function (data) {
			req.logout(); // Provided by Passport
			res.json(data);
			next();
		}).catch(function (err) {
			debug(`Error handling logout request.`, err);
			next(err);
		});
	}; // handleUserLogout

	/**********************************************************/
	function handleVerify(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			const currentToken = req.params.token || false;
			if (!currentToken || currentToken == 'missing') {
				debug(`Verify request, token is missing.`);
				return reject(createError(400, "Verify token is missing"));
			}

			const postVerifyHandler = function (err, user, info) {
				if (err) {
					debug(`Error handling verify request.`, err);
					return reject(createError(400, err));
				}
				// The API doesn't store any state in a session!
				req.login(user, {
					'session': false
				}, function (err) {
					if (err) {
						debug(`Login failed during verify request.`, err);
						return reject(createError(400, "Failed logging in verified user"));
					}
					debug(`User is verified and logged in.`);
					var data = {
						'success': true,
						'token': req.locals.basic_login_token // TODO: option jwt here instead!
					};
					resolve(data);
				});
			};

			passport.authenticate('local-verify', postVerifyHandler)(req, res);
		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
			debug(`Error during verify request.`, err);
			next(err);
		});
	} // handleVerify

	// *********************************************************
	function handleLogin(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			const loginHandler = function (err, user, info) {
				if (err) {
					debug(`Error during user login`, err);
					return reject(err);
				}
				if (!user) {
					debug(`Login user not found or invalid credentials`, info);
					reject(createError(401, "Incorrect username or password"));
				} else {
					const data = {
						'success': true,
						'token': req.locals.basic_login_token
					};
					resolve(data);
				}
			};

			debug(`Handling user login`);
			passport.authenticate('local', {
				session: false
			}, loginHandler)(req, res);
		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
			debug(`Error during login request.`, err);
			next(err);
		});
	}; // handleLogin

	return {
		handleForgot,
		handleReset,
		handleSignup,
		handleUserMe,
		handleSocketToken,
		handleForceLogout,
		handleLogout,
		handleVerify,
		handleLogin
	};
};