'use strict';
const restifyErrors = require('restify-errors');
const passport = require('passport');
const assert = require('assert');

module.exports = function LocalUserHandler(server, options) {

	const HTTPS = "https:";
	const HTTP = "http:";
	
	const emailHandler = options.emailHandler;
	const templateHandler = options.templateHandler;
	const nonceHandler = options.nonceHandler;

	const AclUser = server.registry.get('mongoose').model("TransomAclUser");

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
					return reject(new restify.InternalError(err));
				}
				if (!usr) {
					// ** Always** Send success, don't let people guess our email addresses.
					return resolve(reply);
				}
				usr.verify_token = usr.generateVerifyHash(); // Make a new 'forgot' token...
				usr.modifiedBy = usr;

				usr.save(function (err, user) {
					if (err) {
						return reject(new restify.InternalError(err));
					}
					const data = {
						email: user.email,
						display_name: user.display_name,
						verify_token: user.verify_token
					};
					const transomEmail = server.registry.get(emailHandler);
					const transomTemplate = server.registry.get(templateHandler);

					transomEmail.sendFromNoreply({
						subject: "Password reset request",
						to: user.email,
						html: transomTemplate.renderEmailTemplate("ForgotPassword.html", data),
						text: transomTemplate.renderEmailTemplate("ForgotPassword.text", data)
					});
					resolve(reply);
				});
			});
		}).then(function (item) {
			res.json(item);
			next();
		}).catch(function (err) {
			console.log("===== ERROR", err);
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
				return reject(new restifyErrors.BadRequestError("New password is missing"));
			}
			const qry = {
				local_auth_type: 'password',
				active: true,
				email: email,
				verify_token: currentToken
			};
			AclUser.findOne(qry, function (err, usr) {
				if (err) {
					return reject(new restifyErrors.InternalError(err));
				}
				if (!usr) {
					return reject(new restifyErrors.InvalidCredentialsError("Email address and reset token did not match"));
				}
				usr.verify_token = "password-reset:" + usr.generateVerifyHash();
				usr.modifiedBy = 'password-reset';

				usr.setPassword(password, function () {
					usr.save(function (err, user) {
						if (err) {
							console.error(err);
							return reject(new restifyErrors.InternalError(err));
						}
						const data = {
							'success': true,
							'message': "Password updated"
						};
						resolve(data);
					});
				});
			});
		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
			next(err);
		});
	}; // handleReset

	/**********************************************************/
	function handleSignup(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			if (req.user) {
				// user is logged in and already has a local account. Ignore signup.
				return resolve(null, req.user);
			}

			const postSignupResponse = function (err, user, info) {
				if (err) {
					return reject(new restifyErrors.InternalError(err.message || err));
				}
				if (!user) {
					// Already registered or failed!
					return reject(new restifyErrors.BadRequestError(info || "Signup failed."));
				}

				const data = {
					email: user.email,
					verify_token: user.verify_token
				};
				const transomEmail = server.registry.get(emailHandler);
				const transomTemplate = server.registry.get(templateHandler);

				transomEmail.sendFromNoreply({
					subject: "Validation email",
					to: user.email,
					html: transomTemplate.renderEmailTemplate("Verification.html", data),
					text: transomTemplate.renderEmailTemplate("Verification.text", data)
				});
				// Signup should NOT include logging in!
				resolve({
					'success': true,
					"which": 1
				});
			};

			passport.authenticate('local-signup', postSignupResponse)(req, res, function () {
				return resolve({
					'success': true,
					"which": 2
				});
			});
		}).then(function (item) {
			res.json(item);
			next();
		}).catch(function (err) {
			next(err);
		});
	}; // handleSignup

	/**********************************************************/
	function handleUserMe(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			resolve(req.locals.user || 'undefined');
		}).then(function (me) {
			res.json({
				me
			});
			next();
		}).catch(function (err) {
			next(err);
		});
	}; // handleUserMe

	/**********************************************************/
	function handleSocketToken(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			//create the nonce with req.locals.user as the payload. TODO expiry should from config
			const expirySeconds = 5;
			const transomNonce = server.registry.get(nonceHandler);
			transomNonce.createNonce(req.locals.user, expirySeconds, function (err, nonce) {
				if (err) {
					return reject(err);
				}
				resolve(nonce);
			});
		}).then(function (nonce) {
			res.json({
				token: nonce.token
			});
			next();
		}).catch(function (err) {
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
						return reject(new restifyErrors.InternalError(err));
					}
					if (!user) {
						return reject(new restifyErrors.NotFoundError());
					}
					user.modifiedBy = req.locals.user;
					user.last_logout_date = new Date();
	
					// Destroy ALL the current Bearer tokens 
					user.bearer = [];
	
					// Save the User back to the database
					user.save(function (err, result) {
						if (err) {
							return reject(new restifyErrors.InternalError(err));
						}
						resolve({
							success: true,
							message: 'success'
						});
					});
				});
			}).then(function (data) {
				res.json(data);
				next();
			}).catch(function (err) {
				next(err);
			});
		}; // handleForceLogout
		
	/**********************************************************/
	function handleLogout(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			// Return success even if not currently logged in.
			if (!req.locals.user) {
				return resolve({
					success: true,
					message: 'not logged in'
				});
			}
			
			// Lookup current user and do the logout.
			AclUser.findOne({
				_id: req.locals.user._id,
				local_auth_type: 'password',
				active: true
			}, function (err, user) {
				if (err) {
					return reject(new restifyErrors.InternalError(err));
				}
				if (!user) {
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
				user.save(function (err, result) {
					if (err) {
						return reject(new restifyErrors.InternalError(err));
					}
					resolve({
						success: true,
						message: 'success'
					});
				});
			});
		}).then(function (data) {
			req.logout(); // Provided by Passport
			res.json(data);
			next();
		}).catch(function (err) {
			next(err);
		});
	}; // handleUserLogout

	/**********************************************************/
	function handleVerify(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			const currentToken = req.params.token || false;
			if (!currentToken || currentToken == 'missing') {
				return reject(new restifyErrors.BadRequestError("Verify token is missing"));
			}

			const postVerifyHandler = function (err, user, info) {
				if (err) {
					return reject(new restifyErrors.InternalError(err));
				}
				// The API doesn't store any state in a session!
				req.login(user, {
					'session': false
				}, function (err) {
					if (err) {
						return reject(new restifyErrors.InternalError("Failed logging in verified user"));
					}
					var data = {
						'success': true,
						'token': req.locals.basic_login_token
					};
					resolve(data);
				});
			};

			passport.authenticate('local-verify', postVerifyHandler)(req, res);
		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
			next(err);
		});
	} // handleVerify

	// *********************************************************
	function handleLogin(req, res, next) {
		var p = new Promise(function (resolve, reject) {

			const loginHandler = function (err, user, info) {
				if (err) {
					return reject(err);
				}
				if (!user) {
					console.log("Login user not found or invalid credentials", info);
					reject(new restifyErrors.InvalidCredentialsError("Incorrect username or password"));
				} else {
					const data = {
						'success': true,
						'token': req.locals.basic_login_token
					};
					resolve(data);
				}
			};

			passport.authenticate('basic', {
				session: false
			}, loginHandler)(req, res);
		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
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