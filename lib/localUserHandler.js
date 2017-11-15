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
				//need to get the logged on cookie in here and then do the redirect somehow
				usr.verify_token = usr.generateVerifyHash(); // Make a new 'forgot' token...
				usr.modifiedBy = usr;

				usr.save(function (err, user) {
					if (err) {
						return reject(new restify.InternalError(err));
					}
					const protocol = ((req.headers.origin || HTTPS).substring(0, 6)) === HTTPS ? HTTPS : HTTP;
					const data = {
						email: user.email,
						display_name: user.display_name,
						resetUrl: `${protocol}//${req.headers.host}/reset?token=${user.verify_token}&email=${user.email}`
					};

					const transomEmail = server.registry.get(emailHandler);
					const transomTemplate = server.registry.get(templateHandler);

					// if (!transomEmail.sendFromNoreply) {
					// 	return reject(new restify.InternalError("Email method 'sendFromNoreply' not found."));
					// }

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
				// Get the protocol from the Origin header, if it's missing fallback to 'https:'.
				const protocol = ((req.headers.origin || HTTPS).substring(0, 6)) === HTTPS ? HTTPS : HTTP;
				const data = {
					email: user.email,
					url: `${protocol}//${req.headers.host}/verify?token=${user.verify_token}`
				};

				const transomEmail = server.registry.get(emailHandler);
				const transomTemplate = server.registry.get(templateHandler);

				// if (!transomEmail.sendFromNoreply) {
				// 	return reject(new restify.InternalError("Email method 'sendFromNoreply' not found."));
				// }

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
	function handleLogout(req, res, next) {
		// TODO: write this...
		var p = new Promise(function (resolve, reject) {
			return resolve('TODO: logout');

			var usr = req.locals.usr;
			// Invalidate Remember me cookies on ALL devices.
			usr.local.remember_me = "logout-" + aUt.randomString(64, '#aA');
			// TODO: whack the current Bearer token.

			usr.save(usr, function (err, newUsr) {
				if (err) {
					return reject(err);
				}
				// aUt.log.info('Logged out user: ' + usr.email);

				res.clearCookie('connect.sid');
				res.clearCookie('remember_me');

				req.logout(); // Provided by Passport
				resolve({});
			});

		}).then(function (data) {
			res.json(data);
			next();
		}).catch(function (err) {
			next(err);
		});
	}; // handleUserLogout


	/**********************************************************/
	function handleVerify(req, res, next) {
		var p = new Promise(function (resolve, reject) {
			const currentToken = req.params.token;
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
					// } );
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
		handleLogout,
		handleVerify,
		handleLogin
	};
};