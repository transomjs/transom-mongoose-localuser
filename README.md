# transom-mongoose-localuser
Add local authentication to your Transom REST API

[![Build Status](https://travis-ci.org/transomjs/transom-mongoose-localuser.svg?branch=master)](https://travis-ci.org/transomjs/transom-mongoose-localuser)


## Installation

```bash
$ npm install transom-mongoose-localuser --save
```

## Overview
The transom-mongoose-local-user plugin is the security provider for the TransomJS Api. It maintains a database of the users and groups in the MongoDB database, and it provides the API endpoints to support new user registration and login and logging off etc.

The transom-mongoose-local-user plugin tightly integrates with the [transon-mongoose](https://github.com/transomjs/transom-mongoose) and [transom-server-functions](https://github.com/transomjs/transom-server-functions) plugins by providing middleware for securing their endpoints.


## Usage

```javascript
const TransomCore = require('@transomjs/transom-core');

// transonMongoose is required when using transom-mongoose-local-user
const transomLocalUser = require('@transomjs/transom-mongoose-localuser');

const transom = new TransomCore();

const localUserOptions = {};

transom.configure(transomLocalUser, localUserOptions);

const myApi = require('./myApi');

// Initialize them all at once.
transom.initialize(myApi).then(function(server){
 ...
});
```

#### Options
The API endpoints created by transom-mongoose-localuser support the workflows for creating and verifying users and resetting passwords. 
It will utilize plugins for sending emails and creating email content from templates. 
Defaults are used when the options object does not provide alternates. 

*Handler keys on the options object are the registry key strings that return the corresponding handler.

Optional configuration values include:
 - emailHandler : (default 'transomSmtp')
 - templateHandler : (default 'transomTemplate')
 - nonceHandler : (default 'transomNonce')

Route groups can be disabled by passing boolean 'false' values on the following keys:
 - signup : false (disable registration and new user verification)
 - forgot : false (disable forgot password and the corresponding verification)
 - sockettoken: false (disable socket authentication requests)
 - forcelogout: false (disable a [sysadmin only] route to logout another user)

Default users (administrator & anonymous) can be customized in metadata as well:
 - administrator: {
				email: 'admin@my-company.com',
				username: 'admin',
				displayName: 'Admin',
				active: true
			},
 - anonymous: false  (the 'anonymous' user is neither created nor considered for authentication)
 Note, anonymous username is fixed and cannot be customized.


```
    localuser: {
        signup: false,
        administrator: {
            email: 'mark@binaryops.ca',
            username: 'mvoorberg',
            displayName: 'Mark Voorberg',
            active: true
        },
        anonymous: false
    },
```

#### Security Endpoints
The transon-mongoose-localuser plugin will create the following routes on a TransomJS REST-API:

|Endpoint| Method | Payload | Description                    |
|---------|--------|---------|--------------------------------|
|/user/signup| POST | { username, password, email, display_name }| Creates a new user object. It will send an email to the user to verify the email address, as well the reponse object contains the full verification url.|
|/user/verify| POST | { token } | Validates the user by means of the token, once completed the user can use the login route|
|/user/login | POST | {} | The login route uses [basic authentication](https://swagger.io/docs/specification/authentication/basic-authentication/) using the `Authorization` header with the username and password, seperated by a colon, and encoded in base64. It returns a token that must be used as a bearer token in the `Authorization` header, for accessing secured end points in the API. Remember that https must be used for keeping user credentials secure!  |
| /user/logout | POST | {} | (Requires a valid Authorization header) Invalidate the current bearer token. |
| /user/forgot | POST | { email } | Sends an email if the provided email address is found in the user database. The email contains a token that must be presented on the reset request. |
| /user/reset | POST | { token, email, password } | Provide the new password along with the token that was generated in an email through the `forgot` request. |
| /user/me | GET | none | (Requires a valid Authorization header) Provide a sanitized copy of the local User Object. |
| /user/sockettoken | GET | none | (Requires a valid Authorization header) Provide the token to be used with the internal SocketIO server. |

#### Middleware
After successful initialization of this module there will be an entry in the Transom server registry for validating that the current user (as identified by the Authorization header) is, in fact, Authenticated.
It can be acccessed using `server.registry.get('localUserMiddleware')`.
```javascript
const uriPrefix = server.registry.get('transom-config.definition.uri.prefix');
const middleware = server.registry.get('localUserMiddleware');
const isLoggedIn = middleware.isLoggedInMiddleware();

// Add it to your own routes with your own pre-middleware.
const yourPreMiddleware = [isLoggedIn, ...preMiddleware];
const yourPostMiddleware = [];
server.get(`${uriPrefix}/something/secure`, yourPreMiddleware, securedCoolFeature, yourPostMiddleware);
```

