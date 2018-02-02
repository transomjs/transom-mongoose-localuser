# transom-mongoose-localuser
Add local authentication to your Transom REST API

[![Build Status](https://travis-ci.org/transomjs/transom-mongoose-localuser.svg?branch=master)](https://travis-ci.org/transomjs/transom-mongoose-localuser)


## Installation

```bash
$ npm install transom-mongoose-localuser --save
```

## Overview
The transom-mongoose-local-user plugin is the security provider for the TransomJS Api. It maintains a database of the users and groups in the MongoDB database, and it provides the API end points to support the routes of user signup and logging on/off.

The transom-mongoose-local-user plugin also tightly integrates with the [transon-mongoose](https://github.com/transomjs/transom-mongoose) and [transom-server-functions](https://github.com/transomjs/transom-server-functions) plugins for the securing their end-points


## Usage

```javascript
var TransomCore = require('@transomjs/transom-core');

//transonMongoose is required for using transom-mongoose-local-user
var transomLocalUser = require('@transomjs/transom-mongoose-localuser');

const transom = new TransomCore();

var localUserOptions = {};

transom.configure(transomLocalUser, localUserOptions);

var myApi = require('./myApi');

// Initialize them all at once.
var server = transom.initialize(myApi);
```

#### Options
The Api end points the support the workflows for creating and verifying users and resetting passwords can utilize plugins for sending emails and creating (email) content from templates. Defaults are used when the options object does not provider alternates. The values on the options object are the registry key strings that return the corresponding handler.<br/>
Optional configuration values include the named handlers for:
 - emailHandler : (default 'transomSmtp')
 - templateHandler : (default 'transomTemplate')
 - nonceHandler : (default 'transomNonce')

#### Security End-points
The transon-mongoose-locauser plugin will create the following routes on your API:

#### /user/signup
|End Point| Method | Payload | Description                    |
|---------|--------|---------|--------------------------------|
|/user/signup| POST | user object | Creates a new user object. It will send an email to the user to verify the email address|
|/user/verify| POST | The verification token on the query string | Validates the user by means of the token, once completed the user can use the login route|
|/user/login | POST | encoded username and password | The login route uses [basic authentication](https://swagger.io/docs/specification/authentication/basic-authentication/) using the `Authorization` header with the username and password, seperated by a colon, and encoded in base64. It returns a token that must be used as a bearer token in the `Authorization` header, for accessing secured end points in the API. Remember that https must be used for keeping user credentials secure!.  |
| /user/logout | POST | ... | Invalidate the bearer token |
| /user/forgot | POST | eail address | Sends an email, if the address is found in the user database. The email contains a token that must be presented on the reset request |
| /user/reset | POST | ... | provide the new password along with the token that was generated in an email through the `forgot` request. |

