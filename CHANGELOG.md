# @transomjs/transom-mongoose-localuser change log

## 2.0.0
- Added JWT, with cookie support
- Removed 'request' as it is no longer required to build the latest bcrypt.

## 1.4.4
- Added sanitize option to allow scrubbing the User Object loaded during Bearer strategy authentication.

## 1.4.3
- Updated initializeAcl to abstract the setPassword callback, tweaked the AclUser schema to fetch the whole document into req.locals.user.
- **WARNING** If using Oauth (or similar) strategies, be sure to scrub any tokens from the /user/me request with pre-middleware.
- Added 'request' as dev dep to sidestep build errors with latest bcrypt.
- Various code cleanup

## 1.4.2
- Fixed finalize on AclUser schema, to return the full error object on save errors.

## 1.4.1
- Added a social attribute to the AclUser schema, to be used with future social login providers.

## 1.4.0
- Updated dependencies to the latest versions & rebuilt the package-lock.json
- Required no code changes from the prior beta

## 1.4.0-0
- Updated dependencies to the latest versions & rebuilt the package-lock.json
- Updated to the latest mongoose 5.2.*
- Added deploy task to package.json

## earlier
- Working as documented and not previously change-logged.