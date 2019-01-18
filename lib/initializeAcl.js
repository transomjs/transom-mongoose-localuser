'use strict';
const debug = require('debug')('transom:mongoose:localuser');

module.exports = (function AclInitialiser() {
    function setPasswordCallback(err, user) {
        if (err) {
            console.error('Error setting password for default user.', err);
            return;
        }
        user.save(function(err) {
            if (err) {
                if (err.code === 11000) {
                    debug(`Default ${user.display_name} user already exists.`);
                } else {
                    console.error(
                        `Error creating ${user.display_name} user.`,
                        err
                    );
                }
                return;
            }
            debug(`Created a default ${user.display_name} user.`);
        });
    }

    function createDefaultUser(server, options) {
        const mongoose = server.registry.get('mongoose');
        const AclUserModel = mongoose.model('TransomAclUser');

        if (options.administrator === false) {
            debug('Auto-create of a default Administrator user is disabled.');
        } else {
            const adminOptions = options.administrator || {};
            const adminUser = new AclUserModel({
                email: adminOptions.email || 'administrator@localhost',
                username: adminOptions.username || 'administrator',
                display_name: adminOptions.displayName || 'Administrator',
                groups: adminOptions.groups || ['sysadmin'],
                active:
                    adminOptions.active === undefined
                        ? true
                        : adminOptions.active,
                modifiedBy: 'initialize-acl',
                verified_date: new Date()
            });
            adminUser.verify_token =
                'initialized-' + adminUser.generateVerifyHash();
            adminUser.setPassword('password', setPasswordCallback);
        }

        if (options.anonymous === false) {
            debug('Auto-create of a default Anonymous user is disabled.');
        } else {
            const anonOptions = options.anonymous || {};
            const anonUser = new AclUserModel({
                email: anonOptions.email || 'anonymous@localhost',
                username: 'anonymous', // not configurable!
                display_name: anonOptions.displayName || 'Anonymous',
                groups: anonOptions.groups || [],
                active:
                    anonOptions.active === undefined
                        ? true
                        : anonOptions.active,
                modifiedBy: 'initialize-acl',
                verified_date: new Date()
            });
            anonUser.verify_token =
                'initialized-' + anonUser.generateVerifyHash();
            anonUser.setPassword('password', setPasswordCallback);
        }
    }

    return {
        setPasswordCallback,
        createDefaultUser
    };
})();
