'use strict';
const debug = require('debug')('transom:mongoose:localuser:LocalUserClient');

/**
 * A server-side client for managing local user resources.
 * 
 */
module.exports = function LocalUserClient() {

    function setGroups(server, distinctGroups) {
        const mongoose = server.registry.get('mongoose');
        const AclGroupModel = mongoose.model("TransomAclGroup");

        let groups;
        if (Array.isArray(distinctGroups)) {
            groups = distinctGroups;
        } else {
            groups = Object.keys(distinctGroups);
        }

        // Attempt to insert Groups, existing ones will fail on a unique constraint.
        groups.map(function (group) {
            const newGroup = new AclGroupModel({
                code: group,
                name: group,
                active: true
            });
            newGroup.modifiedBy = 'initialize-acl';
            newGroup.save().then((item) => {
                debug(`Created AclGroup '${item.name}'.`);
            }).catch((err) => {
                if (err.code !== 11000) {
                    debug(`Error creating AclGroup '${group}'.`, err);
                }
            });
        });
    };

    function findOrCreateUser(server, user){
        return new Promise(function(resolve, reject) {
            const mongoose = server.registry.get('mongoose');
            const AclUserModel = mongoose.model("TransomAclUser");
            AclUserModel.find({"email":user.email})
            .then((users) => {
                if (users.length > 0) {
                    // Pick the first one, what else can we do?
                    const usr = users[0];
                    resolve(usr);
                } else {
                    // Create a new user...
                    const usr = new AclUserModel(user);
                    usr.modifiedBy = user.modifiedBy;
                    usr.save().then((usr) => {
                        resolve(usr);
                    })
                    .catch((err) => {
                        reject(err);
                    });
                }
            })
            .catch((err) => {
                reject(err);
            })
        });
    };

    return {
        setGroups,
        findOrCreateUser
    }
}();
