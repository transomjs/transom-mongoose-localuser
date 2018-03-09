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
            newGroup.save().then(function (item) {
                debug(`Created AclGroup '${item.name}'.`);
            }).catch(function (err) {
                if (err.code !== 11000) {
                    debug(`Error creating AclGroup '${group}'.`, err);
                }
            });
        });
    };

    return {
        setGroups
    }
}();