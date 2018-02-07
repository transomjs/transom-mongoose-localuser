'use strict';
const assert = require('assert');
// const debug = require('debug')('transom:mongoose:localuser:initializeAcl');

module.exports = function LocalUserClient() {

    function setGroups(server, distinctGroups) {
        const mongoose = server.registry.get('mongoose');
        const AclGroupModel = mongoose.model("TransomAclGroup");
        const dbMongoose = server.registry.get('transom-config.definition.mongoose', null);

        // Attempt to insert Groups, existing ones will fail on a unique constraint.
        Object.keys(distinctGroups).map(function(group) {
            const newGroup = new AclGroupModel({
                code: group,
                name: group,
                active: true
            });
            newGroup.modifiedBy = 'initialize-acl';
            newGroup.save().catch(function(err) {
                if (err.code !== 11000) {
                    console.error(`Error creating ${group} Group.`, err);
                }
            });
        });
    };

    return {
        setGroups
    }

}();