const debug = require('debug')('transomjs:mongoose:localuser');
// const expect = require('chai').expect;
// const sinon = require('sinon');
// const NonceHandler = require('../lib/nonceHandler');
const mongoose = require('mongoose');
const PocketRegistry = require('pocket-registry');
const mongotest = require('./mongotest');
const TransomLocalUser = require('../index');

describe('LocalUserHandler', function (done) {

    const server = {};
    let expect;

    before(function () {

        mongotest.prepareDb('mongodb://localhost/transomlocalusertests', {
            timeout: 10000
        });

        server.registry = new PocketRegistry();
        mongoose.Promise = Promise;
        server.registry.set('mongoose', mongoose);
        server.registry.set('transom-config.definition.uri.prefix', '/api/v1');
        
        server.get = function() {
            server.registry.set(`get|${arguments[0]}`, Array.prototype.slice.call(arguments, 1))
        }
        
        server.post = function() {
            server.registry.set(`post|${arguments[0]}`, Array.prototype.slice.call(arguments, 1))
        }

        const options = {};
        TransomLocalUser.initialize(server, options);

        // Use a dynamic import for the chai ES module!
        return import("chai").then((chai) => (expect = chai.expect));
    });

    after(function() {
        mongotest.disconnect();
    });

    
    it('should have tests!', function () {
        const dummyServer = {};
        const dummyOptions = {};
    });

});