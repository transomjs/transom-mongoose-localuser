const debug = require('debug')('transomjs:mongoose:localuser');
const expect = require('chai').expect;
// const sinon = require('sinon');
// const NonceHandler = require('../lib/nonceHandler');
const mongoose = require('mongoose');
const PocketRegistry = require('pocket-registry');
const mongotest = require('./mongotest');
const TransomLocalUser = require('../index');

describe('LocalUserHandler', function (done) {

    const server = {};

    before(function () {

        mongotest.prepareDb('mongodb://localhost/transomlocalusertests', {
            timeout: 10000
        });

        server.registry = new PocketRegistry();
        mongoose.Promise = Promise;
        server.registry.set('mongoose', mongoose);

        server.get = function() {
            server.registry.set(`get|${arguments[0]}`, Array.prototype.slice.call(arguments, 1))
        }
        
        server.post = function() {
            server.registry.set(`post|${arguments[0]}`, Array.prototype.slice.call(arguments, 1))
        }

        const options = {};
        TransomLocalUser.initialize(server, options);
    });

    after(function() {
        mongotest.disconnect();
    });

    
    it('should have tests!', function () {
        const dummyServer = {};
        const dummyOptions = {};
    });

});