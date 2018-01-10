/* jshint node:true */
/* jshint esversion:6 */
'use strict';

// process.env.NODE_ENV = 'test';

var chai = require('chai');
var chaiHttp = require('chai-http');
var request = require('supertest');
var app = require('../server/server');
var should = chai.should();
var utils = require('./LoginUtils');

var accessToken = null;


var testraw = {
    "principalInvestigator": "string",
    "endTime": "2018-01-09T14:39:47.477Z",
    "creationLocation": "string",
    "dataFormat": "string",
    "scientificMetadata": {},
    "pid": "string",
    "owner": "string",
    "ownerEmail": "string",
    "orcidOfOwner": "string",
    "contactEmail": "string",
    "sourceFolder": "string",
    "size": 0,
    "packedSize": 0,
    "creationTime": "2018-01-09T14:39:47.477Z",
    "type": "string",
    "validationStatus": "string",
    "keywords": [
        "string"
    ],
    "description": "string",
    "userTargetLocation": "string",
    "classification": "string",
    "license": "string",
    "version": "string",
    "doi": "string",
    "isPublished": true,
    "ownerGroup": "string",
    "accessGroups": [
        "string"
    ],
    "createdAt": "2018-01-09T14:39:47.477Z",
    "updatedAt": "2018-01-09T14:39:47.477Z",
    "sampleId": "string",
    "proposalId": "string"
};

describe('RawDatasets', () => {
    beforeEach((done) => {
        utils.getToken(app, {'username': 'ingestor', 'password': 'aman'},
            (tokenVal) => {
                accessToken = tokenVal;
                done();
            });
    });
    describe('POST /api/v2/RawDatasets', function () {
        it('adds a new dataset', function (done) {
            request(app)
                .post('/api/v2/RawDatasets?access_token=' + accessToken)
                .send(testraw)
                .set('Accept', 'application/json')
                .expect(200)
                .expect('Content-Type', /json/)
                .end(function (err, res) {
                    if (err)
                        return done(err);
                    res.body.should.have.property('user').and.be.instanceof(Object);
                    done();
                });
        });
    });
    describe('Get All RawDatasets', function () {
        it('fails with incorrect credentials', function (done) {
            request(app)
                .get('/api/v2/RawDatasets?filter=%7B%22limit%22%3A10%7D&access_token=' + accessToken)
                .set('Accept', 'application/json')
                .expect(200)
                .expect('Content-Type', /json/)
                .end((err, res) => {
                    if (err)
                        return done(err);
                    res.body.should.be.instanceof(Array);
                    done();
                });
        });
    });
});
