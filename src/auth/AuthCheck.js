/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

var express = require('express');
var router = express.Router();

var fetch = require('./AuthFetch');

var { GRAPH_ME_ENDPOINT } = require('./AuthConfig');
const winston = require('winston');
const logger = winston.loggers.get("authLogger");
const cors = require("cors");
const database = require("../database");

// custom middleware to check auth state
function isAuthenticated(req, res, next) {
    if (!req.session.isAuthenticated) {
        res.status(401).json({
            status: "failed",
            reason: "Unauthorized"
        });
        return;
    }

    next();
};

router.use(cors({
    credentials: true,
    origin: "http://localhost:9000",
    exposedHeaders: ["set-cookie"],
}));

router.get('/id',
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        res.status(200).json({ idTokenClaims: req.session.account.idTokenClaims });
    }
);

router.get('/profile',
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        try {
            res.status(200).json(
                {
                    status: "success",
                    reason: "",
                    profile: {
                        name: req.session.account.name,
                        username: req.session.account.username
                    }
                }
            );
            return;
        } catch (error) {
            logger.error(error.stack);
            res.status(403).json({
                status: "failed",
                reason: "Failed",
                error: error.stack
            });
            return;
        }
    }
);

router.get('/checkuser',
    isAuthenticated,
    async (req, res) => {
        try {
            let getUserResult = await database.getUser(req.session.account.username);
            if (getUserResult.status == "success") {
                res.status(200).json(getUserResult);
            } else {
                res.status(404).json(getUserResult);
            }
        } catch (error) {
            logger.error(error.stack);
            res.status(403).json({
                status: "failed",
                reason: "Failed",
                error: error.stack
            });
            return;
        }
    }
)

module.exports.router = router;