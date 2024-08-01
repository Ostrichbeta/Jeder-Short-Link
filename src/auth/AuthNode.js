// Copied and modified from https://learn.microsoft.com/en-us/entra/identity-platform/tutorial-v2-nodejs-webapp-msal

var express = require('express');
const bodyParser = require("body-parser");

const authProvider = require('./AuthProvider');
const { REDIRECT_URI, POST_LOGOUT_REDIRECT_URI, HOSTNAME } = require('./AuthConfig');
const cors = require("cors");

const winston = require('winston');
const logger = winston.loggers.get("authLogger");

const router = express.Router();

router.use(bodyParser.json());       // to support JSON-encoded bodies
router.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
}));

router.use(cors({
    credentials: true,
    origin: "http://localhost:9000",
    exposedHeaders: ["set-cookie"], 
}));

router.get('/signin', async (req, res, next) => {
    try {
        await new Promise((resolve, reject) => {
            req.session.regenerate((err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            })
        });
        next();
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal Server Error"
        });
        return;
    }
}, authProvider.login({
    scopes: [],
    redirectUri: HOSTNAME + REDIRECT_URI,
    successRedirect: HOSTNAME + '/auth/acquireToken'
}));

router.get('/acquireToken', authProvider.acquireToken({
    scopes: [''],
    redirectUri: HOSTNAME + REDIRECT_URI,
    successRedirect: HOSTNAME + '/user/#/login'
}));

router.post('/redirect', authProvider.handleRedirect(), async (err, req, res, next) => {
    logger.error(err.stack);
    res.redirect(HOSTNAME + '/user/#/login');
});

router.get('/signout', authProvider.logout({
    postLogoutRedirectUri: HOSTNAME + POST_LOGOUT_REDIRECT_URI
}));

module.exports.router = router;