const express = require("express");
const router = express.Router();
const database = require("./database");
const path = require("path");
const nconf = require("nconf");
const { accessFrequencyCheck, approveCheck } = require("./security");
const uap = require('ua-parser-js');
const cors = require("cors");
const bodyParser = require("body-parser");

const sessionCheck = require("./security").sessionCheck;
const tokenCheck = require("./security").tokenCheck;
const normalUserCheck = require("./security").normalUserCheck;
const adminCheck = require("./security").adminCheck;
const superAdminCheck = require("./security").superAdminCheck;
const getIP = require("./security").getIP;
const userModifyLinkCheck = require("./security").userModifyLinkCheck;
const checkUserPermissionForLink = require("./security").checkUserPermissionForLink;

const winston = require("winston");
const logger = winston.loggers.get("accessLogger");

let configFile = path.join(path.dirname(__dirname), 'config', 'config.json');

nconf.file({file: configFile});

async function getUserList(req, res, next) {
    try {
        let getListResult = await database.getUserList();
        if (getListResult["status"] == "success") {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuserlist got 200.`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/getuserlist got 200.`);
            }
            res.status(200).json(getListResult);
        } else {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuserlist got 403 (${getListResult["reason"]})`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/getuserlist got 403 (${getListResult["reason"]})`);
            }
            res.status(403).json(getListResult);
        }
        return;
    } catch (error) {
        if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuserlist got 500.`);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/getuserlist got 500.`);
        }
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
}

async function getUser(req, res, next) {
    try {
        if (!req.query.email) {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuser got 403 (Too few arguments)`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/getuser got 403 (Too few arguments)`);
            }
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }
        let queryResult = await database.getUser(req.query.email);
        if (queryResult["status"] == "success") {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuser got 200.`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/getuser got 200.`);
            }
            res.status(200).json(queryResult);
            return;
        } else {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuser got 404 (${queryResult.reason})`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/getuser got 404 (${queryResult.reason})`);
            }
            res.status(404).json(queryResult);
            return;
        }
    } catch (error) {
        if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetuser got 500.`);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/getuser got 500.`);
        }
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
}

async function addUser(req, res, next) {
    try {
        if (!(req.query.email && req.query.role && [0, 1, 99].includes(parseInt(req.query.role)))) {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/useradduser got 403 (Too few arguments or Invalid input)`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/adduser got 403 (Too few arguments or Invalid input)`);
            }
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments or Invalid input"
            });
            return;
        }
        let addResult = await database.addUser(req.query.email, (req.query.comment ? req.query.comment : ""), parseInt(req.query.role));
        if (addResult["status"] == "success") {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/useradduser got 200 (user ${req.query.email}, comment ${req.query.comment}, role ${req.query.role})`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/adduser got 200 added a user ${req.query.email}, comment ${req.query.comment}, role ${req.query.role}`);
            }
            res.status(200).json(addResult);
        } else {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/useradduser got 403 (${addResult.reason})`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/adduser got 403 (${addResult.reason})`);
            }
            res.status(403).json(addResult);
        }
        return;
    } catch (error) {
        if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/useradduser got 500.`);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/adduser got 500.`);
        }
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
}

async function removeUser(req, res, next) {
    try {
        if (!req.query.email) {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userremoveuser got 403 (Too few arguments or Invalid input)`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/removeuser got 403 (Too few arguments)`);
            }
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }

        let queryResult = await database.getUser(req.query.email);
        
        if (queryResult["status"] == "success") {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                if (req.session.account.username == req.query.email) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userremoveuser got 403 (attempting to remove itself)`);
                    res.status(403).json({
                        status: "failed",
                        reason: "You cannot remove yourself"
                    });
                    return;
                }
                if ((res.locals.userRole !== undefined) && (queryResult.results[0]["ROLE"] < res.locals.userRole)) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userremoveuser got 403 (permission level)`);
                    res.status(403).json({
                        status: "failed",
                        reason: "You cannot remove a user that has or higher permission"
                    });
                    return;
                }
            }

            let deleteResult = await database.removeUser(req.query.email);
            if (deleteResult["status"] == "success") {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userremoveuser got 200 (user: ${req.query.email})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/removeuser got 200 (user: ${req.query.email})`);
                }
                res.status(200).json(deleteResult);
            } else {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userremoveuser got 403 (${deleteResult.reason})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/removeuser got 403 (${deleteResult.reason})`);
                }
                res.status(403).json(deleteResult);
            }
            return;
        } else {
            if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userremoveuser got 403 (${deleteResult.reason})`);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/removeuser got 403 (${deleteResult.reason})`);
            }
            res.status(403).json(queryResult);
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
}

async function getDetail(req, res, next) {
    if (!(req.query.id || req.query.source || req.query.target)) {
        if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 403 (Too few arguments)`);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 403 (Too few arguments)`);
        }
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }

    let userInfo = '';
    if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
        // logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/getDetail (ID: ${req.query.id !== undefined ? req.query.id : "None"}), Source: ${req.query.source !== undefined ? req.query.source : "None"}, Target: ${req.query.target !== undefined ? req.query.target : "None"})`);
        if (res.locals.userRole > 1) {
            userInfo = req.session.account.username;
        }
    }

    try {
        if (req.query.id) {
            // Check ID first
            let getIDResult = await database.getID(req.query.id, userInfo);
            if (getIDResult["status"] == "success") {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 200 (ID: ${req.query.id})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 200 (ID: ${req.query.id})`);
                }
                res.status(200).json(getIDResult);
            } else {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 403 (${getIDResult.reason})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 403 (${getIDResult.reason})`);
                }
                res.status(403).json(getIDResult);
            }
            return;
        }

        if (req.query.source) {
            // Check source then
            let getSourceResult = await database.getLink(req.query.source, userInfo);
            if (getSourceResult["status"] == "success") {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 200 (Source: ${req.query.source})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 200 (ID: ${req.query.source})`);
                }
                res.status(200).json(getSourceResult);
            } else {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 403 (${getSourceResult.reason})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 403 (${getSourceResult.reason})`);
                }
                res.status(403).json(getSourceResult);
            }
            return;
        }
        
        if (req.query.target) {
            // Check target last
            let getTargetResult = await database.getTarget(req.query.target, userInfo);
            if (getTargetResult["status"] == "success") {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 200 (Target: ${req.query.target})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 200 (Target: ${req.query.target})`);
                }
                res.status(200).json(getTargetResult);
            } else {
                if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 403 (${getTargetResult.reason})`);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 403 (${getTargetResult.reason})`);
                }
                res.status(403).json(getTargetResult);
            }
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        if (!((res.locals.sessionOrTokenCheckPassed !== undefined && res.locals.sessionOrTokenCheckPassed == true))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/usergetdetail got 500.`);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/getdetail got 500.`);
        }
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
}

router.use(bodyParser.json());       // to support JSON-encoded bodies
router.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
}));

router.use(cors({
    credentials: true,
    origin: "http://localhost:9000",
    exposedHeaders: ["set-cookie"], 
}));

router.get("/api/create", getIP, sessionCheck, async (req, res) => {
    if (!(req.query.name && req.query.target)) {
        logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (Too few arguments)`);
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }
    try {
        if (req.query.expireat && (parseInt(req.query.expireat) === NaN || parseInt(req.query.expireat) * 1000 < Date.now())) {
            logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (Invalid expire time: ${req.query.expireat})`);
            res.status(403).json({
                status: "failed",
                reason: "Invalid expire time"
            });
            return;
        } else {
            if (!req.query.expireat) {
                if (req.query.expireafter && parseInt(req.query.expireafter) !== NaN) {
                    let createResult = await database.addLink(req.query.name, req.query.target, Date.now() + parseInt(req.query.expireafter));
                    if (createResult["status"] == "success") {
                        logger.info(`User token from ${res.locals.ip} requested /api/create got 200 (name: ${req.query.name}, target: ${req.query.target}, expireafter: ${req.query.expireafter}, source: ${createResult["source"]})`);
                        res.status(200).json(createResult);
                    } else {
                        logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (${createResult["reason"]})`);
                        res.status(403).json(createResult);
                    }
                    return;
                } else {
                    let createResult = await database.addLink(req.query.name, req.query.target);
                    if (createResult["status"] == "success") {
                        logger.info(`User token from ${res.locals.ip} requested /api/create got 200 (name: ${req.query.name}, target: ${req.query.target}, source: ${createResult["source"]})`);
                        res.status(200).json(createResult);
                    } else {
                        logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (${createResult["reason"]})`);
                        res.status(403).json(createResult);
                    }
                    return;
                }
            } else {
                let createResult = await database.addLink(req.query.name, req.query.target, parseInt(req.query.expireat));
                if (createResult["status"] == "success") {
                    logger.info(`User token from ${res.locals.ip} requested /api/create got 200 (name: ${req.query.name}, target: ${req.query.target}, expireat: ${req.query.expireat}, source: ${createResult["source"]})`);
                    res.status(200).json(createResult);
                } else {
                    logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (${createResult["reason"]})`);
                    res.status(403).json(createResult);
                }
                return;
            }
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User token from ${res.locals.ip} requested /api/create got 500.`);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/remove", getIP, sessionCheck, async (req, res) => {
    if (!(req.query.id || req.query.source)) {
        logger.info(`User token from ${res.locals.ip} requested /api/remove got 403 (Too few arguments)`);
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }

    try {
        if (req.query.id) {
            // Check ID first
            let deleteIDResult = await database.removeLinkFromID(req.query.id);
            if (deleteIDResult["status"] == "success") {
                logger.info(`User token from ${res.locals.ip} requested /api/remove got 200 (ID: ${req.query.id})`);
                res.status(200).json(deleteIDResult);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (${deleteIDResult["reason"]})`);
                res.status(403).json(deleteIDResult);
            }
            return;
        }

        if (req.query.source) {
            // Check source then
            let deleteSourceResult = await database.removeLinkFromSourceLink(req.query.source);
            if (deleteSourceResult["status"] == "success") {
                logger.info(`User token from ${res.locals.ip} requested /api/remove got 200 (source: ${req.query.source})`);
                res.status(200).json(deleteSourceResult);
            } else {
                logger.info(`User token from ${res.locals.ip} requested /api/create got 403 (${deleteSourceResult["reason"]})`);
                res.status(403).json(deleteSourceResult);
            }
            return;
        }
    } catch (error) {
        logger.info(`User token from ${res.locals.ip} requested /api/remove got 500.`);
        logger.error(error.stack);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.post("/api/batchremove", getIP, sessionCheck, async (req, res) => {
    if (!req.body.ids || !(req.body.ids instanceof Array)) {
        logger.info(`User token from ${res.locals.ip} requested /api/batchremove got 403 (Too few arguments)`);
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }
    try {
        for (const item of req.body.ids) {
            await database.removeLinkFromID(item);
        }
        logger.info(`User token from ${res.locals.ip} requested /api/batchremove got 200 (links: ${req.body.ids})`);
        res.status(200).json({
            status: "success",
            reason: ""
        });
        return;
    } catch (error) {
        logger.info(`User token from ${res.locals.ip} requested /api/batchremove got 500.`);
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/getdetail", getIP, sessionCheck, getDetail);

router.get("/api/getlist", getIP, sessionCheck, async (req, res) => {
    try {
        let getListResult = await database.getList();
        if (getListResult["status"] == "success") {
            logger.info(`User token from ${res.locals.ip} requested /api/getlist got 200.`);
            res.status(200).json(getListResult);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/getlist got 403 (${getListResult.reason})`);
            res.status(403).json(getListResult);
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User token from ${res.locals.ip} requested /api/getlist got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/resetcount", getIP, sessionCheck, async (req, res) => {
    if (!(req.query.id)) {
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }
    try {
        let getIDResult = await database.getID(req.query.id);
        if (getIDResult["status"] == "success") {
            await database.resetClickCount(getIDResult["results"][0]["id"]);
            logger.info(`User token from ${res.locals.ip} requested /api/resetcount got 200.`);
            res.status(200).json(getIDResult);
        } else {
            logger.info(`User token from ${res.locals.ip} requested /api/resetcount got 404.`);
            res.status(404).json({
                status: "failed",
                reason: "Not found"
            });
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User token from ${res.locals.ip} requested /api/resetcount got 500.`);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/getme", sessionCheck, async (req, res) => {
    try {
        if (!req.session) {
            res.status(401).json({
                status: "failed",
                reason: "Unauthorized"
            });
            return;
        } else {
            let returnBody = {
                status: "success",
                user: "",
                role: undefined
            }
            if (req.session.user == "root") {
                returnBody["user"] = "root";
            }

            res.status(200).json(returnBody);
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.post("/api/adminlogin", getIP, tokenCheck, async (req, res) => {
    try {
        await new Promise((resolve, reject) => {
            req.session.regenerate((err) => {
                if (err) {
                    reject(err);
                }

                req.session.user = "root";

                logger.info("Root user logged in from " + res.locals.ip);

                req.session.save((err) => {
                    if (err) {
                        reject(err);
                    }
                    resolve(undefined);
                });
            });
        });
        res.status(200).json({
            status: "succes",
            reason: ""
        });
        return;
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/adduser", getIP, sessionCheck, addUser);

router.get("/api/getuserlist", getIP, sessionCheck, getUserList);

router.get("/api/getuser", getIP, sessionCheck, getUser);

router.get("/api/removeuser", getIP, sessionCheck, removeUser);

router.post("/api/batchremoveuser", getIP, sessionCheck, async (req, res) => {
    try {
        if (! (req.body && req.body.users && (req.body.users instanceof Array))) {
            logger.info(`User token from ${res.locals.ip} requested /api/batchremoveuser got 403 (users: ${req.body.users !== undefined ? req.body.users : "None"})`);
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }
        for (const item of req.body.users) {
            await database.removeUser(item);
        }
        logger.info(`User token from ${res.locals.ip} requested /api/batchremoveuser got 200 (users: ${req.body.users !== undefined ? req.body.users : "None"})`);
        res.status(200).json({
            status: "success",
            reason: "",
            users: req.body.users
        });
        return;
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User token from ${res.locals.ip} requested /api/batchremoveuser got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.use("/api/logout", getIP, sessionCheck, async (req, res, next) => {
    if (req.headers.authorization) {
        logger.info(`User token from ${res.locals.ip} requested /api/logout got 423.`);
        res.status(423).json({
            status: "failed",
            reason: "Unexcepted ending"
        });
        return;
    } else {
        next();
    }
}, async (req, res) => {
    try {
        await new Promise((resolve, reject) => {
            req.session.destroy((err) => {
                if (err) {
                    reject(err);
                }
                resolve(undefined);
            });
        });
        logger.info(`User token from ${res.locals.ip} requested /api/logout got 200.`);
        res.status(200).json({
            status: "success",
            reason: "",
            goodbye: true
        });
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User token from ${res.locals.ip} requested /api/logout got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

// User link operations

router.get("/api/usergetlinklist", getIP, approveCheck, normalUserCheck, async (req, res) => {
    try {
        if (res.locals.userRole <= 1) {
            // Admin
            let getListResult = await database.getList();
            if (getListResult.status == "success") {
                res.status(200).json(getListResult);
            } else {
                res.status(500).json(getListResult);
            }
            return;
        } else {
            // Normal user
            let getListResult = await database.getList(req.session.account.username);
            if (getListResult.status == "success") {
                res.status(200).json(getListResult);
            } else {
                res.status(500).json(getListResult);
            }
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/userlinkcreate", getIP, approveCheck, normalUserCheck, async (req, res) => {
    if (!(req.query.name && req.query.target)) {
        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 403 (Too few arguments)`);
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }

    try {
        const username = req.session.account.username;
        if (req.query.expireat && (parseInt(req.query.expireat) === NaN || parseInt(req.query.expireat) * 1000 < Date.now())) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 403 (Invalid expire time)`);
            res.status(403).json({
                status: "failed",
                reason: "Invalid expire time"
            });
            return;
        } else {
            if (!req.query.expireat) {
                if (req.query.expireafter && parseInt(req.query.expireafter) !== NaN) {
                    let createResult = await database.addLink(req.query.name, req.query.target, Date.now() + parseInt(req.query.expireafter), username);
                    if (createResult["status"] == "success") {
                        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 200 (name: ${req.query.name}, target: ${req.query.target}, expireafter: ${req.query.expireafter})`);
                        res.status(200).json(createResult);
                    } else {
                        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 403 (${createResult.reason})`);
                        res.status(403).json(createResult);
                    }
                    return;
                } else {
                    let createResult = await database.addLink(req.query.name, req.query.target, -1, username);
                    if (createResult["status"] == "success") {
                        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 200 (name: ${req.query.name}, target: ${req.query.target})`);
                        res.status(200).json(createResult);
                    } else {
                        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 403 (${createResult.reason})`);
                        res.status(403).json(createResult);
                    }
                    return;
                }
            } else {
                let createResult = await database.addLink(req.query.name, req.query.target, parseInt(req.query.expireat));
                if (createResult["status"] == "success") {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 200 (name: ${req.query.name}, target: ${req.query.target}, expireat: ${req.query.expireat})`);
                        res.status(200).json(createResult);
                } else {
                    logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 403 (${createResult.reason})`);
                    res.status(403).json(createResult);
                }
                return;
            }
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkcreate got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/userlinkmodify", getIP, approveCheck, normalUserCheck, userModifyLinkCheck, async (req, res) => {
    try {
        if (!(req.query.id && (req.query.name || (req.query.expireat && parseInt(req.query.expireat) !== NaN)))) {
            if (!req.query.id) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkmodify got 403 (Too few arguments)`);
                res.status(403).json({
                    status: "failed",
                    reason: "Too few arguments"
                });
                return;
            }
        }

        if (parseInt(req.query.expireat) < -1) {
            if (!req.query.id) {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkmodify got 403 (Invalid expire time)`);
                res.status(403).json({
                    status: "failed",
                    reason: "Invalid expire time"
                });
                return;
            }
        }

        let modifyName = undefined;
        let modifyExpireAt = undefined;

        if (req.query.name !== undefined) {
            modifyName = req.query.name;
        }

        if (req.query.expireat !== undefined) {
            modifyExpireAt = parseInt(req.query.expireat);
        }

        let modifyResult = await database.modifyLink(req.query.id, modifyName, modifyExpireAt);
        if (modifyResult.status == "success") {
            res.status(200).json(modifyResult);
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} modified link ${req.query.id} with ${req.query.name !== undefined ? ("name: " + req.query.name) : ""} ${req.query.expireat !== undefined ? ("expireat: " + req.query.expireat) : ""}`);
        } else {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkmodify got 500.`);
            res.status(500).json(modifyResult);
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkmodify got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/userlinkremove", getIP, approveCheck, normalUserCheck, userModifyLinkCheck, async (req, res) => {
    try {
        if (!req.query.id) {
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }
        
        if (req.query.id) {
            // Check ID first
            let deleteIDResult = await database.removeLinkFromID(req.query.id);
            if (deleteIDResult["status"] == "success") {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkremove got 200 (id: ${req.query.id})`);
                res.status(200).json(deleteIDResult);
            } else {
                logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkremove got 403 (id: ${deleteIDResult.reason})`);
                res.status(403).json(deleteIDResult);
            }
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkremove got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/usercheckpermission", getIP, approveCheck, normalUserCheck, async (req, res) => {
    try {
        if (!(req.query.id)) {
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }

        let checkPermResult = await checkUserPermissionForLink(req.query.id, req.session.account.username);
        if (checkPermResult[0] == 200) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} passed permission check for link ${req.query.id}.`);
            res.status(200).json({
                status: "success",
                reason: ""
            });
            return;
        } else {
            logger.warn(`User ${req.session.account.username} from ${res.locals.ip} failed permission check for link ${req.query.id}, reason is ${checkPermResult[1]["reason"]}`);
            res.status(403).json({
                status: "failed",
                reason: "Permission Denied"
            });
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.post("/api/userlinkbatchremove", getIP, approveCheck, normalUserCheck, async (req, res) => {
    try {
        if (!(req.body !== undefined && req.body.ids !== undefined && (req.body.ids instanceof Array))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkbatchremove got 403 (ids: ${req.body.ids !== undefined ? req.body.ids : 'None'})`);
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }

        let permissionPassed = true;
        for (const item of req.body.ids) {
            if ((await checkUserPermissionForLink(item, req.session.account.username))[0] != 200) {
                permissionPassed = false;
            }
        }

        if (!permissionPassed) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkbatchremove got 403 (Permission denied, ids: ${req.body.ids !== undefined ? req.body.ids : 'None'})`);
            res.status(403).json({
                status: "failed",
                reason: "You don't have the permission to delete one or more links."
            });
            return;
        } else {

            for (const item of req.body.ids) {
                await database.removeLinkFromID(item);
            }

            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkbatchremove got 200 (ids: ${req.body.ids})`);

            res.status(200).json({
                status: "success",
                reason: ""
            });
            return;
        }
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/userlinkbatchremove got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/usergetuserlist", getIP, approveCheck, superAdminCheck, getUserList);

router.get("/api/usergetuser", getIP, approveCheck, superAdminCheck, getUser);

router.get("/api/useradduser", getIP, approveCheck, superAdminCheck, addUser);

router.get("/api/userremoveuser", getIP, approveCheck, superAdminCheck, removeUser);

router.get("/api/usergetdetail", getIP, approveCheck, normalUserCheck, getDetail);

router.post("/api/userbatchremoveuser", getIP, approveCheck, superAdminCheck, async (req, res) => {
    try {
        if (!(req.body !== undefined && req.body.emails !== undefined && (req.body.emails instanceof Array))) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/batchremoveuser got 403 (users: ${req.body.users !== undefined ? req.body.users : "None"})`);
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }

        let permissionPassed = true;
        
        for (const item of req.body.emails) {
            let getUserResult = await database.getUser(item);
            if (req.session.account.username == item) {
                permissionPassed = false;
                break;
            }

            if (getUserResult.status != "success") {
                permissionPassed = false;
                break;
            }
            if (getUserResult.status == "success" && (getUserResult.results[0]["ROLE"] <= res.locals.userRole && getUserResult.results[0]["ROLE"] != 0)) {
                permissionPassed = false;
                break;
            }
        }

        if (!permissionPassed) {
            logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/batchremoveuser got 403 (Permission denied, users: ${req.body.users !== undefined ? req.body.users : "None"})`);
            res.status(403).json({
                status: "failed",
                reason: "Permission denied for modifing one or more user"
            });
            return;
        }
        

        for (const item of req.body.emails) {
            await database.removeUser(item);
        }

        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/batchremoveuser got 200 (users: ${req.body.users !== undefined ? req.body.users : "None"})`);
            
        res.status(200).json({
            status: "success",
            reason: ""
        });
        return;
    } catch (error) {
        logger.error(error.stack);
        logger.info(`User ${req.session.account.username} from ${res.locals.ip} requested /api/batchremoveuser got 500.`);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
})

router.use("/admin", express.static("admin-panel"));

router.use("/user", express.static("webui-panel"));

router.get("/:link", accessFrequencyCheck, async (req, res) => {
    try {
        let ua = uap(req.headers["user-agent"]); // Get user agent to check if the request is come from browser

        let getLinkResult = await database.getLink(req.params.link);
        if (getLinkResult["status"] == "success") {
            // res.status(200).json({
            //     status: "success",
            //     reason: "",
            //     link: getLinkResult["results"][0]['TARGET_LINK']
            // });'
            logger.info("Client from " + res.locals.ip + " accessed /" + req.params.link + " (" + getLinkResult["results"][0]["id"] + ")");
            await database.writeLog(getLinkResult["results"][0]["id"], req.params.link, res.locals.ip);
            await database.addClickCount(getLinkResult["results"][0]["id"]);
            res.redirect(302, getLinkResult["results"][0]['TARGET_LINK']);
            return;
        } else {
            logger.info("Client from " + res.locals.ip + " accessed /" + req.params.link + " (not found)");
            await database.writeLog("notfound", req.params.link, res.locals.ip);
            if (!ua.browser.name) {
                // Undefined browser
                res.status(404).json({
                    status: "failed",
                    reason: "Not found"
                });
                return;
            } else {
                res.render("notfound");
                return;
            }
        }
    } catch (error) {
        logger.error(error.stack);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

module.exports.router = router;