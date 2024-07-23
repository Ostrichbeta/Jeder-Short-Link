const express = require("express");
const router = express.Router();
const tokenCheck = require("./security").tokenCheck;
const sessionCheck = require("./security").sessionCheck;
const database = require("./database");
const path = require("path");
const nconf = require("nconf");
const { accessFrequencyCheck } = require("./security");
const uap = require('ua-parser-js');
const cors = require("cors");
const bodyParser = require("body-parser");

const winston = require("winston");
const logger = winston.loggers.get("accessLogger");

let configFile = path.join(path.dirname(__dirname), 'config', 'config.json');

nconf.file({file: configFile});

router.use(bodyParser.json());       // to support JSON-encoded bodies
router.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
}));

router.use(cors({
    credentials: true,
    origin: "http://localhost:9000",
    exposedHeaders: ["set-cookie"], 
}));

router.get("/api/create", sessionCheck, async (req, res) => {
    if (!(req.query.name && req.query.target)) {
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }
    try {
        if (req.query.expireat && (parseInt(req.query.expireat) === NaN || parseInt(req.query.expireat) * 1000 < Date.now())) {
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
                        res.status(200).json(createResult);
                    } else {
                        res.status(403).json(createResult);
                    }
                    return;
                } else {
                    let createResult = await database.addLink(req.query.name, req.query.target);
                    if (createResult["status"] == "success") {
                        res.status(200).json(createResult);
                    } else {
                        res.status(403).json(createResult);
                    }
                    return;
                }
            } else {
                let createResult = await database.addLink(req.query.name, req.query.target, parseInt(req.query.expireat));
                if (createResult["status"] == "success") {
                    res.status(200).json(createResult);
                } else {
                    res.status(403).json(createResult);
                }
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

router.get("/api/remove", sessionCheck, async (req, res) => {
    if (!(req.query.id || req.query.source)) {
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
                res.status(200).json(deleteIDResult);
            } else {
                res.status(403).json(deleteIDResult);
            }
            return;
        }

        if (req.query.source) {
            // Check source then
            let deleteSourceResult = await database.removeLinkFromSourceLink(req.query.source);
            if (deleteSourceResult["status"] == "success") {
                res.status(200).json(deleteSourceResult);
            } else {
                res.status(403).json(deleteSourceResult);
            }
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

router.post("/api/batchremove", sessionCheck, async (req, res) => {
    if (!req.body.ids || !(req.body.ids instanceof Array)) {
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
        res.status(200).json({
            status: "success",
            reason: ""
        });
        return;
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/getdetail", sessionCheck, async (req, res) => {
    if (!(req.query.id || req.query.source || req.query.target)) {
        res.status(403).json({
            status: "failed",
            reason: "Too few arguments"
        });
        return;
    }

    try {
        if (req.query.id) {
            // Check ID first
            let getIDResult = await database.getID(req.query.id);
            if (getIDResult["status"] == "success") {
                res.status(200).json(getIDResult);
            } else {
                res.status(403).json(getIDResult);
            }
            return;
        }

        if (req.query.source) {
            // Check source then
            let getSourceResult = await database.getLink(req.query.source);
            if (getSourceResult["status"] == "success") {
                res.status(200).json(getSourceResult);
            } else {
                res.status(403).json(getSourceResult);
            }
            return;
        }
        
        if (req.query.target) {
            // Check target last
            let getSourceResult = await database.getTarget(req.query.target);
            if (getSourceResult["status"] == "success") {
                res.status(200).json(getSourceResult);
            } else {
                res.status(403).json(getSourceResult);
            }
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

router.get("/api/getlist", sessionCheck, async (req, res) => {
    try {
        let getListResult = await database.getList();
        if (getListResult["status"] == "success") {
            res.status(200).json(getListResult);
        } else {
            res.status(403).json(getListResult);
        }
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/resetcount", sessionCheck, async (req, res) => {
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
            res.status(200).json(getIDResult);
        } else {
            res.status(404).json({
                status: "failed",
                reason: "Not found"
            });
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

router.post("/api/adminlogin", tokenCheck, async (req, res) => {
    try {
        await new Promise((resolve, reject) => {
            req.session.regenerate((err) => {
                if (err) {
                    reject(err);
                }

                req.session.user = "root";

                logger.info("Root user logged in");

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

router.get("/api/adduser", sessionCheck, async (req, res) => {
    try {
        if (!(req.query.email && req.query.role && [0, 1, 99].includes(parseInt(req.query.role)))) {
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments or Invalid input"
            });
            return;
        }
        let addResult = await database.addUser(req.query.email, (req.query.comment ? req.query.comment : ""), parseInt(req.query.role));
        if (addResult["status"] == "success") {
            res.status(200).json(addResult);
        } else {
            res.status(403).json(addResult);
        }
        return;
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/getuserlist", sessionCheck, async (req, res) => {
    try {
        let getListResult = await database.getUserList();
        if (getListResult["status"] == "success") {
            res.status(200).json(getListResult);
        } else {
            res.status(403).json(getListResult);
        }
        return;
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/getuser", sessionCheck, async (req, res) => {
    try {
        if (!req.query.email) {
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }
        let queryResult = await database.getUser(req.query.email);
        if (queryResult["status"] == "success") {
            res.status(200).json(queryResult);
        } else {
            res.status(404).json(queryResult);
        }
        return;
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.get("/api/removeuser", sessionCheck, async (req, res) => {
    try {
        if (!req.query.email) {
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }

        let queryResult = await database.addUser(req.query.email);
        if (queryResult["status"] == "success") {
            let deleteResult = await database.removeUser(req.query.email);
            if (deleteResult["status"] == "success") {
                res.status(200).json(deleteResult);
            } else {
                res.status(403).json(deleteResult);
            }
            return;
        } else {
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
});

router.post("/api/batchremoveuser", sessionCheck, async (req, res) => {
    try {
        if (! (req.body && req.body.users && (req.body.users instanceof Array))) {
            res.status(403).json({
                status: "failed",
                reason: "Too few arguments"
            });
            return;
        }
        for (const item of req.body.users) {
            await database.removeUser(item);
        }
        res.status(200).json({
            status: "success",
            reason: "",
            users: req.body.users
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

router.use("/api/logout", sessionCheck, async (req, res, next) => {
    if (req.headers.authorization) {
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
        res.status(200).json({
            status: "success",
            reason: "",
            goodbye: true
        });
    } catch (error) {
        logger.error(error);
        res.status(500).json({
            status: "failed",
            reason: "Internal server error"
        });
    }
});

router.use("/admin", express.static("admin-panel"));

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