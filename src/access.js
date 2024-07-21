const express = require("express");
const router = express.Router();
const authCheck = require("./security").authCheck;
const database = require("./database");
const path = require("path");
const nconf = require("nconf");
const { accessFrequencyCheck } = require("./security");
const uap = require('ua-parser-js');

const winston = require("winston");
const logger = winston.loggers.get("accessLogger");

let configFile = path.join(path.dirname(__dirname), 'config', 'config.json');

nconf.file({file: configFile});

router.get("/api/create", authCheck, async (req, res) => {
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
                let createResult = await database.addLink(req.query.name, req.query.target, parseInt(req.query.expireat) * 1000);
                if (createResult["status"] == "success") {
                    res.status(200).json(createResult);
                } else {
                    res.status(403).json(createResult);
                }
                return;
            }
        }
    } catch (error) {
        logger.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/remove", authCheck, async (req, res) => {
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
        logger.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/getdetail", authCheck, async (req, res) => {
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
    } catch (error) {
        logger.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/getlist", authCheck, async (req, res) => {
    try {
        let getListResult = await database.getList();
        if (getListResult["status"] == "success") {
            res.status(200).json(getListResult);
        } else {
            res.status(403).json(getListResult);
        }
    } catch (error) {
        logger.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/api/resetcount", authCheck, async (req, res) => {
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
            await database.resetCLickCount(getIDResult["results"][0]["id"]);
            res.status(200).json(getIDResult);
        } else {
            res.status(404).json({
                status: "failed",
                reason: "Not found"
            });
        }
    } catch (error) {
        logger.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

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
            await database.addCLickCount(getLinkResult["results"][0]["id"]);
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
        logger.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

module.exports.router = router;