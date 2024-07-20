const express = require("express");
const router = express.Router();
const authCheck = require("./security").authCheck;
const database = require("./database");
const path = require("path");
const axios = require("axios");
const nconf = require("nconf");

let configFile = path.join(path.dirname(__dirname), 'config', 'config.json');

nconf.file({file: configFile});

router.get("/create", authCheck, async (req, res) => {
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
                let createResult = await database.addLink(req.query.name, req.query.target);
                if (createResult["status"] == "success") {
                    res.status(200).json(createResult);
                } else {
                    res.status(403).json(createResult);
                }
                return;
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
        console.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/remove", authCheck, async (req, res) => {
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
        console.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/getdetail", authCheck, async (req, res) => {
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
        console.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/getlist", authCheck, async (req, res) => {
    try {
        let getListResult = await database.getList();
        if (getListResult["status"] == "success") {
            res.status(200).json(getListResult);
        } else {
            res.status(403).json(getListResult);
        }
    } catch (error) {
        console.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

router.get("/:link", async (req, res, next) => {
    try {
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        let accessResult = await database.getIPLog(ip, 60000);
        if (accessResult.length <= 3) {
            next("route");
        } else {
            console.log("Trunstile invoked.");
            if (!req.query.token) {
                // No turnstile token provided
                res.render("verify", {
                    link: req.params.link
                });
            } else {
                const cfURL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
                let cloudflareVerificationResult = await axios.post(cfURL, {
                    secret: nconf.get("Turnstile:secret"),
                    response: req.query.token,
                    remoteip: ip
                });
                if (cloudflareVerificationResult.status == 200 && cloudflareVerificationResult.data["success"] == true) {
                    next("route");
                } else {
                    console.warn("[Access] Client from " + ip + " accessed /" + req.params.link + " failed the verification at " + new Date().toJSON());
                    res.status(403).json({
                        status: "failed",
                        reason: "Turnstile verification failed"
                    });
                    return;
                }
            }
            return;
        }
    } catch (error) {
        console.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Interna1 server error"
        });
        return;
    }

});

router.get("/:link", async (req, res) => {
    try {
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        let getLinkResult = await database.getLink(req.params.link);
        if (getLinkResult["status"] == "success") {
            // res.status(200).json({
            //     status: "success",
            //     reason: "",
            //     link: getLinkResult["results"][0]['TARGET_LINK']
            // });'
            database.writeLog(getLinkResult["results"][0]["id"], req.params.link, ip);
            res.redirect(302, getLinkResult["results"][0]['TARGET_LINK']);
            return;
        } else {
            database.writeLog("notfound", req.params.link, ip);
            res.status(404).json({
                status: "failed",
                reason: "Not found"
            });
            return;
        }
    } catch (error) {
        console.error(error);
        res.send(500).json({
            status: "failed",
            reason: "Internal server error"
        });
        return;
    }
});

module.exports.router = router;