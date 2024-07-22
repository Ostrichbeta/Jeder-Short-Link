const { channel } = require("diagnostics_channel");
const fs = require("fs");
const path = require("path");
const { exit } = require("process");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { error } = require("console");
const database = require("./database");
const nconf = require("nconf");
const fsExists = require("fs.promises.exists");
const axios = require("axios");

const winston = require("winston");
const logger = winston.loggers.get("securityLogger");
const accessLogger = winston.loggers.get("accessLogger");

let configFile = path.join(path.dirname(__dirname), 'config', 'config.json');
let secretFile = path.join(path.dirname(__dirname), 'res', 'secret');

nconf.file({file: configFile});

var secret = "";
const timer = ms => new Promise( res => setTimeout(res, ms));

async function checkRes() {
    let parentPath = path.dirname(__dirname);
    if (!await fsExists(path.join(parentPath, 'res'))) {
        let mkdirResult = await fs.promises.mkdir(path.join(parentPath, 'res'));
        logger.debug("No res folder, creating it.");
    }
    
    if (!(await fs.promises.lstat(path.join(parentPath, 'res'))).isDirectory()) {
        logger.error(`${parentPath}/res is not a directory, please remove it and go again.`);
        exit(127);
    }

    return 0;
}

async function checkConfig() {
    let parentPath = path.dirname(__dirname);
    if (!await fsExists(path.join(parentPath, 'config'))) {
        fs.mkdir(path.join(parentPath, 'config'), (err) => {
            logger.error(err);
        });
        logger.debug("No config folder, creating it.");
    }
    
    if (!(await fs.promises.lstat(path.join(parentPath, 'config'))).isDirectory()) {
        logger.error(`${parentPath}/config is not a directory, please remove it and go again.`);
        exit(127);
    }

    // Check if config file exist

    if (await fsExists(configFile) && (await fs.promises.lstat(configFile)).isFile()) {
        // File (if it is a file exists)
        logger.debug("Config file exists.");
    }
    if (await fsExists(configFile)) {
        if ((await fs.promises.lstat(configFile)).isDirectory()) {
            await fs.promises.rmdir(configFile);
            await fs.promises.writeFile(configFile, "{}");
        }
    } else {
        await fs.promises.writeFile(configFile, "{}");
    }

    let trunstileCheck = true;

    nconf.file({file: configFile});

    if ((!nconf.get("Turnstile:sitekey")) || (nconf.get("Turnstile:sitekey") == "")) {
        logger.error("[Turnstile] No sitekey detected!");
        nconf.set("Turnstile:sitekey", "<sitekey>");
        trunstileCheck = false;
    }

    if ((!nconf.get("Turnstile:secret")) || (nconf.get("Turnstile:secret") == "")) {
        logger.error("[Turnstile] No secret detected!");
        nconf.set("Turnstile:secret", "<secretkey>");
        trunstileCheck = false;
    }

    nconf.save();

    if (!trunstileCheck) {
        logger.error("Turnstile config error, the program will now exit.");
        exit(127);
    }

    return 0;
}

async function checkSecretExists(forceRegen = false) {
    if (fs.existsSync(secretFile) && fs.lstatSync(secretFile).isFile() && (!forceRegen)) {
        // File (if it is a file exists)
        logger.debug("Key file exists, passed the check.");
        let secretByte = await fs.promises.readFile(secretFile);
        return secretByte.toString();
    }
    if (fs.existsSync(secretFile)) {
        if (fs.lstatSync(secretFile).isDirectory()) {
            fs.rmdirSync(secretFile);
        } else {
            fs.rmSync(secretFile);
        }
    }
    
    // Token generation
    let hashedToken = ""
    try {
        let tokenBytes = await crypto.randomBytes(32);
        let hexstr = tokenBytes.toString('hex');
        logger.info(`Token generated, please copy and save this string in safe place, it will be shown ONLY ONCE!`);
        logger.info(`Token: ${hexstr}`);
        hashedToken = await bcrypt.hash(hexstr, 10);
        await fs.promises.writeFile(secretFile, hashedToken);
    } catch (error) {
        throw error;
    }
    return hashedToken.toString();
}

async function checkSecret(str) {
    if (secret == "") {
        try {
            while (true) {
                try {
                    await fs.promises.access(secretFile, fs.constants.F_OK);
                    break;
                } catch (error) {
                    await timer(500);
                }
            }
            let secretByte = await fs.promises.readFile(secretFile);
            secret = secretByte.toString();
        } catch (error) {
            logger.error(error.stack);
        }
    }
    if (await bcrypt.compare(str, secret)) {
        return true;
    } else {
        return false;
    }
}

async function tokenCheck(req, res, next) {
    if (!req.headers.authorization) {
        res.status(401).json({
            status: "failed",
            reason: "Unauthorized"
        });
        return;
    }
    
    let isTokenValid = await checkSecret(req.headers.authorization.slice(7));
    if (isTokenValid) {
        next();
    } else {
        res.status(403).json({  
            status: "failed",
            reason: "Invalid Token"
        });
        return;
    }
}

async function accessFrequencyCheck(req, res, next) {
    // Check access frequency before directing to the target site
    try {
        let xffList = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].toString().split(", ")[0] : undefined;
        let ip = xffList || req.socket.remoteAddress;
        res.locals.ip = ip;
        let accessResult = await database.getIPLog(ip, 60000);
        if (accessResult.length <= 3) {
            next();
        } else {
            accessLogger.info(`Client from ${ip} accessed /${req.params.link} invokes the Turnstile verification`);
            if (!req.query.token) {
                // No turnstile token provided
                res.render("verify", {
                    link: req.params.link
                });
                await database.writeLog("turnstile", req.params.link, ip);
            } else {
                const cfURL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
                let cloudflareVerificationResult = await axios.post(cfURL, {
                    secret: nconf.get("Turnstile:secret"),
                    response: req.query.token,
                    remoteip: ip
                });
                if (cloudflareVerificationResult.status == 200 && cloudflareVerificationResult.data["success"] == true) {
                    next();
                } else {
                    console.warn("[Access] Client from " + ip + " accessed /" + req.params.link + " failed the verification");
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
        logger.error(error.stack);
        res.send(500).json({
            status: "failed",
            reason: "Interna1 server error"
        });
        return;
    }
}

async function sessionCheck(req, res, next) {
    try {
        if (req.session.user) {
            if (req.session.user == "root") {
                res.locals.bypassTokenCheck = true;
                next();
            } else {
                res.status(401).json({
                    status: "failed",
                    reason: "Unauthorized"
                });
                return;
            }
            // TODO: Other user
        } else {
            if (req.headers.authorization) {
                // No session, jump to token check
                return tokenCheck(req, res, next);
            } else {
                res.status(401).json({
                    status: "failed",
                    reason: "Unauthorized"
                });
                return;
            }
        }
    } catch (error) {
        logger.error(error.stack);
        res.status(500).json({
            status: "failed",
            reason: "Internal Server Error"
        });
        return;
    }
}

module.exports.checkConfig = checkConfig;
module.exports.checkRes = checkRes;
module.exports.checkSecret = checkSecret;
module.exports.checkSecretExists = checkSecretExists;
module.exports.tokenCheck = tokenCheck;
module.exports.accessFrequencyCheck = accessFrequencyCheck;
module.exports.sessionCheck = sessionCheck;