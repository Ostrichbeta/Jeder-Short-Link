const express = require("express");
const args = require("yargs").argv;
const cors = require("cors");
const tpu = require("tcp-port-used");
const logger = require("./src/logger");
const session = require("express-session");
const bodyParser = require("body-parser");

const winston = require("winston");
const mainLogger = winston.loggers.get("mainLogger");

const security = require("./src/security");
const databaseObj = require("./src/database");
const accessRouter = require("./src/access").router;
const authRouter = require("./src/auth/AuthNode").router;
const authTestRouter = require("./src/auth/AuthCheck").router;

const app = express();
let port = args['port'] ? parseInt(args['port']) : 3000;
let host = args['host'] ? parseInt(args['host']) : "localhost";


async function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

(async () => {
    while (await tpu.check(port, "localhost")) {
        await sleep(200);
        console.log(`Port ${port} used, now trying ${port + 1}...`);
        port = port + 1;
    }

    await logger.checkLog();
    await security.checkRes();
    let hashedSecret = await security.checkSecretExists();
    await security.checkConfig();

    app.set('trust proxy', 1); // trust first proxy
    app.use(session({
        secret: hashedSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 600000 // 10 Minutes,
        },
    }));

    app.set('view engine', 'ejs'); // Use ejs to render statis pages
    app.use('/auth', authRouter);
    app.use('/acheck', authTestRouter);
    app.use('/', accessRouter);
    app.use(bodyParser.json());       // to support JSON-encoded bodies
    app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
        extended: true
    }));

    await databaseObj.initDatabase();
    let shortLinkLists = await databaseObj.getList();
    mainLogger.info(`There are currently ${shortLinkLists.results.length} link(s) in the database.`);

    await app.listen(port, () => {
        mainLogger.info(`Listening on port ${port}.`);
    });
})();