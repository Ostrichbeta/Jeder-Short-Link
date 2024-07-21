const express = require("express");
const args = require("yargs").argv;
const cors = require("cors");
const tpu = require("tcp-port-used");
const logger = require("./src/logger");

const winston = require("winston");
const mainLogger = winston.loggers.get("mainLogger");

const security = require("./src/security");
const databaseObj = require("./src/database");
const accessRouter = require("./src/access").router;

const app = express();
let port = args['port'] ? parseInt(args['port']) : 3000;
let host = args['host'] ? parseInt(args['host']) : "localhost";

app.set('view engine', 'ejs'); // Use ejs to render statis pages
app.use('/', accessRouter);
app.use(cors());

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
    await security.checkSecretExists();
    await security.checkConfig();

    await databaseObj.initDatabase();
    let shortLinkLists = await databaseObj.getList();
    mainLogger.info(`[Server] There are currently ${shortLinkLists.results.length} link(s) in the database.`);

    await app.listen(port, () => {
        mainLogger.info(`[Server] Listening on port ${ port }.`);
    });
})();