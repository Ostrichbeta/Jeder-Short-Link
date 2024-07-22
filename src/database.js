const fs = require("fs");
const { exit } = require("process");
const sqlite3 = require("sqlite3").verbose();
const { open } = require('sqlite');
const path = require("path");
const HRI = require("human-readable-ids").hri;
const randomstring = require("randomstring");

const winston = require("winston");
const logger = winston.loggers.get("databaseLogger");

const sqlitePath = path.join(path.dirname(__dirname), 'res', 'database.db');
const logDBPath = path.join(path.dirname(__dirname), 'res', 'log.db');

async function initDatabase() {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    })
    logger.debug("Check and create the link database in " + sqlitePath + "...");
    // Create database
    await db.run("CREATE TABLE IF NOT EXISTS LINK_TABLE (id TEXT PRIMARY KEY, name TEXT, SOURCE_LINK TEXT NOT NULL, TARGET_LINK TEXT NOT NULL, CREATED_AT INTEGER NOT NULL, EXPIRE_AT INTEGER DEFAULT -1 NOT NULL)");
    // Add click count
    try {
        await db.exec("ALTER TABLE LINK_TABLE ADD COLUMN CLICKCOUNT INTEGER DEFAULT 0");
    } catch (error) {
        logger.debug("DB click count patch added.");
    }
    await db.close();
    logger.debug("Link database closed.");

    const logdb = await open({
        filename: logDBPath,
        driver: sqlite3.Database
    });
    logger.debug("Check and create the log database in " + logDBPath + "...");
    await logdb.run("CREATE TABLE IF NOT EXISTS LOG_TABLE (id TEXT NOT NULL, SOURCE_LINK TEXT NOT NULL, IP TEXT NOT NULL, ACCESSED_AT INTEGER NOT NULL)");
    await logdb.close();
    logger.debug("Link database closed.");
}

async function addLink(name, targetLink, expireAt = -1) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        // Find duplicated ids
        let id = "";
        let generatedLink = "";
        while (true) {
            id = HRI.random();

            const result = await db.get('SELECT * FROM LINK_TABLE WHERE id = ?', id);
            if (result !== undefined) {
                console.info("Dupicated id " + id);
            } else {
                break;
            }
        }

        // Find duplicated generated links
        while (true) {
            generatedLink = randomstring.generate({
                length: 3,
                charset: 'QWERTYUPASDFGHJKLXCVBNMqwertyupasdfghjklxcvbnm0123456789'
            });

            const result = await db.get('SELECT * FROM LINK_TABLE WHERE SOURCE_LINK = ?', generatedLink);
            if (result !== undefined) {
                console.info("Dupicated source link " + generatedLink);
            } else {
                break;
            }
        }
        

        const stmt = await db.prepare("INSERT INTO LINK_TABLE (id, name, SOURCE_LINK, TARGET_LINK, CREATED_AT, EXPIRE_AT) VALUES (?, ?, ?, ?, ?, ?)");
        await stmt.run([id, name, generatedLink, targetLink, Date.now(), expireAt]);
        await stmt.finalize();
        await db.close();
        logger.debug(`A new link /${generatedLink} (ID: ${id}) added, target ${targetLink} expire at ${expireAt}`);
        return {status: "success", reason: "", id: id, source: "/" + generatedLink, target: targetLink, created_at: Date.now(), expire_at: expireAt};
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function getLink(source) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        await db.run('DELETE FROM LINK_TABLE WHERE (EXPIRE_AT <> -1 AND EXPIRE_AT <= ?)', Date.now());
        const result = await db.all('SELECT * FROM LINK_TABLE WHERE SOURCE_LINK = ?', source);
        await db.close();
        if (result.length > 0) {
            return {status: "success", reason: "", results: result};
        } else {
            return {status: "failed", reason: "Not found", results: []};
        }
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function getID(id) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        await db.run('DELETE FROM LINK_TABLE WHERE (EXPIRE_AT <> -1 AND EXPIRE_AT <= ?)', Date.now());
        const result = await db.all('SELECT * FROM LINK_TABLE WHERE id = ?', id);
        await db.close();
        if (result.length > 0) {
            return {status: "success", reason: "", results: result};
        } else {
            return {status: "failed", reason: "Not found", results: []};
        }
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function getTarget(target) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        await db.run('DELETE FROM LINK_TABLE WHERE (EXPIRE_AT <> -1 AND EXPIRE_AT <= ?)', Date.now());
        const result = await db.all('SELECT * FROM LINK_TABLE WHERE instr(TARGET_LINK, ?) > 0;', target);
        await db.close();
        if (result.length > 0) {
            return {status: "success", reason: "", results: result};
        } else {
            return {status: "failed", reason: "Not found", results: []};
        }
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function removeLinkFromID(id) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        const result = await db.all('SELECT * FROM LINK_TABLE WHERE id = ?', id);
        if (result.length > 0) {
            await db.run('DELETE FROM LINK_TABLE WHERE id = ?', id);
            await db.close();
            logger.debug(`Link /${result[0]["SOURCE_LINK"]} (ID: ${result[0]["id"]}) removed, target ${result[0]["TARGET_LINK"]}`);
            return {status: "success", reason: "", results: result};
        } else {
            await db.close();
            return {status: "failed", reason: "Not found"};
        }
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}
async function removeLinkFromSourceLink(sourceLink) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        const result = await db.all('SELECT * FROM LINK_TABLE WHERE SOURCE_LINK = ?', sourceLink);
        if (result.length > 0) {
            await db.run('DELETE FROM LINK_TABLE WHERE SOURCE_LINK = ?', sourceLink);
            await db.close();
            logger.debug(`Link /${result[0]["SOURCE_LINK"]} (ID: ${result[0]["id"]}) removed, target ${result[0]["TARGET_LINK"]}`);
            return {status: "success", reason: "", results: result};
        } else {
            await db.close();
            return {status: "failed", reason: "Not found"};
        }
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function getList() {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        await db.run('DELETE FROM LINK_TABLE WHERE (EXPIRE_AT <> -1 AND EXPIRE_AT <= ?)', Date.now());
        const result = await db.all('SELECT * FROM LINK_TABLE');
        await db.close();
        return {status: "success", reason: "", results: result};
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function writeLog(id, source, ip) {
    const logdb = await open({
        filename: logDBPath,
        driver: sqlite3.Database
    });
    try {
        await logdb.run("INSERT INTO LOG_TABLE (id, SOURCE_LINK, IP, ACCESSED_AT) VALUES (?, ?, ?, ?)", [id, source, ip, Date.now()]);
        await logdb.close();
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function getIPLog(ip, interval = -1) {
    const logdb = await open({
        filename: logDBPath,
        driver: sqlite3.Database
    });
    try {
        if (interval == -1) {
            const IPLogResult = await logdb.all("SELECT * FROM LOG_TABLE WHERE IP = ?", ip);
            await logdb.close();
            return IPLogResult;
        } else {
            const IPLogResult = await logdb.all("SELECT * FROM LOG_TABLE WHERE (IP = ? AND ACCESSED_AT >= ?)", ip, Date.now() - interval);
            await logdb.close();
            return IPLogResult;
        }
        
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

async function addClickCount(id) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        let queryResult = await db.all("SELECT * FROM LINK_TABLE WHERE id = ?", [id]);
        if (queryResult.length == 0) {
            logger.error(`The given id ${id} is invalid.`);
            return;
        }
        let currentClickCount = queryResult[0]["CLICKCOUNT"];
        await db.run("UPDATE LINK_TABLE SET CLICKCOUNT = ? WHERE id = ?", [currentClickCount + 1, id]);
    } catch (error) {
        logger.error(error.stack);
    }
}

async function resetClickCount(id) {
    const db = await open({
        filename: sqlitePath,
        driver: sqlite3.Database
    });
    try {
        let queryResult = await db.all("SELECT * FROM LINK_TABLE WHERE id = ?", [id]);
        if (queryResult.length == 0) {
            logger.error(`The given id ${id} is invalid.`);
            return;
        }
        await db.run("UPDATE LINK_TABLE SET CLICKCOUNT = ? WHERE id = ?", [0, id]);
    } catch (error) {
        logger.error(error.stack);
    }
}

async function keepLog(retentionTime) {
    const logdb = await open({
        filename: logDBPath,
        driver: sqlite3.Database
    });
    try {
        await logdb.run("DELETE FROM LOG_TABLE WHERE ACCESSED_AT <= ?", Date.now() - retentionTime);
        await logdb.close();
    } catch (error) {
        logger.error(error.stack);
        return {status: "failed", reason: "Internal Error"};
    }
}

module.exports.initDatabase = initDatabase;
module.exports.addLink = addLink;
module.exports.getLink = getLink;
module.exports.getID = getID;
module.exports.removeLinkFromID = removeLinkFromID;
module.exports.removeLinkFromSourceLink = removeLinkFromSourceLink;
module.exports.getList = getList;
module.exports.writeLog = writeLog;
module.exports.getIPLog = getIPLog;
module.exports.keepLog = keepLog;
module.exports.addClickCount = addClickCount;
module.exports.resetClickCount = resetClickCount;
module.exports.getTarget = getTarget;