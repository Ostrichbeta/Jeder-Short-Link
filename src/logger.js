const winston = require("winston");
const path = require("path");
const { combine, label, timestamp, json, printf, colorize, form } = winston.format;
const fs = require("fs");
const fsExists = require("fs.promises.exists");

const errorLogPath = path.join(path.dirname(__dirname), 'log', 'error.log');

async function checkLog() {
    let parentPath = path.dirname(__dirname);
    if (!await fsExists(path.join(parentPath, 'log'))) {
        let mkdirResult = await fs.promises.mkdir(path.join(parentPath, 'log'));
        console.log("No log folder, creating it.");
    }
    
    if (!(await fs.promises.lstat(path.join(parentPath, 'log'))).isDirectory()) {
        console.error(`${parentPath}/log is not a directory, please remove it and go again.`);
        exit(127);
    }

    return 0;
}

const myFormat = printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${level}] <${label}> - ${message}`;
});

winston.loggers.add("loggerLogger", {
    level: 'debug', 
    transports: [
        new winston.transports.Console({
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "LOGGER"}), colorize({all: true}), myFormat, 
            )
        }),
        new winston.transports.File({
            filename: errorLogPath,
            level: "warn",
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "LOGGER"}), myFormat, 
            )
        })
    ]
});

winston.loggers.get("loggerLogger").info("Logger for logger initialized.");

winston.loggers.add("accessLogger", {
    level: 'debug', 
    transports: [
        new winston.transports.Console({
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "ACCESS"}), colorize({all: true}), myFormat, 
            )
        }),
        new winston.transports.File({
            filename: errorLogPath,
            level: "warn",
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "ACCESS"}), myFormat, 
            )
        })
    ]
});

winston.loggers.get("loggerLogger").info("Logger for access module initialized.");

winston.loggers.add("databaseLogger", {
    level: 'debug', 
    transports: [
        new winston.transports.Console({
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "DB"}), colorize({all: true}), myFormat, 
            )
        }),
        new winston.transports.File({
            filename: errorLogPath,
            level: "warn",
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "DB"}), myFormat, 
            )
        })
    ]
});

winston.loggers.get("loggerLogger").info("Logger for database module initialized.");

winston.loggers.add("securityLogger", {
    level: 'debug', 
    transports: [
        new winston.transports.Console({
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "SECURITY"}), colorize({all: true}), myFormat, 
            )
        }),
        new winston.transports.File({
            filename: errorLogPath,
            level: "warn",
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "SECURITY"}), myFormat, 
            )
        })
    ]
});

winston.loggers.get("loggerLogger").info("Logger for security module initialized.");

winston.loggers.add("mainLogger", {
    level: 'debug', 
    transports: [
        new winston.transports.Console({
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "MAIN"}), colorize({all: true}), myFormat, 
            )
        }),
        new winston.transports.File({
            filename: errorLogPath,
            level: "warn",
            format: combine(
                winston.format(info => ({ ...info, level: info.level.toUpperCase() }))(),
                timestamp({format: "MM/DD hh:mm:ss.SS A"}), label({label: "MAIN"}), myFormat, 
            )
        })
    ]
});

winston.loggers.get("loggerLogger").info("Logger for main module initialized.");

module.exports.checkLog = checkLog;