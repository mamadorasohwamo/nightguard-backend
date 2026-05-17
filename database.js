const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'nightguard.db');
const db = new sqlite3.Database(dbPath);

const initDb = () => {
    db.serialize(() => {
        // Customers table
        db.run(`CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE,
            username TEXT,
            avatar TEXT,
            role TEXT DEFAULT 'customer',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Generated PINs table
        db.run(`CREATE TABLE IF NOT EXISTS generated_pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pin TEXT UNIQUE,
            customer_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )`);

        // Scans table
        db.run(`CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            customer_id INTEGER,
            pin_id INTEGER,
            player_hwid TEXT,
            player_name TEXT,
            risk_score INTEGER,
            verdict TEXT,
            raw_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(customer_id) REFERENCES customers(id),
            FOREIGN KEY(pin_id) REFERENCES generated_pins(id)
        )`);

        // Detections table
        db.run(`CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            category TEXT,
            path TEXT,
            matched_keyword TEXT,
            severity TEXT,
            first_seen DATETIME,
            downloaded_at DATETIME,
            executed_at DATETIME,
            last_seen DATETIME,
            deleted_at DATETIME,
            confidence_score REAL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )`);

        // Reports table
        db.run(`CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            report_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )`);
    });
};

module.exports = {
    db,
    initDb
};
