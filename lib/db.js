/**
 * SecureLoop - Shared Database Module
 * by Jorge Elizalde
 *
 * Single source of truth for the SQLite connection and schema.
 * All modules (index.js, dashboard/server.js, lib/scan.js) import
 * from here so they always open the SAME db/secureloop.db, regardless
 * of the process's current working directory.
 */

import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import Database from "better-sqlite3";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// Resolve from this file's location, not process.cwd().
// lib/ lives at repo_root/lib/ so db is one level up.
export const DB_PATH = path.join(__dirname, "..", "db", "secureloop.db");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);

// Schema — safe to run repeatedly (CREATE IF NOT EXISTS)
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_name  TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    risk_level  TEXT NOT NULL,
    findings    TEXT NOT NULL,
    scanned_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS blocklist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_name  TEXT NOT NULL UNIQUE,
    reason      TEXT,
    blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_name  TEXT NOT NULL UNIQUE,
    added_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS app_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

export default db;
