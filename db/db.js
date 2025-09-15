// db.js
// ─────────────────────────────────────────────────────────────
// Single source of truth for SQLite access & app data models.
// - Users table: id/email/pw_hash
// - User states: (user_id, ns) → JSON state with updated_at
// - Ready for express-session store sharing (same DB file OK)
// ─────────────────────────────────────────────────────────────
const path = require("path");
const Sqlite = require("better-sqlite3");

// DB 파일 경로: 필요 시 .env의 DB_PATH로 교체
const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), "app.db");
const db = new Sqlite(DB_PATH);

// 성능/안정성 권장 설정
db.pragma("journal_mode = WAL");   // 동시성 향상
db.pragma("foreign_keys = ON");    // FK 무결성
db.pragma("synchronous = NORMAL"); // WAL과 궁합
db.pragma("busy_timeout = 5000"); // 경합시 5초까지 대기

// ─────────────────────────────────────────────────────────────
// Schema
// ─────────────────────────────────────────────────────────────
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT    NOT NULL UNIQUE,     -- lowercased
  pw_hash    TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_states (
  user_id    INTEGER NOT NULL,
  ns         TEXT    NOT NULL,            -- namespace (e.g., user.id or custom)
  state_json TEXT    NOT NULL,            -- serialized JSON
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, ns),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_states_updated
ON user_states (updated_at DESC);
`);

// ─────────────────────────────────────────────────────────────
/** Prepared statements */
// ─────────────────────────────────────────────────────────────
const stmtInsertUser = db.prepare(`
  INSERT INTO users (email, pw_hash, created_at)
  VALUES (LOWER(?), ?, ?)
`);
const stmtGetUserByEmail = db.prepare(`
  SELECT id, email, pw_hash, created_at
  FROM users WHERE email = LOWER(?)
`);
const stmtGetUserById = db.prepare(`
  SELECT id, email, pw_hash, created_at
  FROM users WHERE id = ?
`);

const stmtGetState = db.prepare(`
  SELECT state_json, updated_at
  FROM user_states
  WHERE user_id = ? AND ns = ?
`);
const stmtPutState = db.prepare(`
  INSERT INTO user_states (user_id, ns, state_json, updated_at)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(user_id, ns) DO UPDATE SET
    state_json = excluded.state_json,
    updated_at = excluded.updated_at
`);
const stmtListNamespaces = db.prepare(`
  SELECT ns, updated_at
  FROM user_states
  WHERE user_id = ?
  ORDER BY updated_at DESC
`);
const stmtDeleteState = db.prepare(`
  DELETE FROM user_states
  WHERE user_id = ? AND ns = ?
`);

// ─────────────────────────────────────────────────────────────
// User APIs
// ─────────────────────────────────────────────────────────────

/**
 * Create user (email must be unique & already validated).
 * @param {string} email - user email (will be lowercased)
 * @param {string} pwHash - argon2 hash or similar
 * @returns {number} user id (lastInsertRowid)
 */
function createUser(email, pwHash) {
  const createdAt = Date.now();
  const info = stmtInsertUser.run(email, pwHash, createdAt);
  return Number(info.lastInsertRowid);
}

/** @param {string} email */
function getUserByEmail(email) {
  const row = stmtGetUserByEmail.get(email);
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    pwHash: row.pw_hash,
    createdAt: row.created_at,
  };
}

/** @param {number} id */
function getUserById(id) {
  const row = stmtGetUserById.get(id);
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    pwHash: row.pw_hash,
    createdAt: row.created_at,
  };
}

// ─────────────────────────────────────────────────────────────
// User State APIs (namespace-based persistent snapshots)
// ─────────────────────────────────────────────────────────────

/**
 * Get a user's namespaced state.
 * @param {number} userId
 * @param {string} ns
 * @returns {{state: any, updatedAt: number} | null}
 */
function getUserState(userId, ns) {
  const row = stmtGetState.get(userId, String(ns));
  if (!row) return null;
  let state = null;
  try { state = JSON.parse(row.state_json); } catch {}
  return { state, updatedAt: row.updated_at };
}

/**
 * Upsert a user's namespaced state.
 * @param {number} userId
 * @param {string} ns
 * @param {any} state - serializable object
 * @param {number} [updatedAt=Date.now()]
 * @returns {true}
 */
function putUserState(userId, ns, state, updatedAt = Date.now()) {
  const json = JSON.stringify(state ?? {});
  stmtPutState.run(userId, String(ns), json, Number(updatedAt) || Date.now());
  return true;
}

/**
 * List namespaces for a user (most-recent first).
 * @param {number} userId
 * @returns {Array<{ns:string, updated_at:number}>}
 */
function listUserNamespaces(userId) {
  return stmtListNamespaces.all(userId)
    .map(r => ({ ns: r.ns, updatedAt: r.updated_at }));
}

/**
 * Delete a single namespaced state.
 * @param {number} userId
 * @param {string} ns
 * @returns {boolean} deleted
 */
function deleteUserState(userId, ns) {
  const info = stmtDeleteState.run(userId, String(ns));
  return info.changes > 0;
}

// ─────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────

/** Run a function in a transaction. fn can return a value. */
function withTransaction(fn) {
  const tx = db.transaction(fn);
  return tx();
}

module.exports = {
  // raw handle (e.g., for session store)
  db,

  // users
  createUser,
  getUserByEmail,
  getUserById,

  // states
  getUserState,
  putUserState,
  listUserNamespaces,
  deleteUserState,

  // util
  withTransaction,
};
