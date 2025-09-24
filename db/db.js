// db.js
// ─────────────────────────────────────────────────────────────
// Single source of truth for SQLite access & app data models.
// - Users table: id / email / pw_hash / display_name / avatar_url
// - User states: (user_id, ns) → JSON state with updated_at
// - Ready for express-session store sharing (same DB file OK)
// ─────────────────────────────────────────────────────────────

const path = require("path");
const Sqlite = require("better-sqlite3");

// ─────────────────────────────────────────────────────────────
// DB Open & Pragmas
// ─────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), "app.db");
const db = new Sqlite(DB_PATH);

// 성능/안정성 권장 설정
db.pragma("journal_mode = WAL");    // 동시성 향상
db.pragma("foreign_keys = ON");     // FK 무결성
db.pragma("synchronous = NORMAL");  // WAL과 궁합
db.pragma("busy_timeout = 5000");   // 경합 시 5초 대기

// ─────────────────────────────────────────────────────────────
// Schema (최신 스키마 기준으로 CREATE)
// ─────────────────────────────────────────────────────────────
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT    NOT NULL UNIQUE,     -- stored lowercased
  pw_hash       TEXT    NOT NULL,
  created_at    INTEGER NOT NULL,
  display_name  TEXT,
  avatar_url    TEXT
);

CREATE TABLE IF NOT EXISTS user_states (
  user_id     INTEGER NOT NULL,
  ns          TEXT    NOT NULL,              -- namespace (e.g., email or custom)
  state_json  TEXT    NOT NULL,              -- serialized JSON
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, ns),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_states_updated
ON user_states (updated_at DESC);
`);

// ─────────────────────────────────────────────────────────────
// One-time migrations (구버전 DB 대응)
//  - 구 DB에 display_name, avatar_url 컬럼이 없을 수 있으니 보강
// ─────────────────────────────────────────────────────────────
function columnExists(table, col) {
  try {
    const rows = db.prepare(`PRAGMA table_info(${table})`).all();
    return rows.some(r => r.name === col);
  } catch {
    return false;
  }
}

if (!columnExists("users", "display_name")) {
  db.exec(`ALTER TABLE users ADD COLUMN display_name TEXT`);
}
if (!columnExists("users", "avatar_url")) {
  db.exec(`ALTER TABLE users ADD COLUMN avatar_url TEXT`);
}

// ─────────────────────────────────────────────────────────────
// Helpers (정규화)
// ─────────────────────────────────────────────────────────────
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeNS(ns) {
  return String(ns || "").trim().toLowerCase();
}

// ─────────────────────────────────────────────────────────────
// Prepared Statements
// ─────────────────────────────────────────────────────────────
const stmtInsertUser = db.prepare(`
  INSERT INTO users (email, pw_hash, created_at, display_name, avatar_url)
  VALUES (LOWER(?), ?, ?, NULL, NULL)
`);

const stmtGetUserByEmail = db.prepare(`
  SELECT id, email, pw_hash, created_at, display_name, avatar_url
  FROM users
  WHERE email = LOWER(?)
`);

const stmtGetUserById = db.prepare(`
  SELECT id, email, pw_hash, created_at, display_name, avatar_url
  FROM users
  WHERE id = ?
`);

const stmtUpdateProfile = db.prepare(`
  UPDATE users
  SET display_name = COALESCE(?, display_name),
      avatar_url   = COALESCE(?, avatar_url)
  WHERE id = ?
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
 * @param {string} pwHash - password hash (e.g., argon2)
 * @returns {number} user id (lastInsertRowid)
 */
function createUser(email, pwHash) {
  const createdAt = Date.now();
  const normEmail = normalizeEmail(email);
  const info = stmtInsertUser.run(normEmail, pwHash, createdAt);
  return Number(info.lastInsertRowid);
}

/** @param {string} email */
function getUserByEmail(email) {
  const row = stmtGetUserByEmail.get(normalizeEmail(email));
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    pwHash: row.pw_hash,
    createdAt: row.created_at,
    displayName: row.display_name || null,
    avatarUrl: row.avatar_url || null,
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
    displayName: row.display_name || null,
    avatarUrl: row.avatar_url || null,
  };
}

/**
 * Update profile fields (partial update).
 * - null/undefined는 기존 값 유지(COALESCE)
 * @param {number} userId
 * @param {{displayName?: string|null, avatarUrl?: string|null}} patch
 * @returns {true}
 */
function updateUserProfile(userId, { displayName = null, avatarUrl = null } = {}) {
  stmtUpdateProfile.run(displayName ?? null, avatarUrl ?? null, userId);
  return true;
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
  const key = normalizeNS(ns);
  const row = stmtGetState.get(userId, key);
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
  const key = normalizeNS(ns);
  const json = JSON.stringify(state ?? {});
  stmtPutState.run(userId, key, json, Number(updatedAt) || Date.now());
  return true;
}

/**
 * List namespaces for a user (most-recent first).
 * @param {number} userId
 * @returns {Array<{ns:string, updatedAt:number}>}
 */
function listUserNamespaces(userId) {
  return stmtListNamespaces
    .all(userId)
    .map(r => ({ ns: r.ns, updatedAt: r.updated_at }));
}

/**
 * Delete a single namespaced state.
 * @param {number} userId
 * @param {string} ns
 * @returns {boolean} deleted
 */
function deleteUserState(userId, ns) {
  const key = normalizeNS(ns);
  const info = stmtDeleteState.run(userId, key);
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

// ─────────────────────────────────────────────────────────────
// Exports
// ────ㅁ─────────────────────────────────────────────────────────
module.exports = {
  // raw handle (e.g., for session store)
  db,

  // users
  createUser,
  getUserByEmail,
  getUserById,
  updateUserProfile,

  // states
  getUserState,
  putUserState,
  listUserNamespaces,
  deleteUserState,

  // util
  withTransaction,
};

// [ADD] Web Push storage
db.exec(`
CREATE TABLE IF NOT EXISTS push_subscriptions (
  ns          TEXT    NOT NULL,
  endpoint    TEXT    NOT NULL UNIQUE,
  json        TEXT    NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS push_events (
  ev_key   TEXT PRIMARY KEY,   -- e.g., "like:ITEM:ACTORNS"
  ts       INTEGER NOT NULL
);
`);

function addPushSubscription(ns, sub){
  const row = db.prepare(`INSERT INTO push_subscriptions (ns, endpoint, json, created_at)
                          VALUES (LOWER(?), ?, ?, ?) 
                          ON CONFLICT(endpoint) DO UPDATE SET json=excluded.json, created_at=excluded.created_at`)
                .run(String(ns||'').toLowerCase(), sub.endpoint, JSON.stringify(sub), Date.now());
  return true;
}
function removePushSubscription(endpoint){
  db.prepare(`DELETE FROM push_subscriptions WHERE endpoint=?`).run(endpoint);
  return true;
}
function listPushSubscriptions(ns){
  return db.prepare(`SELECT endpoint, json FROM push_subscriptions WHERE ns=LOWER(?)`).all(String(ns||'').toLowerCase());
}
function seenPushEvent(evKey, ttlMs=1000*60*60*24){
  const now = Date.now();
  const row = db.prepare(`SELECT ts FROM push_events WHERE ev_key=?`).get(evKey);
  if (row && (now - Number(row.ts||0) < ttlMs)) return true;
  db.prepare(`INSERT INTO push_events (ev_key, ts) VALUES (?, ?)
              ON CONFLICT(ev_key) DO UPDATE SET ts=excluded.ts`).run(evKey, now);
  return false; // false면 '이번에 처음' == 발사 OK
}

module.exports.addPushSubscription = addPushSubscription;
module.exports.removePushSubscription = removePushSubscription;
module.exports.listPushSubscriptions = listPushSubscriptions;
module.exports.seenPushEvent = seenPushEvent;
