// db.js (정리된 최종본: 그대로 교체해도 안전)

// ─────────────────────────────────────────────────────────────
// Single source of truth for SQLite access & app data models.
// ─────────────────────────────────────────────────────────────
const path = require("path");
const Sqlite = require("better-sqlite3");

// ─────────────────────────────────────────────────────────────
// DB Open & Pragmas
// ─────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), "app.db");
const db = new Sqlite(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("synchronous = NORMAL");
db.pragma("busy_timeout = 5000");

// ─────────────────────────────────────────────────────────────
/* Schema (최신 스키마 기준) */
// ─────────────────────────────────────────────────────────────
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT    NOT NULL UNIQUE,
  pw_hash       TEXT    NOT NULL,
  created_at    INTEGER NOT NULL,
  display_name  TEXT,
  avatar_url    TEXT
);

CREATE TABLE IF NOT EXISTS user_states (
  user_id     INTEGER NOT NULL,
  ns          TEXT    NOT NULL,
  state_json  TEXT    NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, ns),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_states_updated ON user_states (updated_at DESC);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  ns          TEXT    NOT NULL,
  endpoint    TEXT    NOT NULL UNIQUE,
  json        TEXT    NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS push_events (
  ev_key   TEXT PRIMARY KEY,
  ts       INTEGER NOT NULL
);
`);

// ─────────────────────────────────────────────────────────────
// One-time migrations
// ─────────────────────────────────────────────────────────────
function columnExists(table, col) {
  try {
    const rows = db.prepare(`PRAGMA table_info(${table})`).all();
    return rows.some(r => r.name === col);
  } catch { return false; }
}
if (!columnExists("users", "display_name")) db.exec(`ALTER TABLE users ADD COLUMN display_name TEXT`);
if (!columnExists("users", "avatar_url")) db.exec(`ALTER TABLE users ADD COLUMN avatar_url TEXT`);

// ─────────────────────────────────────────────────────────────
// Helpers (정규화)
// ─────────────────────────────────────────────────────────────
function normalizeEmail(email) { return String(email || "").trim().toLowerCase(); }
function normalizeNS(ns) { return String(ns || "").trim().toLowerCase(); }

// ─────────────────────────────────────────────────────────────
// Prepared Statements
// ─────────────────────────────────────────────────────────────
const stmtInsertUser = db.prepare(`
  INSERT INTO users (email, pw_hash, created_at, display_name, avatar_url)
  VALUES (LOWER(?), ?, ?, NULL, NULL)
`);
const stmtGetUserByEmail = db.prepare(`
  SELECT id, email, pw_hash, created_at, display_name, avatar_url
  FROM users WHERE email = LOWER(?)
`);
const stmtGetUserById = db.prepare(`
  SELECT id, email, pw_hash, created_at, display_name, avatar_url
  FROM users WHERE id = ?
`);
const stmtUpdateProfile = db.prepare(`
  UPDATE users
  SET display_name = COALESCE(?, display_name),
      avatar_url   = COALESCE(?, avatar_url)
  WHERE id = ?
`);
const stmtGetState = db.prepare(`
  SELECT state_json, updated_at
  FROM user_states WHERE user_id = ? AND ns = ?
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
  FROM user_states WHERE user_id = ? ORDER BY updated_at DESC
`);
const stmtDeleteState = db.prepare(`
  DELETE FROM user_states WHERE user_id = ? AND ns = ?
`);
const stmtDeleteAllStatesForUser = db.prepare(`
  DELETE FROM user_states WHERE user_id = ?
`);

// ─────────────────────────────────────────────────────────────
// User APIs
// ─────────────────────────────────────────────────────────────
function createUser(email, pwHash) {
  const info = stmtInsertUser.run(normalizeEmail(email), pwHash, Date.now());
  return Number(info.lastInsertRowid);
}
function getUserByEmail(email) {
  const r = stmtGetUserByEmail.get(normalizeEmail(email));
  if (!r) return null;
  return { id: r.id, email: r.email, pwHash: r.pw_hash, createdAt: r.created_at, displayName: r.display_name || null, avatarUrl: r.avatar_url || null };
}
function getUserById(id) {
  const r = stmtGetUserById.get(id);
  if (!r) return null;
  return { id: r.id, email: r.email, pwHash: r.pw_hash, createdAt: r.created_at, displayName: r.display_name || null, avatarUrl: r.avatar_url || null };
}
function updateUserProfile(userId, { displayName = null, avatarUrl = null } = {}) {
  stmtUpdateProfile.run(displayName ?? null, avatarUrl ?? null, userId);
  return true;
}

// ─────────────────────────────────────────────────────────────
// User State APIs (legacy ns)
// ─────────────────────────────────────────────────────────────
function getUserState(userId, ns) {
  const row = stmtGetState.get(userId, normalizeNS(ns));
  if (!row) return null;
  let state = null; try { state = JSON.parse(row.state_json); } catch {}
  return { state, updatedAt: row.updated_at };
}
function putUserState(userId, ns, state, updatedAt = Date.now()) {
  const json = JSON.stringify(state ?? {});
  stmtPutState.run(userId, normalizeNS(ns), json, Number(updatedAt) || Date.now());
  return true;
}
function listUserNamespaces(userId) {
  return stmtListNamespaces.all(userId).map(r => ({ ns: r.ns, updatedAt: r.updated_at }));
}
function deleteUserState(userId, ns) {
  const info = stmtDeleteState.run(userId, normalizeNS(ns));
  return info.changes > 0;
}

// ─────────────────────────────────────────────────────────────
// Email-first State APIs (single namespace = email)
// ─────────────────────────────────────────────────────────────
function getUserEmailById(id) {
  const r = stmtGetUserById.get(Number(id));
  return r ? normalizeEmail(r.email) : null;
}
function getStateByEmail(email) {
  const u = stmtGetUserByEmail.get(normalizeEmail(email));
  if (!u) return null;
  const row = stmtGetState.get(u.id, normalizeEmail(email));
  if (!row) return null;
  let state = null; try { state = JSON.parse(row.state_json); } catch {}
  return { state, updatedAt: row.updated_at };
}
function putStateByEmail(email, state, updatedAt = Date.now()) {
  const u = stmtGetUserByEmail.get(normalizeEmail(email));
  if (!u) return false;
  const json = JSON.stringify(state ?? {});
  stmtPutState.run(u.id, normalizeEmail(email), json, Number(updatedAt) || Date.now());
  return true;
}
function deleteAllStatesForUser(userId) {
  stmtDeleteAllStatesForUser.run(Number(userId));
  return true;
}

// ─────────────────────────────────────────────────────────────
// Web Push storage
// ─────────────────────────────────────────────────────────────
function addPushSubscription(ns, sub){
  db.prepare(`INSERT INTO push_subscriptions (ns, endpoint, json, created_at)
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
  return db.prepare(`SELECT endpoint, json FROM push_subscriptions WHERE ns=LOWER(?)`)
           .all(String(ns||'').toLowerCase());
}
function seenPushEvent(evKey, ttlMs=1000*60*60*24){
  const now = Date.now();
  const row = db.prepare(`SELECT ts FROM push_events WHERE ev_key=?`).get(evKey);
  if (row && (now - Number(row.ts||0) < ttlMs)) return true;
  db.prepare(`INSERT INTO push_events (ev_key, ts) VALUES (?, ?)
              ON CONFLICT(ev_key) DO UPDATE SET ts=excluded.ts`).run(evKey, now);
  return false; // false이면 이번이 최초 발사
}

// ─────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────
function withTransaction(fn) {
  const tx = db.transaction(fn);
  return tx();
}

// ─────────────────────────────────────────────────────────────
// Exports (단일 블록)
// ─────────────────────────────────────────────────────────────
module.exports = {
  // raw
  db,

  // users
  createUser,
  getUserByEmail,
  getUserById,
  updateUserProfile,

  // states (legacy ns)
  getUserState,
  putUserState,
  listUserNamespaces,
  deleteUserState,

  // email-first
  getUserEmailById,
  getStateByEmail,
  putStateByEmail,
  deleteAllStatesForUser,

  // push
  addPushSubscription,
  removePushSubscription,
  listPushSubscriptions,
  seenPushEvent,

  // util
  withTransaction,
};
