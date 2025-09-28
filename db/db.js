// file: db.js
// ─────────────────────────────────────────────────────────────
// Single source of truth for SQLite access & app data models.
// - Users table: id / email / pw_hash / display_name / avatar_url
// - User states: (user_id, ns) → JSON state with updated_at
// - Push: push_subscriptions(ns, endpoint) / push_events(ev_key)
// - Ready for express-session store sharing (same DB file OK)
// ─────────────────────────────────────────────────────────────

const path = require("path");
const Sqlite = require("better-sqlite3");

// ─────────────────────────────────────────────────────────────
// DB Open & Pragmas
// ─────────────────────────────────────────────────────────────
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), ".data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "app.db");
const db = new Sqlite(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("synchronous = NORMAL");
db.pragma("busy_timeout = 5000");

// ─────────────────────────────────────────────────────────────
/** Schema (최신 스키마 기준으로 CREATE) */
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
const stmtGetUserIdByEmail = db.prepare(`
  SELECT id FROM users WHERE email = LOWER(?) LIMIT 1
`);
const stmtDeleteAllStatesForUser = db.prepare(`
  DELETE FROM user_states WHERE user_id = ?
`);

// ─────────────────────────────────────────────────────────────
// User APIs
// ─────────────────────────────────────────────────────────────

/**
 * Create user (email must be unique & already validated).
 * Sets display_name default to email local-part to avoid "member".
 */
function createUser(email, pwHash) {
  const createdAt = Date.now();
  const normEmail = normalizeEmail(email);
  const info = stmtInsertUser.run(normEmail, pwHash, createdAt);
  const userId = Number(info.lastInsertRowid);

  // 기본 display_name = 이메일 로컬파트
  try {
    const local = String(normEmail).split("@")[0] || "user";
    db.prepare(
      `UPDATE users
         SET display_name = COALESCE(display_name, ?)
       WHERE id = ?
         AND (display_name IS NULL OR TRIM(display_name) = '')`
    ).run(local, userId);
  } catch {}

  return userId;
}

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
 * null/undefined는 기존 값 유지(COALESCE)
 */
function updateUserProfile(userId, { displayName = null, avatarUrl = null } = {}) {
  stmtUpdateProfile.run(displayName ?? null, avatarUrl ?? null, userId);
  return true;
}

// ─────────────────────────────────────────────────────────────
// User State APIs (namespace-based persistent snapshots)
// ─────────────────────────────────────────────────────────────
function getUserState(userId, ns) {
  const key = normalizeNS(ns);
  const row = stmtGetState.get(userId, key);
  if (!row) return null;
  let state = null;
  try { state = JSON.parse(row.state_json); } catch {}
  return { state, updatedAt: row.updated_at };
}
function putUserState(userId, ns, state, updatedAt = Date.now()) {
  const key = normalizeNS(ns);
  const json = JSON.stringify(state ?? {});
  stmtPutState.run(userId, key, json, Number(updatedAt) || Date.now());
  return true;
}
function listUserNamespaces(userId) {
  return stmtListNamespaces.all(userId).map(r => ({ ns: r.ns, updatedAt: r.updated_at }));
}
function deleteUserState(userId, ns) {
  const key = normalizeNS(ns);
  const info = stmtDeleteState.run(userId, key);
  return info.changes > 0;
}

// ─────────────────────────────────────────────────────────────
// Email-first State APIs
// ─────────────────────────────────────────────────────────────
function getUserEmailById(id) {
  const row = stmtGetUserById.get(Number(id));
  return row ? normalizeEmail(row.email) : null;
}
function getStateByEmail(email) {
  const user = stmtGetUserByEmail.get(normalizeEmail(email));
  if (!user) return null;
  const row = stmtGetState.get(user.id, normalizeEmail(email));
  if (!row) return null;
  let state = null;
  try { state = JSON.parse(row.state_json); } catch {}
  return { state, updatedAt: row.updated_at };
}
function putStateByEmail(email, state, updatedAt = Date.now()) {
  const user = stmtGetUserByEmail.get(normalizeEmail(email));
  if (!user) return false;
  const json = JSON.stringify(state ?? {});
  stmtPutState.run(user.id, normalizeEmail(email), json, Number(updatedAt) || Date.now());
  return true;
}
function deleteAllStatesForUser(userId) {
  stmtDeleteAllStatesForUser.run(Number(userId));
  return true;
}

// ─────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────
function withTransaction(fn) {
  const tx = db.transaction(fn);
  return tx();
}

// 멱등: 이메일이 없거나 유저가 없어도 true
function deleteAllStatesForEmail(email) {
  try {
    const norm = normalizeEmail(email);
    if (!norm) return true;
    const row = stmtGetUserIdByEmail.get(norm);
    if (!row || !row.id) return true;
    stmtDeleteAllStatesForUser.run(row.id);
    return true;
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────
// Hard delete user (with cascade) + push cleanup
// ─────────────────────────────────────────────────────────────
function deleteUser(userId) {
  userId = Number(userId);
  if (!Number.isFinite(userId)) return false;

  return withTransaction(() => {
    try {
      // 이메일 확보(why: ns 기반 리소스 정리)
      const urow = stmtGetUserById.get(userId);
      const email = urow ? normalizeEmail(urow.email) : "";

      // 상태/구독 선정리(멱등)
      try { deleteAllStatesForUser(userId); } catch {}
      try { if (email) deletePushSubscriptionsByNS(email); } catch {}

      const info = db.prepare(`DELETE FROM users WHERE id=?`).run(userId);
      return info.changes > 0;
    } catch {
      return false;
    }
  });
}

// ─────────────────────────────────────────────────────────────
// Push storage
// ─────────────────────────────────────────────────────────────
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

function addPushSubscription(ns, sub) {
  db.prepare(`
    INSERT INTO push_subscriptions (ns, endpoint, json, created_at)
    VALUES (LOWER(?), ?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET
      json = excluded.json,
      created_at = excluded.created_at
  `).run(String(ns||'').toLowerCase(), sub.endpoint, JSON.stringify(sub), Date.now());
  return true;
}
function removePushSubscription(endpoint) {
  db.prepare(`DELETE FROM push_subscriptions WHERE endpoint=?`).run(endpoint);
  return true;
}
function listPushSubscriptions(ns) {
  return db.prepare(`SELECT endpoint, json FROM push_subscriptions WHERE ns=LOWER(?)`)
           .all(String(ns||'').toLowerCase());
}
function seenPushEvent(evKey, ttlMs = 1000*60*60*24) {
  const now = Date.now();
  const row = db.prepare(`SELECT ts FROM push_events WHERE ev_key=?`).get(evKey);
  if (row && (now - Number(row.ts || 0) < ttlMs)) return true;
  db.prepare(`
    INSERT INTO push_events (ev_key, ts) VALUES (?, ?)
    ON CONFLICT(ev_key) DO UPDATE SET ts=excluded.ts
  `).run(evKey, now);
  return false; // false면 '이번에 처음' == 발사 OK
}
function deletePushSubscriptionsByNS(ns) {
  db.prepare(`DELETE FROM push_subscriptions WHERE ns=LOWER(?)`).run(String(ns||'').toLowerCase());
  return true;
}

// ─────────────────────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────────────────────
module.exports = {
  // raw handle (e.g., for session store)
  db,

  // users
  createUser,
  getUserByEmail,
  getUserById,
  updateUserProfile,
  deleteUser,

  // states
  getUserState,
  putUserState,
  listUserNamespaces,
  deleteUserState,
  deleteAllStatesForEmail,
  deleteAllStatesForUser,
  putStateByEmail,

  // util
  withTransaction,

  // push
  addPushSubscription,
  removePushSubscription,
  listPushSubscriptions,
  seenPushEvent,
  deletePushSubscriptionsByNS,
};
