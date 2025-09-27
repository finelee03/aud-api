// server.js  — clean, consolidated (+ fallback social routes installed safely)
const path = require("path");
const fs = require("fs");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const SqliteStoreFactory = require("better-sqlite3-session-store");
const Sqlite = require("better-sqlite3");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const argon2 = require("argon2");
const { z } = require("zod");
const { v4: uuid } = require("uuid");
const compression = require("compression");
const sharp = require("sharp");
require("dotenv").config();

const DATA_DIR =
  process.env.DATA_DIR ||
  process.env.RENDER_DISK_PATH ||          // (선택) 직접 주입한 디스크 경로
  (fs.existsSync("/var/data") ? "/var/data" : "/tmp"); // Render 디스크 없으면 /tmp
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

// === Admin config & seeding ===
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "finelee03@naver.com")
  .split(",").map(s => String(s || "").trim().toLowerCase()).filter(Boolean);
const ADMIN_SEED_PASSWORD = process.env.ADMIN_SEED_PASSWORD || "dlghkdls398!a"; // 반드시 환경변수로 옮기세요.

function isAdminEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  return ADMIN_EMAILS.includes(e);
}

async function seedAdminUsers() {
  try {
    for (const email of ADMIN_EMAILS) {
      const hit = getUserByEmail?.(email);
      if (hit) continue;
      const hash = await argon2.hash(ADMIN_SEED_PASSWORD);
      const uid = createUser(email, hash);
      console.log(`[admin] seeded admin user ${email} (id=${uid})`);
    }
  } catch (e) {
    console.warn("[admin] seed failed:", e?.message || e);
  }
}

const {
  db, createUser, getUserByEmail, getUserById,
  getUserState, putUserState,
  getUserEmailById, getStateByEmail, putStateByEmail, deleteAllStatesForUser,
  migrateAllUserStatesToEmail, // ★ 추가: 이메일 NS 마이그레이션
} = require("./db");

  seedAdminUsers();

let startBleBridge = null;
try {
  ({ startBleBridge } = require("./ble-bridge"));
} catch {
  // optional module
}

function findFirstExisting(dir, id, exts) {
  for (const e of exts) {
    const p = path.join(dir, `${id}.${e}`);
    if (fs.existsSync(p)) return e;
  }
  return null;
}

// ──────────────────────────────────────────────────────────
// 기본 셋업
// ──────────────────────────────────────────────────────────

// 2) 부팅 시 조건부 마이그레이션 훅 추가 (hardResetOnBoot 호출 부근에 배치)
function migrateEmailNsOnBoot() {
  // why: 운영에선 명시 opt-in, 개발에선 안전 기본 off
  const want =
    process.env.MIGRATE_EMAIL_NS_ON_BOOT === "1" ||
    (process.env.NODE_ENV !== "production" && process.env.MIGRATE_EMAIL_NS_ON_BOOT === "dev");
  if (!want) return;

  try {
    if (typeof migrateAllUserStatesToEmail !== "function") {
      console.log("[MIGRATE] skip: migrateAllUserStatesToEmail not available");
      return;
    }
    console.log("[MIGRATE] consolidating user_states to email namespace...");
    const stats = migrateAllUserStatesToEmail();
    // 표 형태 요약
    try {
      // console.table 이 없는 환경도 있으니 안전 호출
      console.table?.(stats);
    } catch {}
    console.log("[MIGRATE] done:", stats);
  } catch (e) {
    console.error("[MIGRATE] failed:", e?.stack || e);
  }
}


function hardResetOnBoot() {
  try {
    // 프로덕션이 아니면 기본 초기화, 프로덕션에서는 opt-in
    const want =
      (process.env.NODE_ENV !== 'production' && process.env.HARD_RESET_ON_BOOT !== '0')
      || process.env.HARD_RESET_ON_BOOT === '1';
    if (!want) return;
    console.log('[BOOT] HARD_RESET_ON_BOOT=1 → wiping server-side state...');
    // 1) 앱 상태(DB 내 user_states / votes / likes 등)
    try { db.exec('DELETE FROM user_states'); } catch {}
    try { db.exec('DELETE FROM item_votes'); } catch {}
    try { db.exec('DELETE FROM item_likes'); } catch {}
    try { db.exec('DELETE FROM items'); } catch {}
    // 2) 업로드 파일들 (유저별 갤러리 / audlab / 아바타)
    try { rmrfSafe(UPLOAD_ROOT); fs.mkdirSync(UPLOAD_ROOT, { recursive:true }); } catch {}
    try { rmrfSafe(AVATAR_DIR);  fs.mkdirSync(AVATAR_DIR,  { recursive:true }); } catch {}
    try { rmrfSafe(USER_AUDLAB_ROOT); fs.mkdirSync(USER_AUDLAB_ROOT, { recursive:true }); } catch {}
    // 3) 세션 저장소도 날려서 모든 로그인 무효화
    try {
      if (fs.existsSync(SESSION_DB_PATH)) fs.rmSync(SESSION_DB_PATH, { force:true });
    } catch {}
    console.log('[BOOT] hard reset done.');
  } catch (e) {
    console.log('[BOOT] hard reset failed:', e?.message || e);
  }
}

/** 재귀 디렉토리 제거(존재해도/없어도 안전) */
function rmrfSafe(dir) {
  try { if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

/** 단일 유저의 모든 데이터 정리 (best-effort) */
function purgeAllUserData(uid) {
  if (!uid) return;
  try {
    let email = null;
    try { email = String(getUserEmailById(uid) || '').toLowerCase(); } catch {}
    // 1) 상태/소셜/좋아요 등 레코드 제거
    try { db.prepare('DELETE FROM user_states WHERE user_id=?').run(uid); } catch {}
    try { db.prepare('DELETE FROM item_likes  WHERE user_id=?').run(uid); } catch {}
    try { db.prepare('DELETE FROM item_votes  WHERE user_id=?').run(uid); } catch {}
    try { db.prepare('DELETE FROM items       WHERE user_id=?').run(uid); } catch {}
    try { db.prepare('DELETE FROM avatars     WHERE user_id=?').run(uid); } catch {}

    // 2) 파일 시스템(업로드/오디오랩)
    try { rmrfSafe(path.join(UPLOAD_ROOT, String(uid))); } catch {}
    if (email) {
      try { rmrfSafe(path.join(UPLOAD_ROOT, encodeURIComponent(email))); } catch {}
      try { rmrfSafe(path.join(USER_AUDLAB_ROOT, encodeURIComponent(email))); } catch {}
    }
  } catch {}
}

// 2) /auth/me 응답에 emailNS 추가(레거시 ns=uid는 유지)
function meHandler(req, res) {
  sendNoStore(res);
  const base = statusPayload(req);
  if (!base.authenticated) return res.json(base);

  const u = getUserById(req.session.uid);

  // display_name 안전 조회
  let displayName = null;
  try {
    const cols = db.prepare("PRAGMA table_info(users)").all().map(r => String(r.name));
    if (cols.includes("display_name")) {
      const r = db.prepare("SELECT display_name FROM users WHERE id=?").get(req.session.uid);
      displayName = r?.display_name || null;
    }
  } catch {}

  const avatarUrl = latestAvatarUrl(req.session.uid);
  const emailNS = getNS(req); // ← 이메일 기반 NS (서버가 강제)

  const payload = {
    ...base,
    user: u ? { id: u.id, email: u.email, displayName } : null,
    ns: String(req.session.uid),            // 레거시(FE가 uid를 기대하던 경우)
    emailNS,                                // ✅ 신규: FE는 이 값을 실제 NS로 사용
  };
  if (u) {
    payload.email = u.email;
    payload.displayName = displayName;
    payload.name = displayName;
    payload.avatarUrl = avatarUrl;
  }
  return res.json(payload);
}

/** 계정 삭제 공통 처리 */
function deleteMyAccount(req, res) {
  if (!req.session?.uid) return res.status(401).json({ ok:false });
  const uid = Number(req.session.uid);
  try { deleteAllStatesForUser(uid); } catch {}
  try { purgeAllUserData(uid); } catch {}
  try { db.prepare("DELETE FROM users WHERE id=?").run(uid); } catch {}
  const clearOpts = { path:"/", sameSite: "lax", secure: process.env.NODE_ENV==="production" };
  const sidName = process.env.NODE_ENV === "production" ? "__Host-sid" : "sid";
  const done = () => {
    try { res.clearCookie(sidName, clearOpts); } catch {}
    try { res.clearCookie(process.env.NODE_ENV==="production" ? "__Host-csrf" : "csrf", clearOpts); } catch {}
    return res.status(204).end();
  };
  return req.session ? req.session.destroy(done) : done();
}

// ── Writable upload roots (moved off read-only app dir) ─────────────
const UPLOAD_ROOT = process.env.UPLOAD_ROOT || path.join(DATA_DIR, "uploads");
try { fs.mkdirSync(UPLOAD_ROOT, { recursive: true }); } catch {}
process.env.UPLOAD_ROOT = UPLOAD_ROOT; // 하위 라우터/모듈과 공유

const AVATAR_DIR = path.join(UPLOAD_ROOT, "avatars");
try { fs.mkdirSync(AVATAR_DIR, { recursive: true }); } catch {}

const USER_AUDLAB_ROOT = path.join(UPLOAD_ROOT, "audlab");
try { fs.mkdirSync(USER_AUDLAB_ROOT, { recursive: true }); } catch {}


const BOOT_ID = uuid();
const app = express();
app.set('trust proxy', 1);

function ensureUserAudlabDir(req) {
  const ns = getNS(req); // ← 로그인 사용자의 이메일(소문자) 반환
  if (!ns) return null;
  const dir = path.join(USER_AUDLAB_ROOT, encodeURIComponent(ns));
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  return { ns, dir };
}

const server = http.createServer(app);

// Frontend가 다른 오리진(예: GitHub Pages)일 때 CORS 허용
const CROSS_SITE = /^(1|true|yes|on)$/i.test(process.env.CROSS_SITE || "");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim().replace(/\/$/, "").toLowerCase())
  .filter(Boolean);

// CSP: connect-src 동적 구성 (self + ws/wss + 허용 오리진)
const connectSrc = ["'self'", "ws:", "wss:", ...ALLOWED_ORIGINS];

const ENABLE_IO_CORS = CROSS_SITE || ALLOWED_ORIGINS.length > 0;
const io = new Server(server, {
  path: "/socket.io",
  ...(ENABLE_IO_CORS && {
    cors: {
      origin(origin, cb) {
        if (!origin) return cb(null, true);
        if (!ALLOWED_ORIGINS.length) return cb(null, true);
        const o = String(origin || "").replace(/\/$/, "").toLowerCase();
        cb(null, !ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(o));
      },
      credentials: true,
      methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    }
  })
});

const ITEM_OWNER_NS = new Map();

const PORT = process.env.PORT || 8787;
const PUBLIC_DIR = path.join(__dirname, "public");
const PROD = process.env.NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET || "810b135542bc33386aa6018125d3b6df";
const NAV_TTL_MS = Number(process.env.NAV_TTL_MS || 10000);

// 최근 내비게이션 마킹
function markNavigate(req) {
  try { req.session.navAt = Date.now(); req.session.save?.(()=>{}); } catch {}
}
function isRecentNavigate(req) {
  const t = Number(req.session?.navAt || 0);
  return t && (Date.now() - t) < NAV_TTL_MS;
}

// 존재할 때만 조용히 장착되는 라우터 유틸
function mountIfExists(basePath, mountPath = "/api") {
  try {
    const r = require(basePath);
    if (typeof r === "function") {
      app.use(mountPath, r);
      console.log(`[router] mounted ${basePath} at ${mountPath}`);
    }
  } catch (e) {
    if (e && e.code === "MODULE_NOT_FOUND") {
      console.log(`[router] skip (not found): ${basePath}`);
    } else {
      console.log(`[router] error mounting ${basePath}:`, e?.message || e);
    }
  }
}

// minimal resolver used by feed routes (no push)
function resolvePushNS(ns) {
  const raw = String(ns || "").trim().toLowerCase();
  if (!raw) return "";
  const isEmail = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(raw);
  if (isEmail) return raw;
  const v = raw.startsWith("user:") ? raw.slice(5) : raw;
  if (/^\d+$/.test(v)) {
    try {
      const row = getUserById ? getUserById(Number(v)) : null;
      const email = String(row?.email || "").trim().toLowerCase();
      if (email) return email;
    } catch {}
  }
  return raw;
}
// ── Allowed MIME lists (images & audio via dataURL) ─────────────────
const ALLOWED_IMAGE_MIMES = new Set([
  "image/png",
  "image/jpeg", "image/jpg",
  "image/webp",
  "image/gif",
]);

const ALLOWED_AUDIO_MIMES = new Set([
  "audio/webm;codecs=opus",
  "audio/webm",
  "audio/ogg;codecs=opus",
  "audio/ogg",
  "audio/mpeg",  // mp3
  "audio/wav",
  "audio/x-wav",
  "audio/mp4",
  "audio/aac",
]);

function isAllowedImageMime(mime) {
  const m = String(mime || "").toLowerCase();
  const base = m.split(";")[0];
  return ALLOWED_IMAGE_MIMES.has(m) || ALLOWED_IMAGE_MIMES.has(base);
}
function isAllowedAudioMime(mime) {
  const m = String(mime || "").toLowerCase();
  const base = m.split(";")[0];
  return ALLOWED_AUDIO_MIMES.has(m) || ALLOWED_AUDIO_MIMES.has(base);
}

// ──────────────────────────────────────────────────────────
// 업로드 준비 (메모리 → 디스크 저장)
// ──────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
});
// 파일시스템 기반 퍼블릭 피드 폴백 라우트를 항상 장착
process.env.FORCE_FALLBACK_PUBLIC = process.env.FORCE_FALLBACK_PUBLIC || "1";
process.env.FORCE_FALLBACK_ITEMS  = process.env.FORCE_FALLBACK_ITEMS  || "1";
fs.mkdirSync(UPLOAD_ROOT, { recursive: true });
function ensureDir(dir) { try { fs.mkdirSync(dir, { recursive: true }); } catch {} }

// dataURL(base64) → Buffer 디코더 (image + audio 지원)
function decodeDataURL(dataURL) {
  const m = String(dataURL || "").match(/^data:([a-z0-9.+/-]+);base64,(.+)$/i);
  if (!m) return null;
  const mime = m[1].toLowerCase();
  const buf  = Buffer.from(m[2], "base64");

  // mime → 확장자 매핑
  const map = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",

    // 오디오
    "audio/webm;codecs=opus": "webm",
    "audio/webm": "webm",
    "audio/ogg": "ogg",
    "audio/ogg;codecs=opus": "ogg",
    "audio/mpeg": "mp3",
    "audio/wav": "wav",
    "audio/x-wav": "wav",
    "audio/mp4": "m4a",
    "audio/aac": "aac",
  };

  // 불특정 파라미터가 붙어도 base mime으로 매핑
  const baseMime = mime.split(";")[0];
  const ext =
    map[mime] || map[baseMime] ||
    (baseMime.startsWith("image/") ? baseMime.split("/")[1] : null) ||
    (baseMime.startsWith("audio/") ? baseMime.split("/")[1] : null) ||
    "bin";

  return { mime, buf, ext };
}

// NS 추출(세션 강제) — 클라가 보낸 ns는 전부 무시
function getNS(req) {
  const uid = Number(req.session?.uid || 0);
  if (!uid) return "";
  try {
    const email = getUserEmailById(uid);
    return email || "";
  } catch { return ""; }
}


// ──────────────────────────────────────────────────────────
// 보안/미들웨어
// ──────────────────────────────────────────────────────────
app.disable("x-powered-by");

// ── CORS (교차 출처 프런트 허용) ───────────────────────────────
if (CROSS_SITE) {
  const corsOptions = {
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (!ALLOWED_ORIGINS.length) return cb(null, true);
      cb(null, ALLOWED_ORIGINS.includes(String(origin || '').replace(/\/$/, '').toLowerCase()));
    },
    credentials: true,
    methods: ["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"],
    allowedHeaders: ["Content-Type","X-CSRF-Token","x-csrf-token","X-XSRF-Token","x-xsrf-token"],
    maxAge: 86400,
  };
  app.use(cors(corsOptions));
  app.options(/.*/, cors(corsOptions));
}

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "https://fonts.googleapis.com"],
        "style-src-elem": ["'self'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
        "connect-src": connectSrc,
        "frame-ancestors": ["'none'"],
        "img-src": [
          "'self'", "data:", "blob:",
          ...((process.env.WEB_ORIGIN || process.env.ALLOWED_ORIGINS || "")
              .split(",").map(s => s.trim()).filter(Boolean))
        ],
        "media-src": [
          "'self'", "data:", "blob:",
          ...((process.env.WEB_ORIGIN || process.env.ALLOWED_ORIGINS || "")
              .split(",").map(s => s.trim()).filter(Boolean))
        ],
        "worker-src": ["'self'", "blob:"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(express.json({ limit: "5mb" }));
const bigJson = express.json({ limit: "30mb" }); // audlab 전용
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(SESSION_SECRET)); // CSRF(cookie 모드) 서명용
// why: 오디오는 압축 대상 제외(스트리밍/Range와 충돌 방지)
app.use(compression({
  filter: (req, res) => {
    const ct = String(res.getHeader("Content-Type")||"").toLowerCase();
    if (ct.startsWith("audio/")) return false;
    return compression.filter(req, res);
  }
}));                // 응답 압축

// 세션
const SqliteStore = SqliteStoreFactory(session);
const SESSION_DB_PATH =
  process.env.SESSION_DB_PATH ||
  path.join(DATA_DIR, "sessions.sqlite");
const sessionDB = new Sqlite(SESSION_DB_PATH);
const MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7;        // 7일(ms)
const MAX_AGE_SEC = Math.floor(MAX_AGE_MS / 1000); // 7일(sec)

const sessionMiddleware = session({
  store: new SqliteStore({
    client: sessionDB,
    expired: { clear: true, intervalMs: 15 * 60 * 1000 },
    ttl: MAX_AGE_SEC,
  }),
  name: PROD ? "__Host-sid" : "sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true, // 활동 시 만료 갱신
  cookie: {
    httpOnly: true,
    sameSite: CROSS_SITE ? "none" : "lax",
    secure: PROD || CROSS_SITE,
    path: "/",
    maxAge: MAX_AGE_MS,
    ...(CROSS_SITE ? { partitioned: true } : {}), // ★ CHIPS
  },
});
app.use(sessionMiddleware);


// CSRF (쿠키 모드)
const CSRF_COOKIE_NAME = PROD ? "__Host-csrf" : "csrf";
const csrfProtection = csrf({
  cookie: {
    key: CSRF_COOKIE_NAME,
    httpOnly: true,
    sameSite: CROSS_SITE ? "none" : "lax",
    secure: PROD || CROSS_SITE,
    path: "/",
    signed: true,
    ...(CROSS_SITE ? { partitioned: true } : {}), // ← CHIPS 대응 (세션과 동일)
  },
  // 헤더(x-csrf-token) 외에 쿼리/바디의 csrf, _csrf도 허용 (레거시 호환)
  value: (req) =>
    req.get("x-csrf-token") ||
    req.headers["x-xsrf-token"] ||
    (req.body && (req.body._csrf || req.body.csrf)) ||
    (req.query && (req.query._csrf || req.query.csrf)),
});

// 유틸 미들웨어
function ensureAuth(req, res, next) {
  if (req.session?.uid) return next();

  const wantsJSON =
    req.path.startsWith("/api") ||
    (req.get("accept") || "").includes("application/json");

  if (wantsJSON) return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
  const nextUrl = req.originalUrl || "/";
  return res.redirect("/login.html?next=" + encodeURIComponent(nextUrl));
}
function requireLogin(req, res, next) {
  if (req.session?.uid) return next();
  res.status(401).json({ ok: false, error: "auth_required" });
}
function getUserRowOrNull(uid) {
  try { return getUserById ? getUserById(uid) : null; } catch { return null; }
}
function requireAdmin(req, res, next) {
  if (!req.session?.uid) return res.status(401).json({ ok:false, error:"auth_required" });
  const row = getUserRowOrNull(req.session.uid);
  if (row && isAdminEmail(row.email)) return next();
  return res.status(403).json({ ok:false, error:"forbidden" });
}
function sendNoStore(res) { res.set("Cache-Control", "no-store"); }
function statusPayload(req) {
  const authed = !!(req.session && req.session.uid);
  return {
    ok: true,
    authenticated: authed,
    bootId: BOOT_ID,
    expires: authed ? req.session.cookie.expires : null,
  };
}

// 입력 검증

// ──────────────────────────────────────────────────────────
// [ADD] 프로필/비밀번호 변경 유틸 + 스키마 + 핸들러
// ──────────────────────────────────────────────────────────

// users 테이블 컬럼 캐시
let _userColsCacheTs = 0, _userColsCache = null;
function userCols() {
  const now = Date.now();
  if (_userColsCache && (now - _userColsCacheTs < 10_000)) return _userColsCache;
  try {
    const rows = db.prepare("PRAGMA table_info(users)").all();
    _userColsCache = new Set(rows.map(r => String(r.name)));
    _userColsCacheTs = now;
  } catch { _userColsCache = new Set(); }
  return _userColsCache;
}

// pw_hash / pwHash 자동 감지
function pwHashColName() {
  const cols = userCols();
  if (cols.has("pw_hash")) return "pw_hash";
  if (cols.has("pwHash"))  return "pwHash";
  return "pw_hash";
}

// display_name 컬럼 없으면 추가
function ensureDisplayNameColumn() {
  const cols = userCols();
  if (!cols.has("display_name")) {
    try {
      db.prepare("ALTER TABLE users ADD COLUMN display_name TEXT").run();
      _userColsCache = null; // 캐시 무효화
    } catch { /* 이미 있거나 ALTER 불가 → 무시 */ }
  }
}
// ──────────────────────────────────────────────────────────
// Public profile helpers
// ──────────────────────────────────────────────────────────
const AVATAR_TTL_MS = 10_000; // 간단 캐시
const _avatarCache = new Map(); // uid -> { url, t }

function latestAvatarUrl(uid) {
  try {
    const k = String(uid);
    const now = Date.now();
    const hit = _avatarCache.get(k);
    if (hit && now - hit.t < AVATAR_TTL_MS) return hit.url;

    const files = fs.readdirSync(AVATAR_DIR)
      .filter(f => f.startsWith(`${k}-`) && /\.(webp|png|jpe?g|gif)$/i.test(f));

    if (!files.length) { _avatarCache.set(k, { url: null, t: now }); return null; }

    files.sort((a,b) => {
      const ta = Number((a.split("-")[1] || "").split(".")[0]) || 0;
      const tb = Number((b.split("-")[1] || "").split(".")[0]) || 0;
      return tb - ta;
    });
    const url = `/uploads/avatars/${files[0]}`;
    _avatarCache.set(k, { url, t: now });
    return url;
  } catch { return null; }
}

function getDisplayNameById(uid) {
  try {
    ensureDisplayNameColumn();
    const r = db.prepare("SELECT display_name FROM users WHERE id=?").get(uid);
    return r?.display_name || null;
  } catch { return null; }
}

function publicUserShape(viewerUid, userRow) {
  if (!userRow) return null;
  const self   = String(userRow.id) === String(viewerUid);
  const email  = String(userRow.email || "");
  const masked = self ? email : (email ? email.replace(/^(.).+(@.*)$/, "$1***$2") : null);

  // 1차: DB display_name → 2차: 이메일 local-part
  const dn = getDisplayNameById(userRow.id) || (email ? email.split("@")[0] : null);

  return {
    id: userRow.id,
    displayName: dn,
    avatarUrl: latestAvatarUrl(userRow.id),
    email: masked,
  };
}

function authorProfileShape(userRow) {
  if (!userRow) return null;
  const email = String(userRow.email || "");
  const displayName =
    (typeof getDisplayNameById === "function" ? getDisplayNameById(userRow.id) : null)
    || (email ? email.split("@")[0] : null);
  return {
    id: userRow.id,
    email,                     // ← 작성자용: 마스킹 없음
    displayName,
    avatarUrl: latestAvatarUrl(userRow.id)
  };
}

// 현재 비밀번호 해시 읽기/쓰기
function getUserPwHash(uid) {
  try {
    const col = pwHashColName();
    const row = db.prepare(`SELECT ${col} AS pwHash FROM users WHERE id=?`).get(uid);
    return row?.pwHash || null;
  } catch { return null; }
}
function setUserPassword(uid, newHash) {
  const col = pwHashColName();
  const info = db.prepare(`UPDATE users SET ${col}=? WHERE id=?`).run(newHash, uid);
  return info.changes > 0;
}

// display_name 쓰기
function setUserDisplayName(uid, name) {
  ensureDisplayNameColumn();
  const info = db.prepare("UPDATE users SET display_name=? WHERE id=?").run(name, uid);
  return info.changes > 0;
}

// Zod 스키마 (여러 FE 호환)
const PwChange = z.object({
  currentPassword: z.string().min(1).max(200),
  newPassword: z.string().min(8).max(200)
}).or(z.object({
  currentPassword: z.string().min(1).max(200),
  password: z.string().min(8).max(200) // 일부 클라가 newPassword 대신 password를 씀
}).transform(v => ({ currentPassword: v.currentPassword, newPassword: v.password })));

const NameChange = z.object({
  displayName: z.string().trim().min(1).max(60)
}).or(z.object({
  name: z.string().trim().min(1).max(60)
}).transform(v => ({ displayName: v.name })));

// 실제 처리기
async function applyPasswordChange(req, res) {
  const parsed = PwChange.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok:false, error:"INVALID" });

  const { currentPassword, newPassword } = parsed.data;
  const uid = req.session.uid;

  const currentHash = getUserPwHash(uid);
  if (!currentHash) return res.status(500).json({ ok:false, error:"NO_PWHASH" });

  const ok = currentHash && await argon2.verify(currentHash, currentPassword);
  if (!ok) return res.status(400).json({ ok:false, error:"BAD_CREDENTIALS" });

  const newHash = await argon2.hash(newPassword, {
    type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1,
  });
  setUserPassword(uid, newHash);
  return res.json({ ok:true });
}

function applyNameChange(req, res) {
  const parsed = NameChange.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok:false, error:"INVALID" });

  const displayName = parsed.data.displayName.trim();
  setUserDisplayName(req.session.uid, displayName);

  const u = getUserById(req.session.uid);
  const avatarUrl = latestAvatarUrl(req.session.uid);
  return res.json({ ok:true, user:{ id:u.id, email:u.email, displayName, avatarUrl } });
}

const EmailPw = z.object({
  email: z.string().email().max(200),
  password: z.string().min(8).max(200),
});

// ──────────────────────────────────────────────────────────
// 인증 라우트
// ──────────────────────────────────────────────────────────
// [NEW] Keepalive ping (GET) — same shape as /auth/me
app.get("/auth/ping", (req, res) => {
  sendNoStore(res);
  try {
    if (req.session) {
      req.session.lastPingAt = Date.now();
      if (typeof req.session.touch === "function") req.session.touch(); // rolling 보강
    }
  } catch {}
  // 읽기 가능한 부트마커 쿠키(선택)
  try { res.cookie('app_boot', BOOT_ID, { path:'/', sameSite: CROSS_SITE ? 'none':'lax', secure: PROD||CROSS_SITE }); } catch {}
  return res.json(statusPayload(req));
});


app.get("/auth/csrf", csrfProtection, (req, res) => {
  return res.json({ csrfToken: req.csrfToken() });
});

// 🔧 NEW: 클라 호환을 위한 GET 엔드포인트 추가
app.get("/auth/me", meHandler);

// (선택) 과거 코드 호환용 별칭
app.get("/api/users/me", meHandler);

app.post("/auth/signup", csrfProtection, async (req, res) => {
  const parsed = EmailPw.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: "INVALID" });

  const { email, password } = parsed.data;
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
  });

  try {
    const userId = createUser(email.toLowerCase(), hash);
    return res.status(201).json({ ok: true, id: userId });
  } catch (e) {
    return res.status(409).json({ ok: false, error: "DUPLICATE_EMAIL" });
  }
});

app.post("/auth/login", csrfProtection, async (req, res) => {
  const parsed = EmailPw.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: "INVALID" });

  const { email, password } = parsed.data;
  const row = getUserByEmail(email.toLowerCase());
  if (!row) return res.status(400).json({ ok: false, error: "NO_USER" });

  const ok = await argon2.verify(row.pwHash ?? row.pw_hash, password);
  if (!ok) return res.status(400).json({ ok: false, error: "BAD_CREDENTIALS" });

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ ok: false });
    req.session.uid = row.id;
    markNavigate(req);
    return res.json({ ok: true, id: row.id });
  });
});

app.post("/auth/nav", (req, res) => {
  if (req.session?.uid) markNavigate(req);
  return res.json({ ok: true });
});

// 명시적 로그아웃 (CSRF 필요)
app.post("/auth/logout", csrfProtection, (req, res) => {
  const name = PROD ? "__Host-sid" : "sid";
  const clearOpts = { path: "/", sameSite: CROSS_SITE ? "none" : "lax", secure: PROD || CROSS_SITE };
  const done = () => {
    res.clearCookie(name, clearOpts);
    res.clearCookie(CSRF_COOKIE_NAME, clearOpts);
    res.json({ ok: true });
  };
  return req.session ? req.session.destroy(done) : done();
});

// 마지막 탭 종료/비콘 로그아웃 (CSRF 없음)
app.post("/auth/logout-beacon", (req, res) => {
  const origin = req.get("origin");
  const host = req.get("host");
  const clearOpts = { path: "/", sameSite: CROSS_SITE ? "none" : "lax", secure: PROD || CROSS_SITE };
  if (origin) {
    try {
      const u = new URL(origin);
      if (u.host !== host) return res.status(403).json({ ok: false });
    } catch { /* malformed origin → 동오리진만 도달하므로 허용 */ }
  }
  if (isRecentNavigate(req)) {
    return res.json({ ok: true, skipped: "recent-nav" });
  }
  const name = PROD ? "__Host-sid" : "sid";
  if (!req.session?.uid) {
    res.clearCookie(name, clearOpts);
    res.clearCookie(CSRF_COOKIE_NAME, clearOpts);
    return res.json({ ok: true });
  }
  req.session.destroy(() => {
    res.clearCookie(name, clearOpts);
    res.clearCookie(CSRF_COOKIE_NAME, clearOpts);
    res.json({ ok: true });
  });
});

// 1) DELETE /auth/me  (정석)
app.delete("/auth/me", requireLogin, csrfProtection, (req, res) => {
  deleteMyAccount(req, res);
});

// 2) POST /auth/delete  (폴백; 일부 FE/프록시 환경 호환)
app.post("/auth/delete", requireLogin, csrfProtection, (req, res) => {
  deleteMyAccount(req, res);
});

// 3) POST /api/users/me  with {_method:"DELETE"} (추가 폴백)
app.post("/api/users/me", requireLogin, csrfProtection, (req, res) => {
  const m = String(req.body?._method || "").toUpperCase();
  if (m === "DELETE") return deleteMyAccount(req, res);
  return res.status(405).json({ ok:false, error:"method_not_allowed" });
});

app.post("/api/audlab/submit", requireLogin, bigJson, async (req, res) => {
  try {
    const slot = ensureUserAudlabDir(req);
    if (!slot) return res.status(400).json({ ok:false, error:"ns_unavailable" });

    const { ns, dir } = slot;
    const id = `lab_${Date.now()}`;

    // 1) PNG 저장 (previewDataURL 필수)
    const decodedImg = decodeDataURL(req.body?.previewDataURL || req.body?.thumbDataURL || "");
    if (!decodedImg || !/^image\//.test(decodedImg.mime) || !isAllowedImageMime(decodedImg.mime)) {
      return res.status(400).json({ ok:false, error:"bad_preview_mime" });
    }
    // (선택) dataURL 경로 용량 가드 — 8MB 정도 권장
    if (decodedImg.buf.length > 8 * 1024 * 1024) {
      return res.status(413).json({ ok:false, error:"image_too_large" });
    }

    const imgExt  = decodedImg.ext || "png";
    const imgMime = decodedImg.mime || "image/png";
    fs.writeFileSync(path.join(dir, `${id}.${imgExt}`), decodedImg.buf);

    // 2) (옵션) 오디오 저장
    let audioExt = null;
    let audioMime = null;
    if (req.body?.audioDataURL) {
      const decodedAud = decodeDataURL(req.body.audioDataURL);
      if (decodedAud && /^audio\//.test(decodedAud.mime)) {
        // ★ 화이트리스트 체크
        if (!isAllowedAudioMime(decodedAud.mime)) {
          return res.status(400).json({ ok:false, error:"bad_audio_mime" });
        }
        // (선택) dataURL 경로 용량 가드 — 12MB 정도 권장
        if (decodedAud.buf.length > 12 * 1024 * 1024) {
          return res.status(413).json({ ok:false, error:"audio_too_large" });
        }
        audioExt = decodedAud.ext || "webm";
        audioMime = decodedAud.mime || "audio/webm";
        fs.writeFileSync(path.join(dir, `${id}.${audioExt}`), decodedAud.buf);
      }
    }

    // 3) 메타 JSON 저장 (기존 그대로)
    const meta = {
      id, ns,
      width: Number(req.body?.width || 0),
      height: Number(req.body?.height || 0),
      strokes: Array.isArray(req.body?.strokes) ? req.body.strokes : [],
      author: (() => {
        const u = getUserById(req.session.uid);
        return u ? { id: u.id, email: u.email, displayName: getDisplayNameById(u.id), avatarUrl: latestAvatarUrl(u.id) } : null;
      })(),
      createdAt: Date.now(),
      ext: imgExt,
      mime: imgMime,
      ...(audioExt ? { audioExt, audioMime } : {}),
    };
    fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(meta));

    return res.json({
      ok: true,
      id, ns,
      json:  `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`,
      image: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${imgExt}`,
      ...(audioExt ? { audio: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${audioExt}` } : {}),
    });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"submit_failed" });
  }
});

/**
 * GET /api/audlab/list
 * 현재 로그인 사용자의 NS에서 최근 제출물 목록을 반환
 * 응답: { items: [{id,json,png}], ns }
 */
app.get("/api/audlab/list", requireLogin, (req, res) => {
  try {
    const slot = ensureUserAudlabDir(req);
    if (!slot) return res.status(400).json({ ok:false, error:"ns_unavailable" });
    const { ns, dir } = slot;

    const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
    const ids = files.filter(f => f.endsWith(".json")).map(f => f.replace(/\.json$/,""));

    // 최신순
    ids.sort((a,b) => (b > a ? 1 : -1));

    const items = ids.slice(0, 200).map(id => {
      // 이미지/오디오 실제 확장자 찾기
      const imgExt = findFirstExisting(dir, id, ["png","jpg","jpeg","webp","gif"]) || "png";
      const audExt = findFirstExisting(dir, id, ["webm","ogg","mp3","wav"]);
      return {
        id,
        json:  `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`,
        image: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${imgExt}`,
        ...(audExt ? { audio: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${audExt}` } : {})
      };
    });

    return res.json({ ok:true, ns, items });
  } catch {
    return res.status(500).json({ ok:false, error:"list_failed" });
  }
});

// ──────────────────────────────────────────────────────────
// Public profile endpoint
// ──────────────────────────────────────────────────────────
app.get("/api/users/:id/public", requireLogin, (req, res) => {
  try {
    let key = String(req.params.id || "");
    if (key === "me") key = String(req.session.uid);

    const row = (/^\d+$/.test(key))
      ? getUserById(Number(key))
      : getUserByEmail?.(key.toLowerCase());

    if (!row) return res.status(404).json({ ok:false, error:"not-found" });

    const profile = publicUserShape(req.session.uid, row);
    return res.json({ ok:true, profile });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"profile-failed" });
  }
});

// 선택: /api/users/me → /auth/me와 동일하게 돌려주고 싶다면
app.get("/api/users/me", requireLogin, (req, res) => meHandler(req, res));


app.post(
  "/api/users/me/avatar",
  requireLogin,
  csrfProtection,
  upload.any(), // avatar | file | image 등 어떤 필드명이 와도 받게
  async (req, res) => {
    const uid = req.session?.uid;
    if (!uid) return res.status(401).json({ ok:false, msg:"로그인이 필요합니다." });

    // 1) FormData 파일 찾기 (avatar, file, image, photo 우선)
    const files = Array.isArray(req.files) ? req.files : [];
    const picked =
      files.find(f => ["avatar","file","image","photo"].includes(f.fieldname)) ||
      files[0] || null;

    let buf = picked?.buffer || null;
    // 파일 mimetype 화이트리스트
    if (picked && !isAllowedImageMime(picked.mimetype)) {
      return res.status(400).json({ ok:false, msg:"bad_image_mime" });
    }


    // 2) 파일이 없으면 dataURL 폴백 (avatar/dataURL/dataUrl/avatarDataURL/thumbDataURL)
    if (!buf) {
      const raw =
        req.body?.avatar ||
        req.body?.dataURL ||
        req.body?.dataUrl ||
        req.body?.avatarDataURL ||
        req.body?.thumbDataURL || "";
      const decoded = decodeDataURL(raw);
      if (!decoded) {
        return res.status(400).json({ ok:false, msg:"파일이 없습니다." });
      }
      if (!/^image\//.test(decoded.mime) || !isAllowedImageMime(decoded.mime)) {
        return res.status(400).json({ ok:false, msg:"bad_image_mime" });
      }
      if (decoded.buf.length > 8 * 1024 * 1024) {
        return res.status(413).json({ ok:false, msg:"image_too_large" });
      }
      buf = decoded.buf;
    }

    if (!buf) return res.status(400).json({ ok:false, msg:"파일이 없습니다." });

    // 3) 정규화: 512x512 WebP
    let outBuf;
    try {
      outBuf = await sharp(buf)
        .rotate()
        .resize(512, 512, { fit: "cover" })
        .webp({ quality: 90 })
        .toBuffer();
    } catch (e) {
      return res.status(400).json({ ok:false, msg:"invalid_image" });
    }

    const filename = `${uid}-${Date.now()}.webp`;
    fs.writeFileSync(path.join(AVATAR_DIR, filename), outBuf);

    const avatarUrl = `/uploads/avatars/${filename}`;
    _avatarCache.set(String(uid), { url: avatarUrl, t: Date.now() });
    res.set("Cache-Control", "no-store");
    res.json({ ok:true, avatarUrl });
  }
);

app.use("/uploads", express.static(UPLOAD_ROOT, {
  setHeaders(res){
    res.set("Accept-Ranges", "bytes");
    res.set("Cache-Control", "public, max-age=31536000, immutable");
  }
}));

// === Admin-only endpoints (audlab) ===
const adminRouter = express.Router();
const AUDLAB_ROOT = USER_AUDLAB_ROOT; // 동일 루트 사용

const nsSafe = (s) => encodeURIComponent(String(s||"").trim().toLowerCase());

app.post("/admin/migrate/email-ns", requireAdmin, csrfProtection, (req, res) => {
  // why: 여러 FE/프록시에서 호출할 수 있게 JSON 결과 반환
  try {
    const stats = migrateAllUserStatesToEmail();
    return res.json({ ok: true, stats });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"migrate_failed", message: e?.message || String(e) });
  }
});

// 업로드된 NS 리스트
adminRouter.get("/admin/audlab/nses", requireAdmin, (req, res) => {
  try {
    const dirs = fs.readdirSync(AUDLAB_ROOT, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => decodeURIComponent(d.name))
      .sort();
    res.json({ ok:true, items: dirs });
  } catch {
    res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

// 특정 NS의 제출물 목록
adminRouter.get("/admin/audlab/list", requireAdmin, (req, res) => {
  try {
    const ns = String(req.query.ns || "").trim();
    if (!ns) return res.status(400).json({ ok:false, error:"ns_required" });

    const safeNs = nsSafe(ns);
    const dir = path.join(AUDLAB_ROOT, safeNs);
    try { fs.mkdirSync(dir, { recursive:true }); } catch {}

    const files = fs.readdirSync(dir)
      .filter(f => /\.json$/i.test(f))
      .sort()
      .reverse();

    const items = files.slice(0, 200).map(f => {
      const id = f.replace(/\.json$/i, "");

      // 이미지/오디오 확장자 탐색
      const imgExt = findFirstExisting(dir, id, ["png","jpg","jpeg","webp","gif"]) || "png";
      const audExt = findFirstExisting(dir, id, ["webm","ogg","mp3","wav"]);

      // ── user 메타 구성 ─────────────────────────────────────────
      let user = null;
      // 1) 메타(author) 우선
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), "utf8"));
        if (meta?.author) {
          user = {
            id: meta.author.id ?? null,
            email: meta.author.email ?? null,
            displayName: meta.author.displayName ?? null,
            avatarUrl: meta.author.avatarUrl ?? null,
          };
        }
      } catch { /* ignore broken meta */ }

      // 2) 없으면 ns로 users 테이블 조회
      if (!user) {
        const nsNum = Number(ns);
        if (Number.isFinite(nsNum)) {
          try {
            const row = getUserById(nsNum);
            if (row) {
              user = {
                id: row.id,
                email: row.email,
                displayName: getDisplayNameById?.(row.id) || (row.email ? row.email.split("@")[0] : null),
                avatarUrl: latestAvatarUrl?.(row.id) || null,
              };
            }
          } catch { /* ignore */ }
        }
      }

      // 3) 그래도 없으면 ns 자체를 id로 사용
      if (!user) user = { id: ns, email: null, displayName: null, avatarUrl: null };
      // ────────────────────────────────────────────────────────

      return {
        id,
        json:  `/uploads/audlab/${safeNs}/${id}.json`,
        image: `/uploads/audlab/${safeNs}/${id}.${imgExt}`,
        ...(audExt ? { audio: `/uploads/audlab/${safeNs}/${id}.${audExt}` } : {}),
        user, // ✅ 카드에서 item.user.id 사용 가능
      };
    });

    res.json({ ok:true, ns, items });
  } catch {
    res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});


// ✅ 모든 NS의 제출물을 한 번에 가져오는 엔드포인트
adminRouter.get("/admin/audlab/all", requireAdmin, (req, res) => {
  try {
    const EXT_IMG = ["png","jpg","jpeg","webp","gif"];
    const EXT_AUD = ["webm","ogg","mp3","wav"];
    const EXT_MIME = { png:"image/png", jpg:"image/jpeg", jpeg:"image/jpeg", webp:"image/webp", gif:"image/gif" };

    // audlab 루트 아래 디렉토리(ns) 나열
    const nses = fs.readdirSync(AUDLAB_ROOT, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => decodeURIComponent(d.name))
      .sort();

    const items = [];

    for (const ns of nses) {
      const dir = path.join(AUDLAB_ROOT, encodeURIComponent(ns));

      // 이 NS의 *.json 들만 긁어오기 (_index.json 제외)
      const jsonFiles = fs.readdirSync(dir)
        .filter(f => f.endsWith(".json") && f !== "_index.json");

      for (const jf of jsonFiles) {
        const id = jf.replace(/\.json$/i, "");
        const jPath = path.join(dir, jf);

        // 메타 로드 (없거나 깨져 있어도 넘어감)
        let meta = null;
        try { meta = JSON.parse(fs.readFileSync(jPath, "utf8")); } catch {}

        // 이미지/오디오 확장자 탐색
        const imgExt = findFirstExisting(dir, id, EXT_IMG) || meta?.ext || "png";
        const audExt = findFirstExisting(dir, id, EXT_AUD) || meta?.audioExt || null;

        // user 메타 구성: 우선순위 (meta.author -> users 테이블 -> ns 폴백)
        let user = null;
        if (meta?.author?.id || meta?.author?.email || meta?.author?.displayName) {
          user = {
            id: meta.author.id ?? null,
            email: meta.author.email ?? null,
            displayName: meta.author.displayName ?? null,
            avatarUrl: meta.author.avatarUrl ?? null,
          };
        } else {
          // ns가 숫자면 users에서 조회
          const nsNum = Number(ns);
          if (Number.isFinite(nsNum)) {
            try {
              const row = getUserById(nsNum);
              if (row) {
                user = {
                  id: row.id,
                  email: row.email,
                  displayName: getDisplayNameById?.(row.id) || (row.email ? row.email.split("@")[0] : null),
                  avatarUrl: latestAvatarUrl?.(row.id) || null,
                };
              }
            } catch {}
          }
          // 그래도 없으면 ns 자체를 id로 노출
          if (!user) user = { id: ns, email: null, displayName: null, avatarUrl: null };
        }

        // createdAt 보정
        const createdAt = Number(meta?.createdAt ?? meta?.created_at ?? 0) ||
                          (() => { try { return Math.floor(fs.statSync(jPath).mtimeMs); } catch { return Date.now(); } })();

        items.push({
          id,
          ns,                         // 어떤 유저의 파일인지 식별용
          createdAt,
          width: Number(meta?.width || 0),
          height: Number(meta?.height || 0),
          label: String(meta?.label || ""),
          caption: typeof meta?.caption === "string" ? meta.caption
                 : (typeof meta?.text === "string" ? meta.text : ""),
          bg: meta?.bg || meta?.bg_color || meta?.bgHex || null,
          // 파일 URL들
          json:  `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`,
          image: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${imgExt}`,
          ...(audExt ? { audio: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${audExt}` } : {}),
          // 카드에 찍을 user
          user,
          // 편의
          mime: EXT_MIME[imgExt] || meta?.mime || null,
          audioExt: audExt || null,
          accepted: !!meta?.accepted,   // 메타에 들어있는 경우 유지
        });
      }
    }

    // 최신순 정렬
    items.sort((a,b) => (b.createdAt - a.createdAt) || (a.id < b.id ? 1 : -1));

    return res.json({ ok: true, items });
  } catch (e) {
    console.log("[/admin/audlab/all] failed:", e?.message || e);
    return res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

// 단건 메타(선택)
adminRouter.get("/admin/audlab/item", requireAdmin, (req, res) => {
  try {
    const ns = String(req.query.ns || "").trim();
    const id = String(req.query.id || "").trim();
    if (!ns || !id) return res.status(400).json({ ok:false, error:"ns_and_id_required" });
    const dir   = path.join(AUDLAB_ROOT, nsSafe(ns));
    const jPath = path.join(dir, `${id}.json`);
    if (!fs.existsSync(jPath)) return res.status(404).json({ ok:false, error:"not_found" });
    const j = JSON.parse(fs.readFileSync(jPath, "utf8"));
    const pointCount = (j.strokes||[]).reduce((s, st)=>s+(st.points?.length||0), 0);

    const imgExt = findFirstExisting(dir, id, ["png","jpg","jpeg","webp","gif"]) || j.ext || "png";
    const audExt = findFirstExisting(dir, id, ["webm","ogg","mp3","wav"]) || j.audioExt || null;

    res.json({
      ok:true, ns, id,
      meta: { strokeCount: (j.strokes||[]).length, pointCount, width:j.width, height:j.height },
      jsonUrl:  `/uploads/audlab/${nsSafe(ns)}/${id}.json`,
      imageUrl: `/uploads/audlab/${nsSafe(ns)}/${id}.${imgExt}`,
      ...(audExt ? { audioUrl: `/uploads/audlab/${nsSafe(ns)}/${id}.${audExt}` } : {})
    });
  } catch {
    res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

// adminRouter 아래에 추가
adminRouter.post("/admin/audlab/accept", requireAdmin, csrfProtection, (req, res) => {
  try {
    const ns = String(req.body?.ns || "").trim();
    const id = String(req.body?.id || "").trim();
    if (!ns || !id) return res.status(400).json({ ok:false, error:"ns_and_id_required" });

    const dir = path.join(AUDLAB_ROOT, nsSafe(ns));
    const indexPath = path.join(dir, "_index.json");

    let idx = []; try { idx = JSON.parse(fs.readFileSync(indexPath, "utf8")); } catch {}
    let hit = null;

   // 인덱스에 없으면 단건 메타를 읽어 새로 추가
   if (!hit) {
     const jPath = path.join(dir, `${id}.json`);
     if (!fs.existsSync(jPath)) return res.status(404).json({ ok:false, error:"not_found" });
     const j = JSON.parse(fs.readFileSync(jPath, "utf8"));
     hit = {
       id,
       ns,
       label: j.label || "",
       createdAt: j.createdAt || Date.now(),
       width: j.width || 0,
       height: j.height || 0,
       ext: j.ext || "png",
       mime: j.mime || "image/png",
       author: j.author || null,
     };
     idx.unshift(hit); // 최신 앞으로
   }

    idx = idx.map(m => {
      if (String(m.id) === id) { hit = m; return { ...m, accepted:true, updatedAt:Date.now() }; }
      return m;
    });
    if (!hit) return res.status(404).json({ ok:false, error:"not_found" });

    fs.writeFileSync(indexPath, JSON.stringify(idx));
    return res.json({ ok:true });
  } catch { return res.status(500).json({ ok:false }); }
});

app.use("/api", adminRouter);

// 로그인만 필요. 운영자 여부만 알려주는 경량 체크(버튼 노출용)
app.get("/api/audlab/admin/bootstrap", requireLogin, (req, res) => {
  try {
    const row = getUserById(req.session.uid);
    const admin = !!(row && isAdminEmail(row.email));
    res.json({ ok: true, admin, email: row?.email || null });
  } catch {
    res.status(500).json({ ok:false });
  }
});

// 비밀번호 변경
app.post("/auth/password",        requireLogin, csrfProtection, applyPasswordChange);
app.post("/auth/change-password", requireLogin, csrfProtection, applyPasswordChange);
app.put ("/api/users/me/password",requireLogin, csrfProtection, applyPasswordChange);

// 이름 변경
app.post("/auth/profile", requireLogin, csrfProtection, applyNameChange);
app.put ("/api/users/me", requireLogin, csrfProtection, applyNameChange);

// 혼합 PATCH (일부 클라가 PATCH /auth/me 에서 name/password 둘 다 보냄)
app.patch("/auth/me", requireLogin, csrfProtection, async (req, res) => {
  const hasPw =
    typeof req.body?.currentPassword === "string" &&
    (typeof req.body?.newPassword === "string" || typeof req.body?.password === "string");
  const hasName =
    typeof req.body?.displayName === "string" || typeof req.body?.name === "string";

  // 비번 → 이름 순으로 처리
  if (!hasPw && !hasName) return res.status(400).json({ ok:false, error:"INVALID" });

  if (hasPw) {
    const p = PwChange.safeParse(req.body);
    if (!p.success) return res.status(400).json({ ok:false, error:"INVALID_PW" });
    const { currentPassword, newPassword } = p.data;
    const currentHash = getUserPwHash(req.session.uid);
    if (!currentHash) return res.status(500).json({ ok:false, error:"NO_PWHASH" });
    const ok = currentHash && await argon2.verify(currentHash, currentPassword);
    if (!ok) return res.status(400).json({ ok:false, error:"BAD_CREDENTIALS" });
    const newHash = await argon2.hash(newPassword, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
    setUserPassword(req.session.uid, newHash);
  }

  let displayName = null;
  if (hasName) {
    const n = NameChange.safeParse(req.body);
    if (!n.success) return res.status(400).json({ ok:false, error:"INVALID_NAME" });
    displayName = n.data.displayName.trim();
    setUserDisplayName(req.session.uid, displayName);
  }

  const u = getUserById(req.session.uid);
  const avatarUrl = latestAvatarUrl(req.session.uid);
  return res.json({
    ok: true,
    user: u ? { id: u.id, email: u.email, displayName, avatarUrl } : null,
    displayName,
  });
});

// 경량 헬스체크
app.get("/api/healthz", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ ok: true, bootId: BOOT_ID });
});

// ──────────────────────────────────────────────────────────
// 이메일 NS 강제 상태 API
app.get("/api/state", requireLogin, (req, res) => {
  const emailNS = getNS(req);
  if (!emailNS) return res.status(401).json({ ok:false });
  const row = getStateByEmail(emailNS);
  if (!row) return res.json({ ok: true, emailNS, state: null });
  return res.json({ ok: true, emailNS, state: row.state, updatedAt: row.updatedAt });
});
app.put("/api/state", requireLogin, csrfProtection, (req, res) => {
  const emailNS = getNS(req);
  if (!emailNS) return res.status(401).json({ ok:false });
  const state = req.body?.state ?? req.body ?? {};
  const updatedAt = Number(state?.updatedAt || Date.now());
  putStateByEmail(emailNS, state, updatedAt);
  return res.json({ ok: true, emailNS });
});
app.post("/api/state", requireLogin, csrfProtection, (req, res) => {
  const emailNS = getNS(req);
  if (!emailNS) return res.status(401).json({ ok:false });
  const state = req.body?.state ?? req.body ?? {};
  const updatedAt = Number(state?.updatedAt || Date.now());
  putStateByEmail(emailNS, state, updatedAt);
  return res.json({ ok: true, emailNS });
});
// ──────────────────────────────────────────────────────────
// 소셜/피드 라우터(있으면 자동 장착) — 업로드/블랍보다 '위'
// ──────────────────────────────────────────────────────────
mountIfExists("./routes/gallery.public");   // GET /api/gallery/public, /api/gallery/:id/blob (visibility-aware)
mountIfExists("./routes/likes.routes");     // PUT/DELETE /api/items/:id/like

// ===== 폴백 소셜 라우트 설치 (mountIfExists 뒤, csrf/UPLOAD_ROOT 이후) =====

(function installFallbackSocialRoutes(){
  // [FIX] 중첩 라우터까지 탐색하는 안전한 라우트 존재 검사
  // ──────────────────────────────────────────────────────────
  // 안전한 라우트 존재 검사 (Express 4/5 호환, 중첩 라우터 OK)
  // ──────────────────────────────────────────────────────────
  function hasRouteDeep(method, suffix) {
    try {
      method = String(method || '').toLowerCase();
      const want = String(suffix || '');
      const norm = (p) => (p || '').toString();
      const endsWith = (p, suf) => norm(p) === norm(suf) || norm(p).endsWith(norm(suf));

      const root = app && app._router && Array.isArray(app._router.stack) ? app._router.stack : [];
      const q = [...root];
      while (q.length) {
        const layer = q.shift();
        if (!layer) continue;

        const route = layer.route;
        if (route && route.path) {
          const path = route.path;
          const methods = route.methods || {};
          if (methods[method] || methods.all) {
            const candidateApi = `/api${path.startsWith('/') ? '' : '/'}${path}`;
            if (endsWith(path, want) || endsWith(candidateApi, want)) return true;
          }
        }
        const handle = layer.handle;
        const childStack =
          handle && typeof handle === 'function' && Array.isArray(handle.stack) ? handle.stack :
          (handle && Array.isArray(handle.stack) ? handle.stack : null);
        if (Array.isArray(childStack)) q.push(...childStack);
      }
    } catch (e) {
      console.log('[router] hasRouteDeep guard:', e?.message || e);
    }
    return false;
  }

  // ───────────────── 테이블 보장 ─────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS item_likes (
      item_id   TEXT NOT NULL,
      user_id   TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (item_id, user_id)
    );

    /* 신규: 투표 테이블 (FE 스펙: label) */
    CREATE TABLE IF NOT EXISTS item_votes (
      item_id    TEXT NOT NULL,
      user_id    TEXT NOT NULL,
      label      TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (item_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_item_votes_item  ON item_votes(item_id);
    CREATE INDEX IF NOT EXISTS idx_item_votes_label ON item_votes(label);
  `);

  // ───────────────── Votes 헬퍼 ─────────────────
  const VOTE_LABELS = new Set(["thump","miro","whee","track","echo","portal"]);
  const isVoteLabel = (s) => VOTE_LABELS.has(String(s || "").trim());
  const zeroCounts  = () => { const o={}; VOTE_LABELS.forEach(k=>o[k]=0); return o; };

  function voteCountsOf(itemId){
    try{
      const rows = db.prepare(
        'SELECT label, COUNT(*) n FROM item_votes WHERE item_id=? GROUP BY label'
      ).all(itemId);
      const out = zeroCounts();
      for (const r of rows) if (isVoteLabel(r.label)) out[r.label] = Number(r.n) || 0;
      return out;
    } catch { return zeroCounts(); }
  }
  function myVoteOf(uid, itemId){
    try{
      const r = db.prepare('SELECT label FROM item_votes WHERE user_id=? AND item_id=?').get(uid, itemId);
      return r && isVoteLabel(r.label) ? r.label : null;
    } catch { return null; }
  }
  function emitVoteUpdate(itemId, ns){
    const counts = voteCountsOf(itemId);
    let ownerNs = ITEM_OWNER_NS.get(String(itemId)) || null;
    if (!ownerNs) {
      try {
        const row = db.prepare('SELECT owner_ns, author_email FROM items WHERE id=?').get(itemId) || {};
        ownerNs = resolvePushNS(row.author_email || row.owner_ns || null); // 이메일 NS로 통일
        if (ownerNs) ITEM_OWNER_NS.set(String(itemId), ownerNs);
      } catch {}
    }
    const payload = { id: itemId, ns, counts, ts: Date.now() };
    if (ownerNs) payload.owner = { ns: ownerNs };
    io.to(`item:${itemId}`).emit('vote:update', payload);
    io.emit('vote:update', payload);
    return counts;
  }

  // =========================================================
  // 아이템 좋아요
  // =========================================================
  if (!hasRouteDeep('put', '/items/:id/like')) {
    app.put('/api/items/:id/like', requireLogin, csrfProtection, (req, res) => {
      try {
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        const info = db.prepare(
          'INSERT OR IGNORE INTO item_likes(item_id, user_id, created_at) VALUES(?,?,?)'
        ).run(id, uid, Date.now());
        const n = db.prepare('SELECT COUNT(*) n FROM item_likes WHERE item_id=?').get(id).n;
        {
          let ownerNs = ITEM_OWNER_NS.get(String(id)) || null;
          if (!ownerNs) {
            try {
              const row = db.prepare('SELECT owner_ns, author_email FROM items WHERE id=?').get(id) || {};
              ownerNs = resolvePushNS(row.author_email || row.owner_ns || null);
              if (ownerNs) ITEM_OWNER_NS.set(String(id), ownerNs);
            } catch {}
          }
          const payload = { id, ns, likes: n, liked: true, by: uid, ts: Date.now() };
          if (ownerNs) payload.owner = { ns: ownerNs };
          io.to(`item:${id}`).emit('item:like', payload);
          io.emit('item:like', payload);
        }
        res.json({ ok: true, liked: true, likes: n });
      } catch { res.status(500).json({ ok: false }); }
    });
  }
  if (!hasRouteDeep('delete', '/items/:id/like')) {
    app.delete('/api/items/:id/like', requireLogin, csrfProtection, (req, res) => {
      try {
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        db.prepare('DELETE FROM item_likes WHERE item_id=? AND user_id=?').run(id, uid);
        const n = db.prepare('SELECT COUNT(*) n FROM item_likes WHERE item_id=?').get(id).n;
        {
          let ownerNs = ITEM_OWNER_NS.get(String(id)) || null;
          if (!ownerNs) {
            try {
              const row = db.prepare('SELECT owner_ns, author_email FROM items WHERE id=?').get(id) || {};
              ownerNs = resolvePushNS(row.author_email || row.owner_ns || null);
              if (ownerNs) ITEM_OWNER_NS.set(String(id), ownerNs);
            } catch {}
          }
          const payload = { id, ns, likes: n, liked: false, by: uid, ts: Date.now() };
          if (ownerNs) payload.owner = { ns: ownerNs };
          io.to(`item:${id}`).emit('item:like', payload);
          io.emit('item:like', payload);
        }
        res.json({ ok: true, liked: false, likes: n });
      } catch { res.status(500).json({ ok: false }); }
    });
  }

  // =========================================================
  // 공개 갤러리 (여러 ns 통합) — 하드닝 버전
  // =========================================================
  if (!hasRouteDeep('get', '/gallery/public') || process.env.FORCE_FALLBACK_PUBLIC === '1') {
    app.get('/api/gallery/public', requireLogin, (req, res) => {
      res.set('Cache-Control', 'no-store');
      try {
        const limit = Math.min(Number(req.query.limit) || 12, 60);

        // after/cursor 둘 다 허용
        const afterParam = String(req.query.after || req.query.cursor || '');
        const [aTsStr, aId = ''] = afterParam ? afterParam.split('-') : [];
        const afterTs = Number(aTsStr || 0);

        const nsFilter    = String(req.query.ns || '').trim().toLowerCase();
        const labelFilter = String(req.query.label || '').trim();

        const SKIP_DIRS = new Set(['avatars','audlab']); // 갤러리 외 디렉토리 제외
        // 1) ns 디렉토리 나열
        let nss = [];
        try {
          nss = fs.readdirSync(UPLOAD_ROOT).filter(d => {
            try {
              if (SKIP_DIRS.has(d)) return false;
              return fs.lstatSync(path.join(UPLOAD_ROOT, d)).isDirectory();
            } catch { return false; }
          });
        } catch {}
        if (nsFilter) nss = nss.filter(ns => String(ns).toLowerCase() === nsFilter);

        const EXT_MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', webp:'image/webp', gif:'image/gif' };

        // 2) 각 ns의 인덱스 취합(+ 인덱스 없으면 파일 스캔 폴백)
        const all = [];
        for (const ns of nss) {
          const dir = path.join(UPLOAD_ROOT, ns);
          const indexPath = path.join(dir, '_index.json');

          let idx = [];
          try { idx = JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch {}

          if (!Array.isArray(idx) || idx.length === 0) {
            // ▶ 폴백: 이미지 파일 스캔으로 메타 생성
            try {
              const files = fs.readdirSync(dir).filter(f => /\.(png|jpe?g|gif|webp)$/i.test(f));
              idx = files.map(f => {
                const ext = f.split('.').pop().toLowerCase();
                const id  = f.replace(/\.(png|jpe?g|gif|webp)$/i, '');
                const st  = fs.statSync(path.join(dir, f));
                return {
                  id,
                  ns,
                  label: "",
                  createdAt: Math.floor(st.mtimeMs || st.ctimeMs || Date.now()),
                  width: 0, height: 0,
                  ext, mime: EXT_MIME[ext]
                };
              });
            } catch {}
          }

          if (!Array.isArray(idx)) continue;

          for (const m of idx) {
            const id = String(m?.id || '').trim();
            if (!id) continue;
            all.push({
              id, ns,
              label: String(m?.label || ''),
              created_at: Number(m?.createdAt ?? m?.created_at ?? 0) || 0,
              width: Number(m?.width || 0),
              height: Number(m?.height || 0),
              caption: typeof m?.caption === 'string' ? m.caption
                    : (typeof m?.text === 'string' ? m.text : ''),
              bg: m?.bg || m?.bg_color || m?.bgHex || null,
              // ⬅ 추가: 업로드 당시 저장해둔 작성자 메타를 리스트에도 싣기
              author: (m?.author ? {
                id: m.author.id ?? null,
                displayName: m.author.displayName ?? null,
                avatarUrl: m.author.avatarUrl ?? null,
                email: m.author.email ?? null,
              } : null),
            });
          }
        }

        // 3) label 필터
        if (labelFilter) {
          for (let i = all.length - 1; i >= 0; i--) {
            if (String(all[i].label || '') !== labelFilter) all.splice(i, 1);
          }
        }

        // 4) 정렬 + after 커서
        all.sort((a,b) => (b.created_at - a.created_at) || (a.id < b.id ? 1 : -1));
        if (afterTs) {
          const cid = String(aId);
          const cut = all.findIndex(x =>
            x.created_at < afterTs || (x.created_at === afterTs && x.id < cid)
          );
          if (cut >= 0) all.splice(0, cut + 1);
        }
        const slice = all.slice(0, limit);

        // 5) DB 카운트/liked 보강

        const authors = new Set();
        for (const it of slice) {
          const ownerId = Number(it.ns);
          if (Number.isFinite(ownerId)) authors.add(`id:${ownerId}`);
          else if (it.ns) authors.add(`email:${String(it.ns).toLowerCase()}`);
        }

        const authorMap = new Map();
        for (const key of authors) {
          if (key.startsWith('id:')) {
            const uid = Number(key.slice(3));
            const row = getUserById(uid);
            authorMap.set(key, row ? publicUserShape(req.session?.uid, row) : null);
          } else {
            const email = key.slice(6);
            const row = getUserByEmail?.(email);
            authorMap.set(key, row ? publicUserShape(req.session?.uid, row) : null);
          }
        }

        for (const it of slice) {
          // 1) 업로드 메타에 author.email 이 있으면 '작성자'를 최우선으로 사용
          const authorEmail = it?.author?.email;
          if (authorEmail && typeof getUserByEmail === "function") {
            const row = getUserByEmail(String(authorEmail).toLowerCase());
            it.user = row ? authorProfileShape(row) : {
              id: authorEmail,
              email: authorEmail,
              displayName: (String(authorEmail).split("@")[0] || null),
              avatarUrl: null
            };
          } else {
            // 2) 없으면 기존 오너 ns 로부터 유저 복원
            const key = Number.isFinite(Number(it.ns)) ? `id:${Number(it.ns)}` : `email:${String(it.ns).toLowerCase()}`;
            const row = authorMap.get(key);
            it.user = row
              ? authorProfileShape({               // ← 공개용이 아니라 '작성자' shape 사용
                  id: row.id,
                  email: row.email,                 // row.email 은 publicUserShape에서 마스킹일 수 있어 null이면 it.ns 사용
                  displayName: row.displayName,
                  avatarUrl: row.avatarUrl
                })
              : {
                  id: it.ns,
                  email: it.ns,
                  displayName: (String(it.ns||"").split("@")[0] || null),
                  avatarUrl: null
                };
          }

          // 3) 메타 보강(표시명/아바타)
          if ((!it.user.displayName || it.user.displayName === null) && it.author?.displayName) it.user.displayName = it.author.displayName;
          if ((!it.user.avatarUrl   || it.user.avatarUrl   === null) && it.author?.avatarUrl)   it.user.avatarUrl   = it.author.avatarUrl;

          // 4) mine 플래그
          it.mine = String(it.ns || '').toLowerCase() === String(getNS(req) || '').toLowerCase();

          // 5) 알림 라우팅용: id -> owner ns 맵 업데이트
          ITEM_OWNER_NS.set(String(it.id), String(it.ns));
        }

        const next = (all.length > limit && slice.length)
          ? `${slice[slice.length - 1].created_at}-${slice[slice.length - 1].id}` : null;

        return res.json({ ok: true, items: slice, nextCursor: next });
      } catch (e) {
        console.log('[gallery.public] fatal:', e?.stack || e);
        return res.status(500).json({ ok:false, error:'public-feed-failed' });
      }
    });
  }

  // =========================================================
  // Votes (poll) — FE가 시도하는 모든 경로 지원
  // =========================================================
  // GET /api/items/:id/votes
  if (!hasRouteDeep('get', '/items/:id/votes')) {
    app.get('/api/items/:id/votes', requireLogin, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        res.json({ ok:true, id, counts: voteCountsOf(id), my: myVoteOf(uid, id) });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // GET /api/votes?item=ID
  if (!hasRouteDeep('get', '/votes')) {
    app.get('/api/votes', requireLogin, (req, res) => {
      try{
        const id  = String(req.query.item || '');
        if (!id) return res.status(400).json({ ok:false, error:'bad-item' });
        const uid = req.session.uid;
        res.json({ ok:true, id, counts: voteCountsOf(id), my: myVoteOf(uid, id) });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // PUT /api/items/:id/vote?label=LB  (or {label} in body)
  if (!hasRouteDeep('put', '/items/:id/vote')) {
    app.put('/api/items/:id/vote', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        const label = String(req.query.label || req.body?.label || req.body?.choice || '').trim();
        if (!isVoteLabel(label)) return res.status(400).json({ ok:false, error:'bad-label' });
        const prev = db.prepare('SELECT label FROM item_votes WHERE item_id=? AND user_id=?').get(id, uid)?.label || null;
        db.prepare(`
          INSERT INTO item_votes(item_id,user_id,label,created_at)
          VALUES(?,?,?,?)
          ON CONFLICT(item_id,user_id)
          DO UPDATE SET label=excluded.label, created_at=excluded.created_at
        `).run(id, uid, label, Date.now());

        const counts = emitVoteUpdate(id, ns);
        res.json({ ok:true, id, counts, my: label });
        // ★ 라벨이 실제로 바뀐 경우에만, 소유자에게 한 번만 푸시
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // POST /api/items/:id/votes {label}
  if (!hasRouteDeep('post', '/items/:id/votes')) {
    app.post('/api/items/:id/votes', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        const label = String(req.body?.label || req.body?.choice || '').trim();
        if (!isVoteLabel(label)) return res.status(400).json({ ok:false, error:'bad-label' });
        const prev = db.prepare('SELECT label FROM item_votes WHERE item_id=? AND user_id=?').get(id, uid)?.label || null;
        db.prepare(`
          INSERT INTO item_votes(item_id,user_id,label,created_at)
          VALUES(?,?,?,?)
          ON CONFLICT(item_id,user_id)
          DO UPDATE SET label=excluded.label, created_at=excluded.created_at
        `).run(id, uid, label, Date.now());

        const counts = emitVoteUpdate(id, ns);
        res.json({ ok:true, id, counts, my: label });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // POST /api/votes { item_id, label }
  if (!hasRouteDeep('post', '/votes')) {
    app.post('/api/votes', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.body?.item_id || req.body?.item || req.query?.item || '');
        const uid = req.session.uid;
        const ns  = getNS(req);
        const label = String(req.body?.label || req.body?.choice || '').trim();
        if (!id) return res.status(400).json({ ok:false, error:'bad-item' });
        if (!isVoteLabel(label)) return res.status(400).json({ ok:false, error:'bad-label' });
        const prev = db.prepare('SELECT label FROM item_votes WHERE item_id=? AND user_id=?').get(id, uid)?.label || null;
        db.prepare(`
          INSERT INTO item_votes(item_id,user_id,label,created_at)
          VALUES(?,?,?,?)
          ON CONFLICT(item_id,user_id)
          DO UPDATE SET label=excluded.label, created_at=excluded.created_at
        `).run(id, uid, label, Date.now());

        const counts = emitVoteUpdate(id, ns);
        res.json({ ok:true, id, counts, my: label });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // DELETE /api/items/:id/vote
  if (!hasRouteDeep('delete', '/items/:id/vote')) {
    app.delete('/api/items/:id/vote', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        db.prepare('DELETE FROM item_votes WHERE item_id=? AND user_id=?').run(id, uid);
        const counts = emitVoteUpdate(id, ns);
        res.json({ ok:true, id, counts, my: null });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // DELETE /api/items/:id/votes
  if (!hasRouteDeep('delete', '/items/:id/votes')) {
    app.delete('/api/items/:id/votes', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        db.prepare('DELETE FROM item_votes WHERE item_id=? AND user_id=?').run(id, uid);
        const counts = emitVoteUpdate(id, ns);
        res.json({ ok:true, id, counts, my: null });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
  // DELETE /api/votes?item=ID
  if (!hasRouteDeep('delete', '/votes')) {
    app.delete('/api/votes', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.query?.item || req.body?.item_id || req.body?.item || '');
        const uid = req.session.uid;
        const ns  = getNS(req);
        if (!id) return res.status(400).json({ ok:false, error:'bad-item' });
        db.prepare('DELETE FROM item_votes WHERE item_id=? AND user_id=?').run(id, uid);
        const counts = emitVoteUpdate(id, ns);
        res.json({ ok:true, id, counts, my: null });
      } catch { res.status(500).json({ ok:false }); }
    });
  }

  // =========================================================
  // 단일 아이템 메타 조회
  // =========================================================
  if (process.env.FORCE_FALLBACK_ITEMS === '1' || !hasRouteDeep('get', '/items/:id')) {
    app.get('/api/items/:id', requireLogin, (req, res) => {
      try {
        const preferNs = getNS(req);
        const id = String(req.params.id || '');
        if (!id) return res.status(400).json({ ok: false, error: 'bad-id' });

        // ✨ 후보 ns: 요청 ns, 내 uid, 내 email 모두
        const candidates = getMyNamespaces(req, preferNs); // 이미 파일에 선언된 헬퍼

        // 1) 메타 찾기 (_index.json)
        let meta = null;
        let foundNs = null;
        for (const ns of candidates) {
          if (!ns) continue;
          try {
            const indexPath = path.join(UPLOAD_ROOT, ns, '_index.json');
            const idx = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
            if (Array.isArray(idx)) {
              const hit = idx.find(m => String(m.id) === id);
              if (hit) { meta = hit; foundNs = ns; break; }
            }
          } catch {} // 없을 수 있음
        }

        // 2) 파일 확장자/타입 찾기 (메타 없거나 ext 없을 때도 안전)
        const EXT_TO_MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', webp:'image/webp', gif:'image/gif' };
        const tryExts = [];
        if (meta?.ext) tryExts.push(String(meta.ext).toLowerCase());
        tryExts.push('png','jpg','jpeg','webp','gif');

        let fileExt = null, fileMime = null, fileNs = foundNs;
        // 먼저 foundNs에서 시도
        if (fileNs) {
          const base = path.join(UPLOAD_ROOT, fileNs, id);
          for (const e of [...new Set(tryExts)]) {
            if (fs.existsSync(`${base}.${e}`)) { fileExt = e; fileMime = EXT_TO_MIME[e]; break; }
          }
        }
        // 거기서 못 찾으면 후보 ns 전부 스캔
        if (!fileExt) {
          for (const ns of candidates) {
            if (!ns) continue;
            const base = path.join(UPLOAD_ROOT, ns, id);
            for (const e of ['png','jpg','jpeg','webp','gif']) {
              if (fs.existsSync(`${base}.${e}`)) { fileExt = e; fileMime = EXT_TO_MIME[e]; fileNs = ns; break; }
            }
            if (fileExt) break;
          }
        }

        // 3) 기본 필드 조립 (meta가 없어도 안전)
        const created_at = Number(meta?.createdAt ?? meta?.created_at ?? 0) || null;
        const out = {
          id,
          ns: fileNs || foundNs || preferNs,
          label: meta?.label || '',
          created_at, createdAt: created_at,
          width: Number(meta?.width || 0), height: Number(meta?.height || 0),
          caption: typeof meta?.caption === 'string' ? meta.caption : (typeof meta?.text === 'string' ? meta.text : ''),
          text:    typeof meta?.caption === 'string' ? meta.caption : (typeof meta?.text === 'string' ? meta.text : ''),
          bg:       meta?.bg || meta?.bg_color || meta?.bgHex || null,
          bg_color: meta?.bg || meta?.bg_color || meta?.bgHex || null,
          bgHex:    meta?.bg || meta?.bg_color || meta?.bgHex || null,
          ext: fileExt || meta?.ext || null,
          mime: fileMime || meta?.mime || (fileExt ? EXT_TO_MIME[fileExt] : null),
        };

        // 4) 좋아요/댓글 카운트 (에러 무시)
        try {
          const uid = req.session?.uid || '';
          const likeCnt = db.prepare('SELECT COUNT(*) n FROM item_likes WHERE item_id=?').get(id)?.n || 0;
          const liked   = !!db.prepare('SELECT 1 FROM item_likes WHERE item_id=? AND user_id=?').get(id, uid);
          out.likes = likeCnt; out.liked = liked;
        } catch {}

        // 5) owner 정보 + mine 플래그 (+ meta.author 보강)
        try {
          // nsUsed: 파일이 위치한 오너 네임스페이스
          const nsUsed   = out.ns || preferNs;
          const myns     = String(req.session?.uid || '').toLowerCase();
          const ownerId  = Number(nsUsed);
          const ownerRow = Number.isFinite(ownerId) ? getUserById(ownerId) : null;

          // 1) 메타에 author.email 이 있으면 '작성자' 우선
          const authorEmail = meta?.author?.email;
          if (authorEmail && typeof getUserByEmail === "function") {
            const row = getUserByEmail(String(authorEmail).toLowerCase());
            out.user = row ? authorProfileShape(row) : {
              id: authorEmail,
              email: authorEmail,
              displayName: (String(authorEmail).split("@")[0] || null),
              avatarUrl: null
            };
          } else {
            // 2) 없으면 오너 ns 기준으로 작성자 추정
            if (ownerRow) {
              out.user = authorProfileShape(ownerRow);
            } else {
              out.user = { id: nsUsed, email: nsUsed, displayName: null, avatarUrl: null };
            }
          }

          // 3) 메타 보강(표시명/아바타)
          if ((!out.user.displayName || out.user.displayName === null) && meta?.author?.displayName) out.user.displayName = meta.author.displayName;
          if ((!out.user.avatarUrl   || out.user.avatarUrl   === null) && meta?.author?.avatarUrl)   out.user.avatarUrl   = meta.author.avatarUrl;


          // ★ 최종 폴백: 이메일 local-part(예: finelee03)
          if (!out.user.displayName && ownerRow?.email) {
            out.user.displayName = String(ownerRow.email).split("@")[0];
          }

          // author 필드 자체도 없으면 최소 셋업(디버깅/FE 호환)
          if (!out.author && ownerRow) {
            out.author = {
              id: ownerRow.id ?? null,
              displayName: out.user.displayName ?? (ownerRow.email ? String(ownerRow.email).split("@")[0] : null),
              avatarUrl: out.user.avatarUrl ?? latestAvatarUrl?.(ownerRow.id) ?? null,
              email: ownerRow.email ?? null,
            };
          }


          out.mine = !!(nsUsed && String(nsUsed).toLowerCase() === myns);

          // 디버깅/표시용 원본 author도 같이 노출(선택)
          if (meta?.author) {
            out.author = {
              id: meta.author.id ?? null,
              displayName: meta.author.displayName ?? null,
              avatarUrl: meta.author.avatarUrl ?? null,
              email: meta.author.email ?? null,
            };
          }
          // ★ 최종 백필: author가 없거나(author.displayName이 비었으면) user로 보강
          if (!out.author) out.author = {};
          if (!out.author.id && out.user?.id) out.author.id = out.user.id;
          if (!out.author.displayName && out.user?.displayName) out.author.displayName = out.user.displayName;
          if (!out.author.avatarUrl && out.user?.avatarUrl) out.author.avatarUrl = out.user.avatarUrl;
          if (!out.author.email && out.user?.email) out.author.email = out.user.email;

        } catch {}

        // 1) 오너 NS 기준으로 owner row 조회
        const ownerNs = out.ns; // (파일 경로에서 추출된 ns 혹은 기존 계산값)
        let ownerRow = null;
        if (Number.isFinite(Number(ownerNs))) {
          ownerRow = getUserById(Number(ownerNs));
        } else if (typeof getUserByEmail === "function") {
          ownerRow = getUserByEmail(String(ownerNs).toLowerCase());
        }

        // 2) 명시 필드 추가
        out.owner = { ns: ownerNs };                               // 오너 네임스페이스
        out.authorProfile = ownerRow ? authorProfileShape(ownerRow) : null;

        // 3) FE 호환: user는 '작성자'로 통일
        if (out.authorProfile) out.user = out.authorProfile;

        // 4) 업로드 메타(author)로 보강
        if (!out.user?.displayName && out.author?.displayName) out.user.displayName = out.author.displayName;
        if (!out.user?.avatarUrl   && out.author?.avatarUrl)   out.user.avatarUrl   = out.author.avatarUrl;

        // 5) 알림 라우팅용 맵 갱신
        ITEM_OWNER_NS.set(String(out.id), ownerNs);


        res.set('Cache-Control', 'no-store');
        return res.json({ ok: true, ...out, item: out });
      } catch (e) {
        // 원인 확인 쉬우라고 에러 메시지 로그
        console.log('[GET /api/items/:id] fatal:', e?.stack || e);
        return res.status(500).json({ ok: false, error: 'item-read-failed' });
      }
    });
  }
  
})();


// ──────────────────────────────────────────────────────────
// 접근 정책: 보호된 페이지/엔드포인트
// ──────────────────────────────────────────────────────────
app.get(["/mine", "/mine.html"], ensureAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "mine.html"));
});
app.get(["/labelmine", "/labelmine.html"], ensureAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "labelmine.html"));
});

app.use("/api/mine", ensureAuth);
app.post("/api/gallery/collect", ensureAuth);
app.post("/api/label/heart", ensureAuth);
app.post("/api/jibbitz/collect", ensureAuth);

// 업로드: /api/gallery/upload (구버전 폴백 /api/gallery 도 허용)
app.post(["/api/gallery/upload", "/api/gallery"],
  ensureAuth,
  csrfProtection,
  upload.single("file"),
  (req, res) => {
    try {
      const ns = getNS(req); // 이메일 네임스페이스
      const {
        id = `g_${Date.now()}`,
        label = "",
        createdAt = Date.now(),
        width = 0,
        height = 0,
        thumbDataURL = "",
      } = req.body || {};

      const dir = path.join(UPLOAD_ROOT, ns);
      ensureDir(dir);

      // 1) 파일 소스 결정 (file 우선, 없으면 thumbDataURL 디코드)
      let fileBuf = req.file?.buffer || null;
      let ext = "png";
      let mime = "image/png";

      // (A) multer 파일도 이미지 화이트리스트 체크
      if (req.file && !isAllowedImageMime(req.file.mimetype)) {
        return res.status(400).json({ ok:false, error:"bad_image_mime" });
      }

      if (!fileBuf && thumbDataURL) {
        const decoded = decodeDataURL(thumbDataURL);
        if (decoded) {
          if (!/^image\//.test(decoded.mime) || !isAllowedImageMime(decoded.mime)) {
            return res.status(400).json({ ok:false, error:"bad_image_mime" });
         }
          // dataURL 경로 용량 가드 (예: 8MB)
          if (decoded.buf.length > 8 * 1024 * 1024) {
            return res.status(413).json({ ok:false, error:"image_too_large" });
          }
          fileBuf = decoded.buf; ext = decoded.ext; mime = decoded.mime;
        }
      }

      if (!fileBuf) return res.status(400).json({ ok: false, error: "no-image" });

      const filename = `${id}.${ext}`;
      const outPath  = path.join(dir, filename);
      // 최종 경로가 dir 내부인지 확인(더블 세이프가드)
      if (!outPath.startsWith(dir + path.sep)) {
        return res.status(400).json({ ok:false, error:"bad-path" });
      }
      fs.writeFileSync(outPath, fileBuf);

      // 2) 메타 저장(확장자/타입 포함)
      const meta = {
        id, label,
        createdAt: Number(createdAt) || Date.now(),
        width: Number(width) || 0,
        height: Number(height) || 0,
        ns, ext, mime,
      };

      // ✨ 작성자 메타 흡수
      {
        const b = req.body || {};
        // labelmine이 보내는 author_* 혹은 user 객체에서 안전하게 수집
        const fromUser = (() => {
          try { return typeof b.user === 'string' ? JSON.parse(b.user) : (b.user || null); } catch { return null; }
        })();
        const author = {
          id:          b.author_id || fromUser?.id || null,
          displayName: b.author_name || fromUser?.displayName || fromUser?.name || null,
          handle:      b.author_handle || null,
          avatarUrl:   b.author_avatar || fromUser?.avatarUrl || null,
          email:       fromUser?.email || null,  // 마스킹은 조회 시 처리
        };
        // 값이 하나라도 있으면 meta에 기록
        if (author.id || author.displayName || author.avatarUrl || author.email) {
          meta.author = author;
        }
      }

            // 2025-09-09: caption/bg 저장 (labelmine에서 보낸 값 반영)
      {
        const b = req.body || {};
        // caption: 최대 500자, 공백 제거
        const cap = typeof b.caption === "string" ? b.caption.trim().slice(0, 500) : "";
        if (cap) {
          meta.caption = cap;
          // 구버전/다른 클라이언트 호환을 위해 text에도 복제
          meta.text = cap;
        }
        // bg: bg | bg_color | bgHex 중 우선 매칭
        const rawBg = String(b.bg || b.bg_color || b.bgHex || "").trim();
        if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(rawBg)) {
          meta.bg = rawBg;
          // 호환 필드도 함께 채움
          meta.bg_color = rawBg;
          meta.bgHex = rawBg;
        }
      }

      const indexPath = path.join(dir, "_index.json");
      let idx = [];
      try { idx = JSON.parse(fs.readFileSync(indexPath, "utf8")); } catch {}
      if (!Array.isArray(idx)) idx = [];
      idx = idx.filter(m => String(m.id) !== id); // 중복 제거
      idx.unshift(meta);                           // 최신이 앞으로
      idx = idx.slice(0, 2000);                    // 안전한 상한
      writeJsonAtomic(indexPath, idx);

      return res.json({ ok: true, id, ns, ext, mime });
    } catch (e) {
      return res.status(500).json({ ok: false, error: "upload-failed" });
    }
  }
);

// ====== item 삭제 헬퍼 & 라우트 (업로드 뒤에 추가, 블랍 라우트 전에) ======
// ====== item 삭제/조회 보강 헬퍼 & 라우트 (업로드 뒤에, 블랍 라우트 전에) ======

// JSON 원자적 저장(임시파일 → rename)
function writeJsonAtomic(filePath, dataObj) {
  try {
    const dir = path.dirname(filePath);
    const tmp = path.join(dir, `.${path.basename(filePath)}.tmp-${Date.now()}`);
    fs.writeFileSync(tmp, JSON.stringify(dataObj));
    fs.renameSync(tmp, filePath);
    return true;
  } catch { return false; }
}

// 내 계정에서 사용할 수 있는 모든 후보 NS (요청 ns, 내 uid, 내 email)
function getMyNamespaces(req, preferNs) {
  const pref = String(preferNs || '').toLowerCase();
  const emailNs = getNS(req);
  return [...new Set([pref, emailNs].filter(Boolean))];
}

// index/파일을 안전하게 삭제 (index에 없더라도 파일만 있으면 삭제 성공으로 간주)
function removeItemFileAndIndexIn(ns, id) {
  try {
    const dir = path.join(UPLOAD_ROOT, ns);
    const indexPath = path.join(dir, '_index.json');

    // 1) index 로드 (없으면 빈 배열)
    let idx = [];
    try { idx = JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch {}

    // 2) index에서 제거 시도
    const before = idx.length;
    idx = Array.isArray(idx) ? idx.filter(m => String(m.id) !== String(id)) : [];

    // 3) 파일 삭제 (하나라도 삭제되면 ok)
    let anyFileDeleted = false;
    for (const ext of ['png','jpg','jpeg','webp','gif']) {
      const p = path.join(dir, `${id}.${ext}`);
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); anyFileDeleted = true; } catch {}
      }
    }

    // 4) index가 바뀌었으면 원자적으로 저장
    if (before !== idx.length) writeJsonAtomic(indexPath, idx);

    // index에서 빠졌거나, 파일을 하나라도 지웠으면 ‘삭제 성공’으로 처리
    return (before !== idx.length) || anyFileDeleted;
  } catch { return false; }
}

// 전체 후보 NS를 돌며 실제로 지워진 곳 반환
function removeItemEverywhere(req, id) {
  const candidates = getMyNamespaces(req, getNS(req));
  for (const ns of candidates) {
    if (!ns) continue;
    if (removeItemFileAndIndexIn(ns, id)) return ns;
  }
  return null;
}

// 삭제 시 DB 고아 레코드 정리
function purgeItemDb(id) {
  try {
    db.prepare('DELETE FROM item_likes WHERE item_id=?').run(id);
    db.prepare('DELETE FROM item_votes WHERE item_id=?').run(id);
  } catch {}
}

// DELETE /api/items/:id
app.delete('/api/items/:id', requireLogin, csrfProtection, (req, res) => {
  const id = String(req.params.id || '');
  if (!id) return res.status(400).json({ ok:false, error:'bad-id' });

  // 클라이언트가 명시적으로 ns를 보낸 경우에만 권한체크
  const sentNs = String(req.body?.ns || req.query?.ns || '').trim();
  if (sentNs && !ensureOwnerNs(req, sentNs)) {
    return res.status(403).json({ ok:false, error:'forbidden' });
  }

  const removedNs = removeItemEverywhere(req, id); // 후보(ns, uid, email) 순회 삭제
  if (!removedNs) return res.status(404).json({ ok:false, error:'not-found' });

  purgeItemDb(id);
  io.to(`item:${id}`).emit('item:removed', { id, ns: removedNs });
  io.emit('item:removed',             { id, ns: removedNs });
  return res.json({ ok:true, id, ns: removedNs });
});

// POST /api/items/:id/delete  (폴백)
app.post('/api/items/:id/delete', requireLogin, csrfProtection, (req, res) => {
  const id = String(req.params.id || '');
  if (!id) return res.status(400).json({ ok:false, error:'bad-id' });

  const sentNs = String(req.body?.ns || req.query?.ns || '').trim();
  if (sentNs && !ensureOwnerNs(req, sentNs)) {
    return res.status(403).json({ ok:false, error:'forbidden' });
  }

  const removedNs = removeItemEverywhere(req, id);
  if (!removedNs) return res.status(404).json({ ok:false, error:'not-found' });

  purgeItemDb(id);
  io.to(`item:${id}`).emit('item:removed', { id, ns: removedNs });
  io.emit('item:removed',             { id, ns: removedNs });
  return res.json({ ok:true, id, ns: removedNs });
});

// POST /api/delete?item=ID  (최후 폴백)
app.post('/api/delete', requireLogin, csrfProtection, (req, res) => {
  const id = String(req.query.item || req.body?.item || '');
  if (!id) return res.status(400).json({ ok:false, error:'bad-id' });

  const sentNs = String(req.body?.ns || req.query?.ns || '').trim();
  if (sentNs && !ensureOwnerNs(req, sentNs)) {
    return res.status(403).json({ ok:false, error:'forbidden' });
  }

  const removedNs = removeItemEverywhere(req, id);
  if (!removedNs) return res.status(404).json({ ok:false, error:'not-found' });

  purgeItemDb(id);
  io.to(`item:${id}`).emit('item:removed', { id, ns: removedNs });
  io.emit('item:removed',             { id, ns: removedNs });
  return res.json({ ok:true, id, ns: removedNs });
});


// 권한 체크: 요청 ns가 내 uid/email 변형 중 하나와 일치해야 함
function ensureOwnerNs(req, ns) {
  const email = getNS(req);
  ns = String(ns || '').toLowerCase();
  return !!email && ns === email;
}

// ===== DEV-ONLY: migrate items from 'default' ns to current user's ns =====
app.post('/api/dev/migrate-default-to-me', requireLogin, csrfProtection, (req, res) => {
  try {
    const myNs = String(req.session.uid).toLowerCase();     // e.g. "2"
    const srcDir = path.join(UPLOAD_ROOT, 'default');
    const dstDir = path.join(UPLOAD_ROOT, myNs);
    ensureDir(dstDir);

    const readIdx  = (dir) => { try { return JSON.parse(fs.readFileSync(path.join(dir,'_index.json'),'utf8')) || []; } catch { return []; } };
    const writeIdx = (dir, idx) => fs.writeFileSync(path.join(dir,'_index.json'), JSON.stringify(idx));

    let srcIdx = readIdx(srcDir);
    let dstIdx = readIdx(dstDir);

    let moved = 0, skipped = 0, movedFiles = 0;
    const movedIds = new Set();

    for (const meta of srcIdx) {
      const id = String(meta.id || '').trim();
      if (!id) continue;

      if (dstIdx.some(m => String(m.id) === id)) { skipped++; continue; }

      // 파일 이동 (첫 번째로 존재하는 확장자만)
      let fileMoved = false;
      for (const ext of ['png','jpg','jpeg','webp','gif']) {
        const sp = path.join(srcDir, `${id}.${ext}`);
        if (fs.existsSync(sp)) {
          const dp = path.join(dstDir, `${id}.${ext}`);
          try { fs.renameSync(sp, dp); } catch {
            try { fs.copyFileSync(sp, dp); fs.unlinkSync(sp); } catch {}
          }
          fileMoved = true; movedFiles++; break;
        }
      }

      const newMeta = { ...meta, ns: myNs };
      dstIdx.push(newMeta);
      movedIds.add(id);
      moved++;
    }

    // src index에서 옮긴 항목 제거, 정렬 갱신
    srcIdx = srcIdx.filter(m => !movedIds.has(String(m.id)));
    const sorter = (a,b) => (Number(b.createdAt||b.created_at||0) - Number(a.createdAt||a.created_at||0)) || (a.id < b.id ? 1 : -1);
    try { dstIdx.sort(sorter); srcIdx.sort(sorter); } catch {}

    writeIdx(srcDir, srcIdx);
    writeIdx(dstDir, dstIdx);

    res.json({ ok:true, from:'default', to: myNs, moved, movedFiles, skipped, dstCount: dstIdx.length });
  } catch (e) {
    res.status(500).json({ ok:false, error:'migrate-failed', message: e?.message || String(e) });
  }
});

// ── 이미지 blob (ns 힌트가 없더라도 전 ns에서 탐색)
(() => {
  const EXT_TO_MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', webp:'image/webp', gif:'image/gif' };
  const exts = ['png','jpg','jpeg','webp','gif'];

  function findBlobPath(id, preferNs, uid) {
    const dirs = new Set();
    if (preferNs) dirs.add(path.join(UPLOAD_ROOT, String(preferNs)));
    if (uid)      dirs.add(path.join(UPLOAD_ROOT, String(uid)));
    try {
      for (const d of fs.readdirSync(UPLOAD_ROOT)) {
        const p = path.join(UPLOAD_ROOT, d);
        try { if (d !== 'avatars' && fs.lstatSync(p).isDirectory()) dirs.add(p); } catch {}
      }
    } catch {}
    for (const dir of dirs) {
      for (const ext of exts) {
        const fp = path.join(dir, `${id}.${ext}`);
        if (fs.existsSync(fp)) return { fp, ext, mime: EXT_TO_MIME[ext] || 'application/octet-stream' };
      }
    }
    return null;
  }

  function serveBlob(req, res, headOnly=false) {
    try {
      const id = String(req.params.id || '');
      if (!id) return res.status(400).json({ ok:false, error:'bad-id' });
      const preferNs = String(req.query.ns || '');
      const uid = req.session?.uid;

      // 인덱스에 등록된 확장자 우선(있으면 제일 먼저 확인)
      let hintExts = [];
      try {
        const ns = preferNs || String(uid || '');
        if (ns) {
          const row = JSON.parse(fs.readFileSync(path.join(UPLOAD_ROOT, ns, '_index.json'), 'utf8'))
            .find(m => String(m.id) === id);
          if (row?.ext) hintExts = [String(row.ext).toLowerCase()];
        }
      } catch {}
      const foundByIndex = hintExts.length
        ? (() => {
            const ns = preferNs || String(uid || '');
            const dir = ns ? path.join(UPLOAD_ROOT, ns) : null;
            if (!dir) return null;
            for (const e of hintExts) {
              const p = path.join(dir, `${id}.${e}`);
              if (fs.existsSync(p)) return { fp: p, ext: e, mime: EXT_TO_MIME[e] || 'application/octet-stream' };
            }
            return null;
          })()
        : null;

      const found = foundByIndex || findBlobPath(id, preferNs, uid);
      if (!found) return res.status(404).json({ ok:false, error:'not-found' });

      res.setHeader('Content-Type', found.mime);
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      if (headOnly) return res.end();
      return fs.createReadStream(found.fp).pipe(res);
    } catch (e) {
      return res.status(500).json({ ok:false, error:'read-failed' });
    }
  }

  app.get('/api/gallery/:id/blob', ensureAuth, (req, res) => serveBlob(req, res, false));
  app.head('/api/gallery/:id/blob', ensureAuth, (req, res) => serveBlob(req, res, true));
})();

// ──────────────────────────────────────────────────────────
// 정적 리소스/루트
// ──────────────────────────────────────────────────────────
app.use(express.static(PUBLIC_DIR));
app.get("/", (_, res) => res.sendFile(path.join(PUBLIC_DIR, "home.html")));

// ──────────────────────────────────────────────────────────
io.engine.use(sessionMiddleware);
io.on("connection", (sock) => {
  sock.on("subscribe", (payload = {}) => {
    // 1) 라벨 조인(기존 유지)
    const labels = Array.isArray(payload.labels)
      ? payload.labels
      : (payload.label ? [payload.label] : []);
    for (const lb of labels) if (typeof lb === "string" && lb) sock.join(`label:${lb}`);

    // 2) 내 NS / 감시 NS 조인
    const ns = String(payload.ns || "").toLowerCase();
    if (ns) sock.join(`ns:${ns}`);
    const watch = Array.isArray(payload.watch) ? payload.watch : [];
    for (const w of watch) {
      const wn = String(w || "").toLowerCase();
      if (wn) sock.join(`ns:${wn}`);
    }

    // 3) 아이템 조인 + ★소유자 NS 학습
    const items = Array.isArray(payload.items) ? payload.items : [];
    for (const it of items) {
      const id = String(it || "");
      if (!id) continue;
      sock.join(`item:${id}`);
      if (ns) ITEM_OWNER_NS.set(id, ns); // 핵심: “이 아이템은 ns 소유”
    }
  });

  sock.on("unsubscribe", (payload = {}) => {
    const labels = Array.isArray(payload.labels)
      ? payload.labels
      : (payload.label ? [payload.label] : []);
    for (const lb of labels) if (typeof lb === "string" && lb) sock.leave(`label:${lb}`);

    const items = Array.isArray(payload.items) ? payload.items : [];
    for (const it of items) {
      const id = String(it || "");
      if (!id) continue;
      sock.leave(`item:${id}`);
      // 캐시는 유지(다른 소켓이 여전히 감시 중일 수 있음)
    }
  });
});

// ──────────────────────────────────────────────────────────
function printRoutesSafe() {
  const router = app && app._router;
  if (!router || !Array.isArray(router.stack)) {
    console.log("\n[ROUTES]\n(router not initialized yet)\n");
    return;
  }
  const out = [];
  const pushRoute = (r) => {
    const methods = Object.keys(r.methods || {}).map(m => m.toUpperCase()).join(",");
    out.push(`${(methods || "GET").padEnd(6)} ${r.path}`);
  };
  const walk = (stack) => {
    for (const layer of stack) {
      if (layer.route && layer.route.path) pushRoute(layer.route);
      else if (layer.name === "router" && layer.handle?.stack) walk(layer.handle.stack);
    }
  };
  walk(router.stack);
  console.log("\n[ROUTES]\n" + (out.length ? out.sort().join("\n") : "(none)") + "\n");
}

// ──────────────────────────────────────────────────────────
hardResetOnBoot();
migrateEmailNsOnBoot();
server.listen(PORT, () => {
  console.log(`listening: http://localhost:${PORT}`);
  if (!PROD) printRoutesSafe();

  // BLE 브리지 초기화(실패해도 서버는 계속)
  try {
    if (typeof startBleBridge === "function") {
      startBleBridge(io, { companyIdLE: 0xFFFF, log: true });
      console.log("[ble] bridge started");
    } else {
      console.log("[ble] startBleBridge not available");
    }
  } catch (e) {
    console.log("[ble] bridge failed to start:", e?.message || e);
  }
});