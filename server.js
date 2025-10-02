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
const nfcRoutes = require("./routes/nfc.routes");
const installGatewayRoutes = require("./routes/gateway.routes");

// === Admin config & seeding ===
const EMAIL_RX = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
const isEmail = (s) => EMAIL_RX.test(String(s || "").trim());

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "audsilhouette@gmail.com")
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
  db,
  createUser,
  getUserByEmail,
  getUserById,
  getUserState,
  putUserState,
  putStateByEmail,
  deleteUser,
  deleteAllStatesForEmail,
  // [ADD] ↓↓↓
  normalizeLabel,
  getLabelStory,
  putLabelStory,
  normalizeJib,
  getJibStory,
  putJibStory,
} = require("./db");

const { startBleBridge } = require("./ble-bridge");

// --- Persistent data root ---
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, ".data"); // Render: /var/data
fs.mkdirSync(DATA_DIR, { recursive: true });

// === 모든 업로드는 퍼시스턴트 디스크 한 곳(UPLOAD_ROOT)으로 통일 ===
const UPLOAD_ROOT = process.env.UPLOAD_ROOT || path.join(DATA_DIR, "uploads");
process.env.UPLOAD_ROOT = UPLOAD_ROOT;
fs.mkdirSync(UPLOAD_ROOT, { recursive: true });

const AVATAR_DIR  = path.join(UPLOAD_ROOT, "avatars");
fs.mkdirSync(AVATAR_DIR,  { recursive: true });

const AUDLAB_ROOT = path.join(UPLOAD_ROOT, "audlab");
fs.mkdirSync(AUDLAB_ROOT, { recursive: true });

function findFirstExisting(dir, id, exts) {
  for (const e of exts) {
    const p = path.join(dir, `${id}.${e}`);
    if (fs.existsSync(p)) return e;
  }
  return null;
}

const IMAGE_EXTS = ["png","jpg","jpeg","webp","gif"];
const VIDEO_EXTS = ["webm"];
const AUDIO_EXTS = ["webm","weba","ogg","mp3","wav","m4a"];
const AUDIO_EXTS_LEGACY = ["ogg","mp3","wav","m4a"];
const AUDLAB_ALL_EXTS = Array.from(new Set([
  ...IMAGE_EXTS,
  ...VIDEO_EXTS,
  ...AUDIO_EXTS,
  ...AUDIO_EXTS_LEGACY,
]));

// ──────────────────────────────────────────────────────────
// 기본 셋업
// ──────────────────────────────────────────────────────────
// ──────────────────────────────────────────────────────────
// 기본 셋업
// ──────────────────────────────────────────────────────────
function dirForNS(ns) {
  return path.join(UPLOAD_ROOT, encodeURIComponent(String(ns || '').toLowerCase()));
}

const BOOT_ID = uuid();
const app = express();

app.set('trust proxy', 1);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Vary", "Origin");
  }
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, X-CSRF-Token, x-xsrf-token, Accept-Language, Content-Language, Authorization"
  );
  res.header("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

function ensureUserAudlabDir(req) {
  const ns = emailNS(req, null);           // ✅ 이메일 NS 고정
  if (!ns) return null;
  const dir = path.join(AUDLAB_ROOT, encodeURIComponent(ns));
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

if (typeof installGatewayRoutes === "function") {
  installGatewayRoutes(app, io);
}

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
      const row = getUserById?.(Number(v));
      const email = String(row?.email || "").trim().toLowerCase();
      if (email) return email;
    } catch {}
  }
  return raw;
}
// 3) 이메일 전용 NS 선택기
function emailNS(req, nsInput) {
  const cand = resolvePushNS(nsInput);
  if (cand && /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(cand)) return cand;
  try {
    const me = getUserById?.(Number(req.session?.uid));
    const email = String(me?.email || "").trim().toLowerCase();
    return email || "";
  } catch {
    return "";
  }
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
  "audio/mpeg",
  "audio/wav",
  "audio/x-wav",
  "audio/mp4",
  "audio/aac",
]);

// [ADD] video/webm 허용 목록 (브라우저별 코덱 다양성 대응)
const ALLOWED_WEBM_VIDEO = new Set([
  "video/webm",
  "video/webm;codecs=vp9,opus",
  "video/webm;codecs=vp8,opus",
  "video/webm;codecs=vp9",
  "video/webm;codecs=vp8",
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
  limits: { fileSize: 20 * 1024 * 1024 },
});

// [ADD] 대용량 비디오 업로더 (녹화 업로드 전용)
const videoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB
});
process.env.FORCE_FALLBACK_PUBLIC = process.env.FORCE_FALLBACK_PUBLIC || "1";
process.env.FORCE_FALLBACK_ITEMS  = process.env.FORCE_FALLBACK_ITEMS  || "1";
function ensureDir(dir) { try { fs.mkdirSync(dir, { recursive: true }); } catch {} }

// [ADD] 유저 업로드/아바타 파일 하드 삭제
function removeUserAssets(email, uid) {
  // why: 재가입/탈퇴 시 사용자 흔적(파일/인덱스/아바타)을 완전히 제거
  const safeEmail = encodeURIComponent(String(email || "").trim().toLowerCase());
  if (!safeEmail) return;

  // 1) audlab/<email> 제거
  try {
    const audlabNsDir = path.join(AUDLAB_ROOT, safeEmail);
    if (audlabNsDir.startsWith(AUDLAB_ROOT + path.sep) && fs.existsSync(audlabNsDir)) {
      fs.rmSync(audlabNsDir, { recursive: true, force: true });
    }
  } catch {}

  // 2) uploads/<email> 제거 (아바타 디렉토리는 건드리지 않음)
  try {
    const uploadsNsDir = path.join(UPLOAD_ROOT, safeEmail);
    // 안전가드: avatars 폴더와 동일하지 않아야 함
    if (
      uploadsNsDir.startsWith(UPLOAD_ROOT + path.sep) &&
      uploadsNsDir !== AVATAR_DIR &&
      fs.existsSync(uploadsNsDir)
    ) {
      fs.rmSync(uploadsNsDir, { recursive: true, force: true });
    }
  } catch {}

  // 3) avatars/<uid>-*.ext 제거
  try {
    if (uid != null) {
      const files = fs.readdirSync(AVATAR_DIR);
      for (const f of files) {
        if (f.startsWith(`${uid}-`) && /\.(webp|png|jpe?g|gif)$/i.test(f)) {
          try { fs.unlinkSync(path.join(AVATAR_DIR, f)); } catch {}
        }
      }
    }
  } catch {}
}

async function handleAccountDelete(req, res) {
  if (!req.session?.uid) return res.status(401).json({ ok:false, error:"auth_required" });

  const uid = req.session.uid;
  const row = getUserById(uid);
  const email = row?.email || "";

  // 파일/디렉토리/아바타 정리
  removeUserAssets(email, uid);

  // ✅ 이 유저의 좋아요/투표도 같이 삭제 (카운트 왜곡 방지)
  try {
    db.prepare('DELETE FROM item_likes WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM item_votes WHERE user_id=?').run(uid);
  } catch {}

  try { deleteAllStatesForEmail(email); } catch {}

  // 유저 삭제 (user_states 는 FK CASCADE)
  deleteUser(uid);

  // 세션/쿠키 정리
  const name = PROD ? "__Host-sid" : "sid";
  const clearOpts = { path: "/", sameSite: CROSS_SITE ? "none" : "lax", secure: PROD || CROSS_SITE };
  const done = () => { try { res.clearCookie(name, clearOpts); } catch {}
                      try { res.clearCookie(CSRF_COOKIE_NAME, clearOpts); } catch {}
                      res.status(204).end(); };
  return req.session ? req.session.destroy(done) : done();
}

// dataURL → Buffer
function decodeDataURL(dataURL) {
  const raw = String(dataURL || "");
  if (!raw.startsWith("data:")) return null;

  const commaIdx = raw.indexOf(",");
  if (commaIdx < 0) return null;
  const meta = raw.slice(5, commaIdx); // strip "data:"
  const payload = raw.slice(commaIdx + 1);
  if (!payload) return null;

  const metaParts = meta.split(";").map((s) => s.trim()).filter(Boolean);
  if (!metaParts.length) return null;

  const mime = metaParts[0].toLowerCase();
  const isBase64 = metaParts.slice(1).some((p) => p.toLowerCase() === "base64");
  if (!isBase64) return null;

  let buf;
  try { buf = Buffer.from(payload, "base64"); }
  catch { return null; }

  const map = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/webp": "webp", "image/gif": "gif",
    "audio/webm;codecs=opus": "webm", "audio/webm": "webm",
    "audio/ogg": "ogg", "audio/ogg;codecs=opus": "ogg",
    "audio/mpeg": "mp3", "audio/wav": "wav", "audio/x-wav": "wav",
    "audio/mp4": "m4a", "audio/aac": "m4a", "audio/mp4;codecs=mp4a.40.2": "m4a",
  };

  const fullMime = mime;
  const baseMime = mime.split(";")[0];
  const ext =
    map[fullMime] || map[baseMime] ||
    (baseMime.startsWith("image/") ? baseMime.split("/")[1] : null) ||
    (baseMime.startsWith("audio/") ? baseMime.split("/")[1] : null) || "bin";

  return { mime: fullMime, buf, ext };
}

// NS 추출(화이트리스트)
function getNS(req) {
  const norm = (s='') => String(s).trim().toLowerCase();
  const raw = norm(req.body?.ns || req.query?.ns || '');
  if (isEmail(raw)) return raw;
  return emailNS(req, null) || "";
}

// ──────────────────────────────────────────────────────────
// 보안/미들웨어
// ──────────────────────────────────────────────────────────
app.disable("x-powered-by");

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
        "img-src": [
          "'self'", "data:", "blob:",
          ...(process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean)
        ],
        "media-src": [
          "'self'", "data:", "blob:",
          ...(process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean)
         ],
        "worker-src": ["'self'", "blob:"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(express.json({ limit: "5mb" }));
const bigJson = express.json({ limit: "30mb" });
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(SESSION_SECRET));
app.use(compression({
  filter: (req, res) => {
    const ct = String(res.getHeader("Content-Type")||"").toLowerCase();
    if (ct.startsWith("audio/")) return false;
    return compression.filter(req, res);
  }
}));

// 세션
const SqliteStore = SqliteStoreFactory(session);
const sessionDB = new Sqlite(path.join(DATA_DIR, "sessions.sqlite"));
const MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7;
const MAX_AGE_SEC = Math.floor(MAX_AGE_MS / 1000);

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
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: CROSS_SITE ? "none" : "lax",
    secure: PROD || CROSS_SITE,
    path: "/",
    maxAge: MAX_AGE_MS,
    ...(CROSS_SITE ? { partitioned: true } : {}),
  },
});
app.use(sessionMiddleware);
app.use("/api", nfcRoutes);

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
    ...(CROSS_SITE ? { partitioned: true } : {}),
  },
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
  try {
    if (!getUserById) {
      console.warn("[getUserRowOrNull] getUserById function is not available");
      return null;
    }
    return getUserById(uid);
  } catch (err) {
    console.error(`[getUserRowOrNull] Error getting user ${uid}:`, err?.message || err);
    return null;
  }
}
function requireAdmin(req, res, next) {
  if (!req.session?.uid) {
    console.log("[requireAdmin] No session UID");
    return res.status(401).json({ ok:false, error:"auth_required" });
  }
  const row = getUserRowOrNull(req.session.uid);
  if (!row) {
    console.log(`[requireAdmin] User not found for UID: ${req.session.uid}`);
    return res.status(403).json({ ok:false, error:"user_not_found" });
  }
  if (!isAdminEmail(row.email)) {
    console.log(`[requireAdmin] User ${row.email} is not an admin`);
    return res.status(403).json({ ok:false, error:"not_admin" });
  }
  return next();
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
      _userColsCache = null;
    } catch {}
  }
}
// ──────────────────────────────────────────────────────────
// Public profile helpers
// ──────────────────────────────────────────────────────────
const AVATAR_TTL_MS = 10_000;
const _avatarCache = new Map();

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
  const dn = getDisplayNameById(userRow.id) || (email ? email.split("@")[0] : null);
  return {
    id: userRow.id,
    email,
    displayName: dn,
    avatarUrl: latestAvatarUrl(userRow.id)
  };
}

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
function setUserDisplayName(uid, name) {
  ensureDisplayNameColumn();
  const info = db.prepare("UPDATE users SET display_name=? WHERE id=?").run(name, uid);
  return info.changes > 0;
}

const PwChange = z.object({
  currentPassword: z.string().min(1).max(200),
  newPassword: z.string().min(8).max(200)
}).or(z.object({
  currentPassword: z.string().min(1).max(200),
  password: z.string().min(8).max(200)
}).transform(v => ({ currentPassword: v.currentPassword, newPassword: v.password })));

const NameChange = z.object({
  displayName: z.string().trim().min(1).max(60)
}).or(z.object({
  name: z.string().trim().min(1).max(60)
}).transform(v => ({ displayName: v.name })));

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
  return res.json({ ok:true, user:{ id:u.id, email:u.email, displayName } });
}

const EmailPw = z.object({
  email: z.string().email().max(200),
  password: z.string().min(8).max(200),
});

// ──────────────────────────────────────────────────────────
// 인증 라우트
// ──────────────────────────────────────────────────────────

// [NEW] Keepalive ping (GET)
app.get("/auth/ping", (req, res) => {
  sendNoStore(res);
  try {
    if (req.session) {
      req.session.lastPingAt = Date.now();
      if (typeof req.session.touch === "function") req.session.touch();
    }
  } catch {}
  return res.json(statusPayload(req));
});

app.get("/auth/csrf", csrfProtection, (req, res) => {
  return res.json({ csrfToken: req.csrfToken() });
});

app.post("/auth/signup", csrfProtection, async (req, res) => {
  const parsed = EmailPw.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: "INVALID" });

  const { email, password } = parsed.data;
  const normEmail = String(email || "").toLowerCase();

  const hash = await argon2.hash(password, {
    type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1,
  });

  try {
    const userId = createUser(normEmail, hash);

    // 1) 상태 초기화 (멱등)
    try { deleteAllStatesForEmail(normEmail); } catch {}
    // 2) 파일 네임스페이스 초기화: audlab/<email>, uploads/<email> 모두 제거
    try { removeUserAssets(normEmail /* email only */); } catch {}

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

// 명시적 로그아웃
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

// 마지막 탭 종료/비콘 로그아웃
app.post("/auth/logout-beacon", (req, res) => {
  const origin = req.get("origin");
  const host = req.get("host");
  const clearOpts = { path: "/", sameSite: CROSS_SITE ? "none" : "lax", secure: PROD || CROSS_SITE };
  if (origin) {
    try {
      const u = new URL(origin);
      if (u.host !== host) return res.status(403).json({ ok: false });
    } catch {}
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

app.post("/api/audlab/submit", requireLogin, bigJson, async (req, res) => {
  try {
    const slot = ensureUserAudlabDir(req);
    if (!slot) return res.status(400).json({ ok:false, error:"ns_unavailable" });

    const { ns, dir } = slot;
    const id = `lab_${Date.now()}`;

    // 1) strokes(Optional) & preview image
    const strokes = Array.isArray(req.body?.strokes) ? req.body.strokes : []; 

    // 2) 프리뷰 이미지는 선택(있으면 저장)
    let previewUrl = "";

    // 2.5) 오디오(dataURL) 저장(선택)
    let audioExt = null;
    const audioRaw = req.body?.audioDataURL || "";
    if (audioRaw) {
      const decodedAud = decodeDataURL(audioRaw);
      if (!decodedAud || !/^audio\//.test(decodedAud.mime)) {
        return res.status(400).json({ ok:false, error:"bad_audio_mime" });
      }
      // 최대 20MB
      if (decodedAud.buf.length > 20 * 1024 * 1024) {
        return res.status(413).json({ ok:false, error:"audio_too_large" });
      }
      audioExt = (decodedAud.ext || "webm").replace("mpeg","mp3");
      fs.writeFileSync(path.join(dir, `${id}.${audioExt}`), decodedAud.buf);
    }
    const previewRaw = req.body?.previewDataURL || req.body?.thumbDataURL || "";
    if (previewRaw) {
      const decodedImg = decodeDataURL(previewRaw);
      if (!decodedImg || !/^image\//.test(decodedImg.mime) || !isAllowedImageMime(decodedImg.mime)) {
        return res.status(400).json({ ok:false, error:"bad_preview_mime" });
      }
      if (decodedImg.buf.length > 8 * 1024 * 1024) {
        return res.status(413).json({ ok:false, error:"image_too_large" });
      }
      const imgExt  = decodedImg.ext || "png";
      fs.writeFileSync(path.join(dir, `${id}.${imgExt}`), decodedImg.buf);
      previewUrl = `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${imgExt}`;
    }

    // 3) 타이밍/메타
    const width      = Number(req.body?.width  || 0);
    const height     = Number(req.body?.height || 0);
    const startedAt  = Number(req.body?.startedAt || Date.now());
    const endedAt    = Number(req.body?.endedAt   || Date.now());
    const durationMs = Number(req.body?.durationMs || Math.max(0, endedAt - startedAt));

    // author 메타(있으면 풍부하게)
    const author = (() => {
      try {
        const row = (typeof getUserByEmail === "function") ? getUserByEmail(ns) : null;
        return row ? {
          id: row.id ?? null,
          email: row.email ?? ns,
          displayName: getDisplayNameById?.(row.id) || (row.email ? row.email.split("@")[0] : null),
          avatarUrl: latestAvatarUrl?.(row.id) || null
        } : { id: ns, email: ns, displayName: (ns.split("@")[0] || null), avatarUrl: null };
      } catch {
        return { id: ns, email: ns, displayName: (ns.split("@")[0] || null), avatarUrl: null };
      }
    })();

    // 4) JSON 메타(이미지/오디오/strokes 저장)
    const meta = {
      id, ns, author,
      width, height,
      startedAt, endedAt, durationMs,
      createdAt: Date.now(),
      strokes,
      audioExt: audioExt || undefined,
      ext: previewUrl ? (previewUrl.split(".").pop().toLowerCase()) : null,
      mime: previewUrl ? (previewUrl.endsWith(".png") ? "image/png"
                 : previewUrl.endsWith(".webp") ? "image/webp"
                 : previewUrl.endsWith(".jpg") || previewUrl.endsWith(".jpeg") ? "image/jpeg"
                 : null) : null,
      previewDataURL: previewRaw || null
    };
    fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(meta));

    // 5) 응답 (신규 키 + 하위호환)
    const base = `/uploads/audlab/${encodeURIComponent(ns)}/${id}`;
    return res.json({
      ok: true,
      id, ns,
      jsonUrl: `${base}.json`,
      previewUrl: previewUrl || null,
      // 레거시 키(기존 프런트가 기대할 수도 있음)
      json:  `${base}.json`,
      ...(previewUrl ? { image: previewUrl } : {})
    });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"submit_failed" });
  }
});

// ──────────────────────────────────────────────────────────
// [ADD] AudLab 캔버스 녹화 업로드 (video/webm)
// POST multipart/form-data:
//  - record: Blob(webm)
//  - meta:   JSON string { id?, startedAt, endedAt, width, height, fps, note? }
// why: me 페이지에서 Play~Submit 구간을 그대로 저장 → adminme에서 재현
// ──────────────────────────────────────────────────────────
app.post("/api/audlab/record", requireLogin, videoUpload.single("record"), (req, res) => {
  try {
    const slot = ensureUserAudlabDir(req);
    if (!slot) return res.status(400).json({ ok:false, error:"ns_unavailable" });
    const { ns, dir } = slot;

    const f = req.file;
    if (!f || !f.buffer || !f.mimetype) {
      return res.status(400).json({ ok:false, error:"missing_record" });
    }
    const mime = String(f.mimetype).toLowerCase();
    const baseMime = mime.split(";")[0];
    if (!ALLOWED_WEBM_VIDEO.has(mime) && !ALLOWED_WEBM_VIDEO.has(baseMime)) {
      return res.status(415).json({ ok:false, error:"unsupported_media_type" });
    }

    let meta = {};
    try { meta = JSON.parse(String(req.body?.meta || "{}")); } catch {}
    const id = String(meta?.id || `rec_${Date.now()}`);

    const webmPath = path.join(dir, `${id}.webm`);
    const jsonPath = path.join(dir, `${id}.json`);

    // 안전가드: 경로 탈출 방지
    if (!webmPath.startsWith(dir + path.sep) || !jsonPath.startsWith(dir + path.sep)) {
      return res.status(400).json({ ok:false, error:"bad_path" });
    }

    fs.writeFileSync(webmPath, f.buffer);
    const startedAt = Number(meta?.startedAt || Date.now());
    const endedAt   = Number(meta?.endedAt   || Date.now());
    const durationMs= Math.max(0, endedAt - startedAt);

    // 기존 submit 메타와 호환되도록 author/ns 필드 구성
    let author = null;
    try {
      const row = typeof getUserByEmail === "function" ? getUserByEmail(ns) : null;
      author = row ? {
        id: row.id ?? null,
        email: row.email ?? ns,
        displayName: getDisplayNameById?.(row.id) || (row.email ? row.email.split("@")[0] : null),
        avatarUrl: latestAvatarUrl?.(row.id) || null
      } : { id: ns, email: ns, displayName: (ns.split("@")[0] || null), avatarUrl: null };
    } catch { author = { id: ns, email: ns, displayName: (ns.split("@")[0] || null), avatarUrl: null }; }

    const metaOut = {
      id, ns, author,
      width: Number(meta?.width || 0),
      height: Number(meta?.height || 0),
      fps: Number(meta?.fps || 60),
      startedAt, endedAt, durationMs,
      createdAt: Date.now(),
      ext: "webm",
      mime: "video/webm",
      note: typeof meta?.note === "string" ? meta.note : null
    };
    fs.writeFileSync(jsonPath, JSON.stringify(metaOut));

    const base = `/uploads/audlab/${encodeURIComponent(ns)}/${id}`;
    return res.json({ ok:true, id, ns, video: `${base}.webm`, json: `${base}.json` });
  } catch (e) {
    console.log("[/api/audlab/record] fatal:", e?.message || e);
    return res.status(500).json({ ok:false, error:"record_failed" });
  }
});

// [ADD] DELETE /auth/me
app.delete("/auth/me", requireLogin, csrfProtection, handleAccountDelete);
// [ADD] DELETE /api/users/me
app.delete("/api/users/me", requireLogin, csrfProtection, handleAccountDelete);
// [ADD] POST /auth/delete
app.post("/auth/delete", requireLogin, csrfProtection, handleAccountDelete);

/**
 * GET /api/audlab/list
 */
app.get("/api/audlab/list", requireLogin, (req, res) => {
  try {
    const slot = ensureUserAudlabDir(req);
    if (!slot) return res.status(400).json({ ok:false, error:"ns_unavailable" });
    const { ns, dir } = slot;

    const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
    const ids = files.filter(f => f.endsWith(".json")).map(f => f.replace(/\.json$/,""));
    ids.sort((a,b) => (b > a ? 1 : -1));

    const items = ids.slice(0, 200).map(id => {
      const metaPath = path.join(dir, `${id}.json`);
      let meta = null;
      try { meta = JSON.parse(fs.readFileSync(metaPath, "utf8")); } catch {}

      let metaAudioExt = meta?.audioExt ? String(meta.audioExt).toLowerCase() : null;
      if (metaAudioExt && !AUDIO_EXTS.includes(metaAudioExt)) metaAudioExt = null;
      const imgExt = findFirstExisting(dir, id, IMAGE_EXTS) || meta?.ext || "png";

      let audExt = null;
      if (metaAudioExt) {
        const audioPath = path.join(dir, `${id}.${metaAudioExt}`);
        if (fs.existsSync(audioPath)) audExt = metaAudioExt;
      }
      if (!audExt) {
        audExt = findFirstExisting(dir, id, AUDIO_EXTS_LEGACY);
      }

      let vidExt = findFirstExisting(dir, id, VIDEO_EXTS);
      if (audExt && vidExt && audExt === vidExt && metaAudioExt === audExt) {
        vidExt = null;
      }

      const base = `/uploads/audlab/${encodeURIComponent(ns)}/${id}`;
      return {
        id,
        json:  `${base}.json`,
        image: `${base}.${imgExt}`,
        ...(vidExt ? { video: `${base}.${vidExt}` } : {}),
        ...(audExt ? { audio: `${base}.${audExt}` } : {}),
        ...(meta?.durationMs ? { durationMs: Number(meta.durationMs) } : {})
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

app.get("/api/users/me", requireLogin, (req, res) => meHandler(req, res));

app.post(
  "/api/users/me/avatar",
  requireLogin,
  csrfProtection,
  upload.any(),
  async (req, res) => {
    const uid = req.session?.uid;
    if (!uid) return res.status(401).json({ ok:false, msg:"로그인이 필요합니다." });

    const files = Array.isArray(req.files) ? req.files : [];
    const picked =
      files.find(f => ["avatar","file","image","photo"].includes(f.fieldname)) ||
      files[0] || null;

    let buf = picked?.buffer || null;
    if (picked && !isAllowedImageMime(picked.mimetype)) {
      return res.status(400).json({ ok:false, msg:"bad_image_mime" });
    }

    if (!buf) {
      const raw =
        req.body?.avatar ||
        req.body?.dataURL ||
        req.body?.dataUrl ||
        req.body?.avatarDataURL ||
        req.body?.thumbDataURL || "";
      const decoded = decodeDataURL(raw);
      if (decoded && (!/^image\//.test(decoded.mime) || !isAllowedImageMime(decoded.mime))) {
        return res.status(400).json({ ok:false, msg:"bad_image_mime" });
      }
      if (decoded && decoded.buf.length > 8 * 1024 * 1024) {
        return res.status(413).json({ ok:false, msg:"image_too_large" });
      }
      if (decoded) { buf = decoded.buf; }
    }

    if (!buf) return res.status(400).json({ ok:false, msg:"파일이 없습니다." });

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
    if (!res.getHeader("Access-Control-Allow-Origin")) {
      res.set("Access-Control-Allow-Origin", "*");
      res.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      res.set("Access-Control-Allow-Headers", "Range, Content-Type");
    }
    res.set("Cross-Origin-Resource-Policy", "cross-origin");
    res.set("Accept-Ranges", "bytes");
    res.set("Cache-Control", "public, max-age=31536000, immutable");
  }
}));

// === Admin-only endpoints (audlab) ===
const adminRouter = express.Router();

const AUDLAB_STATUS = {
  SUBMITTED: "submitted",
  DEVELOPING: "developing",
  DEVELOPED: "developed",
};
const VALID_AUDLAB_STATUS = new Set(Object.values(AUDLAB_STATUS));

function readAudlabIndex(dir) {
  const indexPath = path.join(dir, "_index.json");
  try {
    const raw = fs.readFileSync(indexPath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAudlabIndex(dir, rows) {
  const indexPath = path.join(dir, "_index.json");
  fs.writeFileSync(indexPath, JSON.stringify(rows));
}

function mutateAudlabStatus(ns, id, nextStatus) {
  const safeNs = nsSafe(ns);
  const dir = path.join(AUDLAB_ROOT, safeNs);
  if (!fs.existsSync(dir)) return { ok: false, error: "not_found" };

  const now = Date.now();
  let idx = readAudlabIndex(dir);
  let hit = null;
  let found = false;

  idx = idx.map((entry) => {
    if (String(entry.id) !== String(id)) return entry;
    found = true;
    const next = {
      ...entry,
      accepted: nextStatus !== AUDLAB_STATUS.SUBMITTED ? true : !!entry.accepted,
      status: nextStatus,
      updatedAt: now,
    };
    hit = next;
    return next;
  });

  if (!found) {
    const metaPath = path.join(dir, `${id}.json`);
    if (!fs.existsSync(metaPath)) return { ok: false, error: "not_found" };
    let meta = {};
    try { meta = JSON.parse(fs.readFileSync(metaPath, "utf8")); } catch {}
    const next = {
      id,
      ns,
      label: meta?.label || "",
      createdAt: meta?.createdAt || Date.now(),
      width: Number(meta?.width || 0),
      height: Number(meta?.height || 0),
      ext: meta?.ext || "png",
      mime: meta?.mime || "image/png",
      author: meta?.author || null,
      accepted: nextStatus !== AUDLAB_STATUS.SUBMITTED,
      status: nextStatus,
      updatedAt: now,
    };
    idx.unshift(next);
    hit = next;
  }

  writeAudlabIndex(dir, idx);

  const metaPath = path.join(dir, `${id}.json`);
  try {
    const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
    meta.accepted = nextStatus !== AUDLAB_STATUS.SUBMITTED ? true : !!meta.accepted;
    meta.status = nextStatus;
    meta.updatedAt = now;
    fs.writeFileSync(metaPath, JSON.stringify(meta));
  } catch {}

  return { ok: true, entry: hit };
}

function ensureDevelopedBadge(ns) {
  try {
    const email = String(ns || "").trim().toLowerCase();
    if (!EMAIL_RX.test(email)) return false;
    const user = getUserByEmail(email);
    if (!user) return false;

    const snap = getUserState(user.id, email);
    const baseState = snap && typeof snap.state === "object" && snap.state ? { ...snap.state } : {};
    const badges = baseState.badges && typeof baseState.badges === "object" ? { ...baseState.badges } : {};

    if (badges.audLabDeveloped) return false;

    badges.audLabDeveloped = true;
    baseState.badges = badges;
    putUserState(user.id, email, baseState, Date.now());
    return true;
  } catch (e) {
    console.log("[audlab] badge update failed:", e?.message || e);
    return false;
  }
}
try { fs.mkdirSync(AUDLAB_ROOT, { recursive: true }); } catch {}

const nsSafe = (s) => encodeURIComponent(String(s||"").trim().toLowerCase());

// [NEW] 관리자 리더보드 (Top10): 포스팅 수 / 받은 투표 수 / 투표 일치율
// === Admin Leaderboards: gallery(UPLOAD_ROOT) + audlab(AUDLAB_ROOT) 모두 집계 ===
adminRouter.get("/admin/leaderboards", requireAdmin, (req, res) => {
  try {
    const EMAIL_RX = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
    const isEmail = s => EMAIL_RX.test(String(s || "").trim());
    const norm = s => String(s || "").trim().toLowerCase();

    const EXT_IMG = ["png","jpg","jpeg","webp","gif"];

    // ns → dir path helpers
    const dirForUploadNS = (ns) => path.join(UPLOAD_ROOT, encodeURIComponent(String(ns).toLowerCase()));
    const dirForAudlabNS  = (ns) => path.join(AUDLAB_ROOT, encodeURIComponent(String(ns).toLowerCase()));

    // 1) 이메일 형태의 NS 디렉토리 나열 (avatars 제외)
    const nsDirs = [];
    if (fs.existsSync(UPLOAD_ROOT)) {
      for (const d of fs.readdirSync(UPLOAD_ROOT, { withFileTypes:true })) {
        if (!d.isDirectory()) continue;
        if (d.name === "avatars") continue;
        const ns = decodeURIComponent(d.name);
        if (isEmail(ns)) nsDirs.push(ns.toLowerCase());
      }
    }
    // audlab 쪽에만 존재하는 ns도 포함
    if (fs.existsSync(AUDLAB_ROOT)) {
      for (const d of fs.readdirSync(AUDLAB_ROOT, { withFileTypes:true })) {
        if (!d.isDirectory()) continue;
        const ns = decodeURIComponent(d.name);
        if (isEmail(ns)) {
          const n = ns.toLowerCase();
          if (!nsDirs.includes(n)) nsDirs.push(n);
        }
      }
    }

    // 2) 갤러리(_index.json 없으면 파일 목록)에서 아이템(id/label) 읽기
    function readGalleryItems(ns) {
      const dir = dirForUploadNS(ns);
      const indexPath = path.join(dir, "_index.json");
      let out = [];

      try {
        const idx = JSON.parse(fs.readFileSync(indexPath, "utf8"));
        if (Array.isArray(idx)) {
          out = idx.map(m => ({
            id: String(m?.id || ""),
            label: norm(m?.label || "")
          })).filter(x => x.id);
        }
      } catch {}

      // 인덱스가 비었으면 파일에서 추론
      if (!out.length) {
        try {
          const files = fs.readdirSync(dir).filter(f => {
            const low = f.toLowerCase();
            return EXT_IMG.some(e => low.endsWith("." + e));
          });
          out = files.map(f => ({
            id: f.replace(/\.(png|jpe?g|gif|webp)$/i, ""),
            label: ""    // 갤러리 파일만으로는 정답 라벨을 알 수 없으니 빈 값
          }));
        } catch {}
      }
      return out;
    }

    // 3) audlab(_index.json 우선, 없으면 *.json 메타)에서 아이템(id/label) 읽기
    function readAudlabItems(ns) {
      const dir = dirForAudlabNS(ns);
      const indexPath = path.join(dir, "_index.json");
      let out = [];

      // 인덱스 우선
      try {
        const idx = JSON.parse(fs.readFileSync(indexPath, "utf8"));
        if (Array.isArray(idx)) {
          out = idx.map(m => ({
            id: String(m?.id || ""),
            label: norm(m?.label || "")
          })).filter(x => x.id);
        }
      } catch {}

      // 인덱스가 없거나 비면 각 아이템 JSON 스캔
      if (!out.length) {
        try {
          const files = fs.readdirSync(dir).filter(f => f.endsWith(".json") && f !== "_index.json");
          for (const jf of files) {
            const id = jf.replace(/\.json$/i, "");
            try {
              const meta = JSON.parse(fs.readFileSync(path.join(dir, jf), "utf8"));
              out.push({ id, label: norm(meta?.label || "") });
            } catch {
              out.push({ id, label: "" });
            }
          }
        } catch {}
      }
      return out;
    }

    // 4) 한 NS의 아이템들을 “갤러리 + audlab”에서 모두 모으고, id 기준으로 병합(라벨 있으면 유지)
    function readAllItems(ns) {
      const a = readGalleryItems(ns);
      const b = readAudlabItems(ns);
      const map = new Map();
      for (const it of [...a, ...b]) {
        if (!it.id) continue;
        const prev = map.get(it.id);
        // 라벨 정보가 있는 쪽을 우선
        if (!prev) map.set(it.id, it);
        else if (!prev.label && it.label) map.set(it.id, it);
      }
      return [...map.values()];
    }

    // 5) 투표 집계 쿼리 (라벨 필터 없음)
    const stmtCounts = db.prepare(
      "SELECT label, COUNT(*) AS n FROM item_votes WHERE item_id=? GROUP BY label"
    );

    const winnersOf = (counts) => {
      const entries = Object.entries(counts);
      if (!entries.length) return [];
      const max = Math.max(...entries.map(([,n]) => Number(n||0)), 0);
      if (max <= 0) return [];
      return entries.filter(([,n]) => Number(n||0) === max).map(([k]) => k);
    };

    const perNS = [];
    for (const ns of nsDirs) {
      const items = readAllItems(ns);
      console.log(`[leaderboards] ${ns}: found ${items.length} items`);
      console.log(`[leaderboards] ${ns}: items with labels: ${items.filter(x => x.label).length}`);

      let posts = items.length;
      let votes = 0;
      let participated = 0;
      let matched = 0;

      for (const it of items) {
        const counts = {};
        try {
          for (const r of stmtCounts.all(it.id)) {
            const lb = norm(r.label);
            if (!lb) continue;
            counts[lb] = (counts[lb] || 0) + Number(r.n || 0);
          }
        } catch {}

        const total = Object.values(counts).reduce((s,n)=>s+Number(n||0), 0);
        votes += total;

        if (total > 0) {
          participated++;
          const tops = winnersOf(counts);
          console.log(`[leaderboards] ${ns} item ${it.id}: label="${it.label}", tops=[${tops.join(',')}], counts=`, counts);
          if (it.label && tops.includes(it.label)) matched++;
        }
      }

      console.log(`[leaderboards] ${ns}: posts=${posts}, votes=${votes}, participated=${participated}, matched=${matched}`);
      perNS.push({ ns, posts, votes, participated, matched });
    }

    const withRate = perNS.map(r => ({
      ...r,
      rate: r.participated > 0 ? Math.round((r.matched / r.participated) * 100) : 0,
    }));

    const pickTop = (arr, key, tie=[]) => {
      const sorted = [...arr].sort((a,b) => {
        if (b[key] !== a[key]) return b[key] - a[key];
        for (const t of tie) if (b[t] !== a[t]) return b[t] - a[t];
        return String(a.ns).localeCompare(String(b.ns));
      });
      return sorted.slice(0, 10);
    };

    const decorate = (row) => {
      const email = isEmail(row.ns) ? row.ns : null;
      return {
        ns: row.ns,
        displayName: email ? row.ns.split("@")[0] : row.ns,
        email,
        avatarUrl: null,
        posts: row.posts,
        votes: row.votes,
        participated: row.participated,
        matched: row.matched,
        rate: row.rate,
        author: email
          ? { email, displayName: email.split("@")[0], avatarUrl: null, id: null }
          : null
      };
    };

    const postsTop10 = pickTop(withRate, "posts", ["votes", "participated"]);
    const votesTop10 = pickTop(withRate, "votes", ["posts", "participated"]);
    const rateTop10  = pickTop(withRate, "rate",  ["participated", "votes"]);

    res.json({
      ok: true,
      postsTop10: postsTop10.map(decorate),
      votesTop10: votesTop10.map(decorate),
      rateTop10:  rateTop10 .map(decorate),
      totalAccounts: withRate.length
    });
  } catch (e) {
    console.error("[admin/leaderboards] failed:", e?.stack || e);
    res.status(500).json({ ok:false });
  }
});

// DEBUG: 투표 데이터 확인
adminRouter.get("/admin/debug/votes", requireAdmin, (req, res) => {
  try {
    const totalVotes = db.prepare("SELECT COUNT(*) as total FROM item_votes").get();
    const sampleVotes = db.prepare("SELECT item_id, user_id, label FROM item_votes LIMIT 10").all();
    const votesByItem = db.prepare("SELECT item_id, COUNT(*) as count FROM item_votes GROUP BY item_id LIMIT 10").all();

    // 갤러리 아이템 샘플
    const ns = "jwyang29@snu.ac.kr";
    const items = [];
    const dirForUploadNS = (ns) => path.join(UPLOAD_ROOT, encodeURIComponent(String(ns).toLowerCase()));
    const dir = dirForUploadNS(ns);
    const indexPath = path.join(dir, "_index.json");
    try {
      const idx = JSON.parse(fs.readFileSync(indexPath, "utf8"));
      if (Array.isArray(idx)) {
        items.push(...idx.slice(0, 5).map(m => ({ id: m?.id, label: m?.label })));
      }
    } catch (e) {
      items.push({ error: e.message });
    }

    res.json({
      ok: true,
      totalVotes: totalVotes?.total || 0,
      sampleVotes,
      votesByItem,
      galleryItems: items
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// 특정 NS의 제출물 목록
adminRouter.get("/admin/audlab/list", requireAdmin, (req, res) => {
  try {
    const ns = String(req.query.ns || "").trim().toLowerCase();
    if (!ns) return res.status(400).json({ ok:false, error:"ns_required" });
    if (!isEmail(ns)) return res.status(400).json({ ok:false, error:"bad_ns" });

    const safeNs = nsSafe(ns);
    const dir = path.join(AUDLAB_ROOT, safeNs);
    try { fs.mkdirSync(dir, { recursive:true }); } catch {}

    const files = fs.readdirSync(dir)
      .filter(f => /\.json$/i.test(f))
      .sort()
      .reverse();

    const items = files.slice(0, 200).map(f => {
      const id = f.replace(/\.json$/i, "");

      const metaPath = path.join(dir, `${id}.json`);
      let meta = null;
      try { meta = JSON.parse(fs.readFileSync(metaPath, "utf8")); } catch {}

      const imgExt = findFirstExisting(dir, id, IMAGE_EXTS) || meta?.ext || "png";

      let metaAudioExt = meta?.audioExt ? String(meta.audioExt).toLowerCase() : null;
      if (metaAudioExt && !AUDIO_EXTS.includes(metaAudioExt)) metaAudioExt = null;
      let audExt = null;
      if (metaAudioExt) {
        const audioPath = path.join(dir, `${id}.${metaAudioExt}`);
        if (fs.existsSync(audioPath)) audExt = metaAudioExt;
      }
      if (!audExt) {
        audExt = findFirstExisting(dir, id, AUDIO_EXTS_LEGACY);
      }

      let vidExt = findFirstExisting(dir, id, VIDEO_EXTS) || (meta?.ext === "webm" ? "webm" : null);
      if (audExt && vidExt && audExt === vidExt && metaAudioExt === audExt) {
        vidExt = null;
      }

      let user = null;
      if (meta?.author) {
        user = {
          id: meta.author.id ?? null,
          email: meta.author.email ?? null,
          displayName: meta.author.displayName ?? null,
          avatarUrl: meta.author.avatarUrl ?? null,
        };
      }

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
          } catch {}
        }
      }

      if (!user) user = { id: ns, email: null, displayName: null, avatarUrl: null };

      const out = {
        id,
        json:  `/uploads/audlab/${safeNs}/${id}.json`,
        image: `/uploads/audlab/${safeNs}/${id}.${imgExt}`,
        ...(vidExt ? { video: `/uploads/audlab/${safeNs}/${id}.${vidExt}` } : {}),
        ...(audExt ? { audio: `/uploads/audlab/${safeNs}/${id}.${audExt}` } : {}),
        user,
        previewDataURL: meta?.previewDataURL || null,
      };
      return out;
    });

    res.json({ ok:true, ns, items });
  } catch {
    res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

adminRouter.get("/admin/audlab/all", requireAdmin, (req, res) => {
  try {
    const EXT_MIME = { png:"image/png", jpg:"image/jpeg", jpeg:"image/jpeg", webp:"image/webp", gif:"image/gif" };

    const nses = fs.readdirSync(AUDLAB_ROOT, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => decodeURIComponent(d.name))
      .sort();

    const items = [];

    for (const ns of nses) {
      const dir = path.join(AUDLAB_ROOT, encodeURIComponent(ns));

      const jsonFiles = fs.readdirSync(dir)
        .filter(f => f.endsWith(".json") && f !== "_index.json");

      for (const jf of jsonFiles) {
        const id = jf.replace(/\.json$/i, "");
        const jPath = path.join(dir, jf);

        let meta = null;
        try { meta = JSON.parse(fs.readFileSync(jPath, "utf8")); } catch {}

        const imgExt = findFirstExisting(dir, id, IMAGE_EXTS) || meta?.ext || "png";

        let metaAudioExt = meta?.audioExt ? String(meta.audioExt).toLowerCase() : null;
        if (metaAudioExt && !AUDIO_EXTS.includes(metaAudioExt)) metaAudioExt = null;
        let audExt = null;
        if (metaAudioExt) {
          const audioPath = path.join(dir, `${id}.${metaAudioExt}`);
          if (fs.existsSync(audioPath)) audExt = metaAudioExt;
        }
        if (!audExt) {
          audExt = findFirstExisting(dir, id, AUDIO_EXTS_LEGACY);
        }

        let vidExt = findFirstExisting(dir, id, VIDEO_EXTS) || (meta?.ext === "webm" ? "webm" : null);
        if (audExt && vidExt && audExt === vidExt && metaAudioExt === audExt) {
          vidExt = null;
        }

        let user = null;
        if (meta?.author?.id || meta?.author?.email || meta?.author?.displayName) {
          user = {
            id: meta.author.id ?? null,
            email: meta.author.email ?? null,
            displayName: meta.author.displayName ?? null,
            avatarUrl: meta.author.avatarUrl ?? null,
          };
        // ★ 보정: 파일이 들어있는 ns와 meta.author.email이 다르면 ns 기준으로 덮어쓰기
        if (!user || (user.email && String(user.email).toLowerCase() !== String(ns).toLowerCase())) {
          const row = (typeof getUserByEmail === "function") ? getUserByEmail(String(ns).toLowerCase()) : null;
          user = row ? {
            id: row.id,
            email: row.email,
            displayName: getDisplayNameById?.(row.id) || (row.email ? row.email.split("@")[0] : null),
            avatarUrl: latestAvatarUrl?.(row.id) || null,
          } : {
            id: ns, email: ns, displayName: (String(ns).split("@")[0] || null), avatarUrl: null
          };
        }
        } else {
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
          if (!user) user = { id: ns, email: null, displayName: null, avatarUrl: null };
        }

        const createdAt = Number(meta?.createdAt ?? meta?.created_at ?? 0) ||
                          (() => { try { return Math.floor(fs.statSync(jPath).mtimeMs); } catch { return Date.now(); } })();

        items.push({
          id,
          ns,
          createdAt,
          width: Number(meta?.width || 0),
          height: Number(meta?.height || 0),
          label: String(meta?.label || ""),
          caption: typeof meta?.caption === "string" ? meta.caption
                 : (typeof meta?.text === "string" ? meta.text : ""),
          bg: meta?.bg || meta?.bg_color || meta?.bgHex || null,
          json:  `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`,
          image: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${imgExt}`,
          ...(vidExt ? { video: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${vidExt}` } : {}),
          ...(audExt ? { audio: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${audExt}` } : {}),
          user,
          mime: EXT_MIME[imgExt] || meta?.mime || null,
          audioExt: audExt || null,
          accepted: !!meta?.accepted,
          status: meta?.status || (meta?.accepted ? AUDLAB_STATUS.DEVELOPING : AUDLAB_STATUS.SUBMITTED),
          previewDataURL: meta?.previewDataURL || null,
        });
      }
    }

    items.sort((a,b) => (b.createdAt - a.createdAt) || (a.id < b.id ? 1 : -1));

    return res.json({ ok: true, items });
  } catch (e) {
    console.log("[/admin/audlab/all] failed:", e?.message || e);
    return res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

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

    const imgExt = findFirstExisting(dir, id, IMAGE_EXTS) || j.ext || "png";

    let metaAudioExt = j?.audioExt ? String(j.audioExt).toLowerCase() : null;
    if (metaAudioExt && !AUDIO_EXTS.includes(metaAudioExt)) metaAudioExt = null;
    let audExt = null;
    if (metaAudioExt) {
      const audioPath = path.join(dir, `${id}.${metaAudioExt}`);
      if (fs.existsSync(audioPath)) audExt = metaAudioExt;
    }
    if (!audExt) {
      audExt = findFirstExisting(dir, id, AUDIO_EXTS_LEGACY);
    }

    let vidExt = findFirstExisting(dir, id, VIDEO_EXTS) || (j.ext === "webm" ? "webm" : null);
    if (audExt && vidExt && audExt === vidExt && metaAudioExt === audExt) {
      vidExt = null;
    }

    const strokes = Array.isArray(j.strokes) ? j.strokes : [];
    const width = Number(j.width || 0);
    const height = Number(j.height || 0);
    const status = j?.status || (j?.accepted ? AUDLAB_STATUS.DEVELOPING : AUDLAB_STATUS.SUBMITTED);

    res.json({
      ok:true, ns, id,
      meta: { strokeCount: strokes.length, pointCount, width, height },
      width,
      height,
      strokes,
      status,
      jsonUrl:  `/uploads/audlab/${nsSafe(ns)}/${id}.json`,
      imageUrl: `/uploads/audlab/${nsSafe(ns)}/${id}.${imgExt}`,
      ...(vidExt ? { videoUrl: `/uploads/audlab/${nsSafe(ns)}/${id}.${vidExt}` } : {}),
      ...(audExt ? { audioUrl: `/uploads/audlab/${nsSafe(ns)}/${id}.${audExt}` } : {})
    });
  } catch {
    res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

adminRouter.post("/admin/audlab/accept", requireAdmin, csrfProtection, (req, res) => {
  try {
    const ns = String(req.body?.ns || "").trim();
    const id = String(req.body?.id || "").trim();
    if (!ns || !id) return res.status(400).json({ ok:false, error:"ns_and_id_required" });

    const result = mutateAudlabStatus(ns, id, AUDLAB_STATUS.DEVELOPING);
    if (!result.ok) {
      const code = result.error === "not_found" ? 404 : 400;
      return res.status(code).json({ ok:false, error: result.error || "status_update_failed" });
    }

    return res.json({ ok:true, status: AUDLAB_STATUS.DEVELOPING });
  } catch (e) {
    console.log("[/admin/audlab/accept] failed:", e?.message || e);
    return res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

adminRouter.post("/admin/audlab/status", requireAdmin, csrfProtection, (req, res) => {
  try {
    const ns = String(req.body?.ns || "").trim();
    const id = String(req.body?.id || "").trim();
    const statusRaw = String(req.body?.status || "").trim().toLowerCase();
    if (!ns || !id) return res.status(400).json({ ok:false, error:"ns_and_id_required" });
    if (!VALID_AUDLAB_STATUS.has(statusRaw) || statusRaw === AUDLAB_STATUS.SUBMITTED) {
      return res.status(400).json({ ok:false, error:"invalid_status" });
    }

    const result = mutateAudlabStatus(ns, id, statusRaw);
    if (!result.ok) {
      const code = result.error === "not_found" ? 404 : 400;
      return res.status(code).json({ ok:false, error: result.error || "status_update_failed" });
    }

    if (statusRaw === AUDLAB_STATUS.DEVELOPED) {
      const badgeGranted = ensureDevelopedBadge(ns);
      if (badgeGranted && io) {
        io.to(`user:${ns}`).emit("badge:granted", { badge: "audLabDeveloped", ns });
      }
    }

    return res.json({ ok:true, status: statusRaw });
  } catch (e) {
    console.log("[/admin/audlab/status] failed:", e?.message || e);
    return res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

app.use("/api", adminRouter);

function adminBootstrapHandler(req, res) {
  try {
    const row = getUserById(req.session.uid);
    const admin = !!(row && isAdminEmail(row.email));
    res.json({ ok: true, admin, email: row?.email || null });
  } catch {
    res.status(500).json({ ok:false });
  }
}

// 두 경로 모두 허용 (프런트/구버전 호환)
app.get("/api/audlab/admin/bootstrap", requireLogin, adminBootstrapHandler);
app.get("/api/admin/audlab/bootstrap", requireLogin, adminBootstrapHandler);


// 비밀번호 변경
app.post("/auth/password",        requireLogin, csrfProtection, applyPasswordChange);
app.post("/auth/change-password", requireLogin, csrfProtection, applyPasswordChange);
app.put ("/api/users/me/password",requireLogin, csrfProtection, applyPasswordChange);

// 이름 변경
app.post("/auth/profile", requireLogin, csrfProtection, applyNameChange);
app.put ("/api/users/me", requireLogin, csrfProtection, applyNameChange);

// 혼합 PATCH
app.patch("/auth/me", requireLogin, csrfProtection, async (req, res) => {
  const hasPw =
    typeof req.body?.currentPassword === "string" &&
    (typeof req.body?.newPassword === "string" || typeof req.body?.password === "string");
  const hasName =
    typeof req.body?.displayName === "string" || typeof req.body?.name === "string";

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

// me & ping
function meHandler(req, res) {
  sendNoStore(res);
  const base = statusPayload(req);
  if (!base.authenticated) return res.json(base);

  const u = getUserById(req.session.uid);

  let displayName = null;
  try {
    const cols = db.prepare("PRAGMA table_info(users)").all().map(r => String(r.name));
    if (cols.includes("display_name")) {
      const r = db.prepare("SELECT display_name FROM users WHERE id=?").get(req.session.uid);
      displayName = r?.display_name || null;
    }
  } catch {}

  const avatarUrl = latestAvatarUrl(req.session.uid);

  const payload = {
    ...base,
    user: u ? { id: u.id, email: u.email, displayName } : null,
    ns: String(u?.email || "").toLowerCase(),
  };
  if (u) {
    payload.email = u.email;
    payload.displayName = displayName;
    payload.name = displayName;
    payload.avatarUrl = avatarUrl;
  }
  return res.json(payload);
}
app.get(["/auth/me", "/api/auth/me"], meHandler);

// 경량 헬스체크
app.get("/api/healthz", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ ok: true, bootId: BOOT_ID });
});

// [NEW] Labels catalog (자동 노출용)

// ──────────────────────────────────────────────────────────
// Label Story REST (read/write)
// ──────────────────────────────────────────────────────────

// 공통 리더
function readLabelStory(lbRaw) {
  const lb = normalizeLabel(lbRaw);
  if (!lb) return { code: 400, body: { ok: false, error: "bad_label" } };
  const story = getLabelStory(lb) || "";
  return { code: 200, body: { ok: true, label: lb, story } };
}

function readJibStory(jbRaw) {
  const jb = normalizeJib(jbRaw);
  if (!jb) return { code: 400, body: { ok: false, error: "bad_jib" } };
  const story = getJibStory(jb) || "";
  return { code: 200, body: { ok: true, jib: jb, story } };
}

// READ
app.get("/api/jibbitz/:jib", requireLogin, (req, res) => {
  const r = readJibStory(req.params.jib);
  res.set("Cache-Control", "no-store");
  return res.status(r.code).json(r.body);
});
app.get("/api/jibbitz/:jib/story", requireLogin, (req, res) => {
  const r = readJibStory(req.params.jib);
  res.set("Cache-Control", "no-store");
  return res.status(r.code).json(r.body);
});
app.get("/api/jib/story", requireLogin, (req, res) => {
  const r = readJibStory(req.query.jib);
  res.set("Cache-Control", "no-store");
  return res.status(r.code).json(r.body);
});

// WRITE
app.put("/api/jibbitz/:jib/story", requireLogin, csrfProtection, express.json(), (req, res) => {
  try {
    const jb = normalizeJib(req.params.jib);
    if (!jb) return res.status(400).json({ ok:false, error:"bad_jib" });
    const saved = putJibStory(jb, String(req.body?.story || ""));
    io.to(`jib:${jb}`).emit("jib:story-updated", { jib: jb, story: saved.story });
    return res.json({ ok:true, jib: jb, story: saved.story, updatedAt: saved.updatedAt });
  } catch {
    return res.status(500).json({ ok:false, error:"save_failed" });
  }
});

adminRouter.post("/admin/audlab/delete", requireAdmin, csrfProtection, (req, res) => {
  try {
    const ns = String(req.body?.ns || "").trim();
    const id = String(req.body?.id || "").trim();
    if (!ns || !id) return res.status(400).json({ ok:false, error:"ns_and_id_required" });

    const safeNs = nsSafe(ns);
    const dir = path.join(AUDLAB_ROOT, safeNs);
    if (!dir.startsWith(AUDLAB_ROOT)) {
      return res.status(400).json({ ok:false, error:"bad_ns" });
    }

    const removed = [];

    if (fs.existsSync(dir)) {
      const prefix = `${id}.`;
      const files = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of files) {
        if (!entry.isFile()) continue;
        const name = entry.name;
        if (name === `${id}.json` || name.startsWith(prefix)) {
          const fp = path.join(dir, name);
          try {
            fs.rmSync(fp, { force: true });
            removed.push(name);
          } catch {}
        }
      }

      const indexPath = path.join(dir, "_index.json");
      if (fs.existsSync(indexPath)) {
        try {
          const raw = fs.readFileSync(indexPath, "utf8");
          const parsed = JSON.parse(raw);
          const idx = Array.isArray(parsed) ? parsed : [];
          const next = idx.filter((item) => String(item?.id) !== id);
          if (next.length !== idx.length) {
            fs.writeFileSync(indexPath, JSON.stringify(next));
          }
        } catch {}
      }
    }

    let leftovers = [];
    if (fs.existsSync(dir)) {
      leftovers = fs.readdirSync(dir)
        .filter((name) => name === `${id}.json` || name.startsWith(`${id}.`));
    }

    const ok = leftovers.length === 0;
    const payload = { ok, ns, id, removed, removedCount: removed.length, leftovers };
    if (!ok) {
      return res.status(500).json({ ...payload, error: "delete_incomplete" });
    }
    return res.json(payload);
  } catch (e) {
    console.log("[/admin/audlab/delete] failed:", e?.message || e);
    return res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});
app.post("/api/jib/story", requireLogin, csrfProtection, express.json(), (req, res) => {
  try {
    const jb = normalizeJib(req.body?.jib);
    if (!jb) return res.status(400).json({ ok:false, error:"bad_jib" });
    const saved = putJibStory(jb, String(req.body?.story || ""));
    io.to(`jib:${jb}`).emit("jib:story-updated", { jib: jb, story: saved.story });
    return res.json({ ok:true, jib: jb, story: saved.story, updatedAt: saved.updatedAt });
  } catch {
    return res.status(500).json({ ok:false, error:"save_failed" });
  }
});

// GET: /api/labels/:label  (스토리 조회)
app.get("/api/labels/:label", requireLogin, (req, res) => {
  const r = readLabelStory(req.params.label);
  res.set("Cache-Control", "no-store");
  return res.status(r.code).json(r.body);
});

// GET: /api/labels/:label/story  (스토리 조회 - alias)
app.get("/api/labels/:label/story", requireLogin, (req, res) => {
  const r = readLabelStory(req.params.label);
  res.set("Cache-Control", "no-store");
  return res.status(r.code).json(r.body);
});

// GET: /api/label/story?label=xxx  (레거시 폴백)
app.get("/api/label/story", requireLogin, (req, res) => {
  const r = readLabelStory(req.query.label);
  res.set("Cache-Control", "no-store");
  return res.status(r.code).json(r.body);
});

// PUT: /api/labels/:label/story  (스토리 저장)
app.put("/api/labels/:label/story", requireLogin, csrfProtection, express.json(), (req, res) => {
  try {
    const lb = normalizeLabel(req.params.label);
    if (!lb) return res.status(400).json({ ok: false, error: "bad_label" });
    const saved = putLabelStory(lb, String(req.body?.story || ""));
    io.to(`label:${lb}`).emit("label:story-updated", { label: lb, story: saved.story });
    return res.json({ ok: true, label: lb, story: saved.story, updatedAt: saved.updatedAt });
  } catch {
    return res.status(500).json({ ok: false, error: "save_failed" });
  }
});

// POST: /api/label/story  (레거시 폴백: body {label, story})
app.post("/api/label/story", requireLogin, csrfProtection, express.json(), (req, res) => {
  try {
    const lb = normalizeLabel(req.body?.label);
    if (!lb) return res.status(400).json({ ok: false, error: "bad_label" });
    const saved = putLabelStory(lb, String(req.body?.story || ""));
    io.to(`label:${lb}`).emit("label:story-updated", { label: lb, story: saved.story });
    return res.json({ ok: true, label: lb, story: saved.story, updatedAt: saved.updatedAt });
  } catch {
    return res.status(500).json({ ok: false, error: "save_failed" });
  }
});


app.get("/api/labels/all", requireLogin, (_req, res) => {
  // 필요 시 환경변수로 치환 가능: process.env.LABEL_KEYS
  res.json(["thump","miro","whee","track","echo","portal"]);
});

// [NEW] Jibbitz catalog (자동 노출용)
app.get("/api/jibbitz/catalog", requireLogin, (_req, res) => {
  // 실제로 관리한다면 DB/파일에서 읽도록 바꿔도 OK
  res.json(["bloom","tail","cap","keyring","duck","twinkle","xmas","bunny"]);
});

// ──────────────────────────────────────────────────────────
app.get("/api/state", requireLogin, (req, res) => {
  const ns = emailNS(req, null);
  const row = getUserState(req.session.uid, ns);
  if (!row) return res.json({ ok: true, state: null });
  return res.json({ ok: true, state: row.state, updatedAt: row.updatedAt });
});

app.put("/api/state", requireLogin, csrfProtection, (req, res) => {
  const email = emailNS(req, req.body?.ns);
  const incomingState = req.body.state || req.body;
  const updatedAt = Number(incomingState?.updatedAt || Date.now());

  // 기존 state를 읽어서 badges 보존
  if (email) {
    const user = getUserByEmail(email);
    if (user) {
      const existing = getUserState(user.id, email);
      const existingBadges = existing?.state?.badges;
      if (existingBadges && typeof existingBadges === "object") {
        incomingState.badges = { ...existingBadges, ...(incomingState.badges || {}) };
      }
    }
    putStateByEmail(email, incomingState, updatedAt);
  }
  return res.json({ ok: true, ns: email });
});

app.post("/api/state", requireLogin, csrfProtection, (req, res) => {
  const email = emailNS(req, req.body?.ns);
  const incomingState = req.body.state || req.body;
  const updatedAt = Number(incomingState?.updatedAt || Date.now());

  // 기존 state를 읽어서 badges 보존
  if (email) {
    const user = getUserByEmail(email);
    if (user) {
      const existing = getUserState(user.id, email);
      const existingBadges = existing?.state?.badges;
      if (existingBadges && typeof existingBadges === "object") {
        incomingState.badges = { ...existingBadges, ...(incomingState.badges || {}) };
      }
    }
    putStateByEmail(email, incomingState, updatedAt);
  }
  return res.json({ ok: true, ns: email });
});

// ──────────────────────────────────────────────────────────
// 소셜/피드 라우터(있으면 자동 장착)
// ──────────────────────────────────────────────────────────
mountIfExists("./routes/gallery.public");
mountIfExists("./routes/likes.routes");

// ===== 폴백 소셜 라우트 설치 =====
(function installFallbackSocialRoutes(){
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

  db.exec(`
    CREATE TABLE IF NOT EXISTS item_likes (
      item_id   TEXT NOT NULL,
      user_id   TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (item_id, user_id)
    );

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
        ownerNs = resolvePushNS(row.author_email || row.owner_ns || null);
        if (ownerNs) ITEM_OWNER_NS.set(String(itemId), ownerNs);
      } catch {}
    }
    const payload = { id: itemId, ns, counts, ts: Date.now() };
    if (ownerNs) payload.owner = { ns: ownerNs };
    io.to(`item:${itemId}`).emit('vote:update', payload);
    io.emit('vote:update', payload);
    return counts;
  }

  if (!hasRouteDeep('put', '/items/:id/like')) {
    app.put('/api/items/:id/like', requireLogin, csrfProtection, (req, res) => {
      try {
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        db.prepare(
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

  if (!hasRouteDeep('get', '/gallery/public') || process.env.FORCE_FALLBACK_PUBLIC === '1') {
    app.get('/api/gallery/public', requireLogin, (req, res) => {
      res.set('Cache-Control', 'no-store');
      try {
        const limit = Math.min(Number(req.query.limit) || 12, 60);

        const afterParam = String(req.query.after || req.query.cursor || '');
        const [aTsStr, aId = ''] = afterParam ? afterParam.split('-') : [];
        const afterTs = Number(aTsStr || 0);

        const nsFilter    = String(req.query.ns || '').trim().toLowerCase();
        const labelFilter = String(req.query.label || '').trim();

        const SKIP_DIRS = new Set(['avatars']);
        let nss = [];
        try {
          nss = fs.readdirSync(UPLOAD_ROOT)
            .filter(d => {
              try {
                if (SKIP_DIRS.has(d)) return false;
                const p = path.join(UPLOAD_ROOT, d);
                if (!fs.lstatSync(p).isDirectory()) return false;
                return isEmail(decodeURIComponent(d));
              } catch { return false; }
            })
            .map(d => decodeURIComponent(d));
        } catch {}
        if (nsFilter) nss = nss.filter(ns => String(ns).toLowerCase() === nsFilter);

        const EXT_MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', webp:'image/webp', gif:'image/gif' };

        const all = [];
        for (const ns of nss) {
          const dir = dirForNS(ns);
          const indexPath = path.join(dirForNS(ns), '_index.json');

          let idx = [];
          try { idx = JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch {}

          if (!Array.isArray(idx) || idx.length === 0) {
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
              author: (m?.author ? {
                id: m.author.id ?? null,
                displayName: m.author.displayName ?? null,
                avatarUrl: m.author.avatarUrl ?? null,
                email: m.author.email ?? null,
              } : null),
            });
          }
        }

        if (labelFilter) {
          for (let i = all.length - 1; i >= 0; i--) {
            if (String(all[i].label || '') !== labelFilter) all.splice(i, 1);
          }
        }

        all.sort((a,b) => (b.created_at - a.created_at) || (a.id < b.id ? 1 : -1));
        if (afterTs) {
          const cid = String(aId);
          const cut = all.findIndex(x =>
            x.created_at < afterTs || (x.created_at === afterTs && x.id < cid)
          );
          if (cut >= 0) all.splice(0, cut + 1);
        }
        const slice = all.slice(0, limit);

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
            const key = Number.isFinite(Number(it.ns)) ? `id:${Number(it.ns)}` : `email:${String(it.ns).toLowerCase()}`;
            const row = authorMap.get(key);
            it.user = row
              ? authorProfileShape({
                  id: row.id,
                  email: row.email,
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

          if ((!it.user.displayName || it.user.displayName === null) && it.author?.displayName) it.user.displayName = it.author.displayName;
          if ((!it.user.avatarUrl   || it.user.avatarUrl   === null) && it.author?.avatarUrl)   it.user.avatarUrl   = it.author.avatarUrl;

          it.mine = isMineEmail(req, it.ns);

          if (!globalThis.ITEM_OWNER_NS) globalThis.ITEM_OWNER_NS = new Map();
          globalThis.ITEM_OWNER_NS.set(String(it.id), String(it.ns));
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

  if (!hasRouteDeep('get', '/items/:id/votes')) {
    app.get('/api/items/:id/votes', requireLogin, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        res.json({ ok:true, id, counts: voteCountsOf(id), my: myVoteOf(uid, id) });
      } catch { res.status(500).json({ ok:false }); }
    });
  }
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
  if (!hasRouteDeep('put', '/items/:id/vote')) {
    app.put('/api/items/:id/vote', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        const label = String(req.query.label || req.body?.label || req.body?.choice || '').trim();
        if (!isVoteLabel(label)) return res.status(400).json({ ok:false, error:'bad-label' });
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
  if (!hasRouteDeep('post', '/items/:id/votes')) {
    app.post('/api/items/:id/votes', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.params.id);
        const uid = req.session.uid;
        const ns  = getNS(req);
        const label = String(req.body?.label || req.body?.choice || '').trim();
        if (!isVoteLabel(label)) return res.status(400).json({ ok:false, error:'bad-label' });

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
  if (!hasRouteDeep('post', '/votes')) {
    app.post('/api/votes', requireLogin, csrfProtection, (req, res) => {
      try{
        const id  = String(req.body?.item_id || req.body?.item || req.query?.item || '');
        const uid = req.session.uid;
        const ns  = getNS(req);
        const label = String(req.body?.label || req.body?.choice || '').trim();
        if (!id) return res.status(400).json({ ok:false, error:'bad-item' });
        if (!isVoteLabel(label)) return res.status(400).json({ ok:false, error:'bad-label' });

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

  if (process.env.FORCE_FALLBACK_ITEMS === '1' || !hasRouteDeep('get', '/items/:id')) {
    app.get('/api/items/:id', requireLogin, (req, res) => {
      try {
        const preferNs = getNS(req);
        const id = String(req.params.id || '');
        if (!id) return res.status(400).json({ ok: false, error: 'bad-id' });

        const candidates = getMyNamespaces(req, preferNs);

        let meta = null;
        let foundNs = null;
        for (const ns of candidates) {
          if (!ns) continue;
          try {
            const indexPath = path.join(dirForNS(ns), '_index.json');
            const idx = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
            if (Array.isArray(idx)) {
              const hit = idx.find(m => String(m.id) === id);
              if (hit) { meta = hit; foundNs = ns; break; }
            }
          } catch {}
        }

        const EXT_TO_MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', webp:'image/webp', gif:'image/gif' };
        const tryExts = [];
        if (meta?.ext) tryExts.push(String(meta.ext).toLowerCase());
        tryExts.push('png','jpg','jpeg','webp','gif');

        let fileExt = null, fileMime = null, fileNs = foundNs;
        if (fileNs) {
          const base = path.join(dirForNS(fileNs), id); // ← FIX: ns → fileNs
          for (const e of [...new Set(tryExts)]) {
            if (fs.existsSync(`${base}.${e}`)) { fileExt = e; fileMime = EXT_TO_MIME[e]; break; }
          }
        }
        if (!fileExt) {
          for (const ns of candidates) {
            if (!ns) continue;
            const base = path.join(dirForNS(ns), id);
            for (const e of ['png','jpg','jpeg','webp','gif']) {
              if (fs.existsSync(`${base}.${e}`)) { fileExt = e; fileMime = EXT_TO_MIME[e]; fileNs = ns; break; }
            }
            if (fileExt) break;
          }
        }

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

        try {
          const uid = req.session?.uid || '';
          const likeCnt = db.prepare('SELECT COUNT(*) n FROM item_likes WHERE item_id=?').get(id)?.n || 0;
          const liked   = !!db.prepare('SELECT 1 FROM item_likes WHERE item_id=? AND user_id=?').get(id, uid);
          out.likes = likeCnt; out.liked = liked;
        } catch {}

        try {
          const nsUsed   = out.ns || preferNs;
          const myns     = String(req.session?.uid || '').toLowerCase();
          const ownerId  = Number(nsUsed);
          const ownerRow = Number.isFinite(ownerId) ? getUserById(ownerId) : null;

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
            if (ownerRow) {
              out.user = authorProfileShape(ownerRow);
            } else {
              out.user = { id: nsUsed, email: nsUsed, displayName: null, avatarUrl: null };
            }
          }

          if ((!out.user.displayName || out.user.displayName === null) && meta?.author?.displayName) out.user.displayName = meta.author.displayName;
          if ((!out.user.avatarUrl   || out.user.avatarUrl   === null) && meta?.author?.avatarUrl)   out.user.avatarUrl   = meta.author.avatarUrl;

          if (!out.user.displayName && ownerRow?.email) {
            out.user.displayName = String(ownerRow.email).split("@")[0];
          }

          if (!out.author && ownerRow) {
            out.author = {
              id: ownerRow.id ?? null,
              displayName: out.user.displayName ?? (ownerRow.email ? String(ownerRow.email).split("@")[0] : null),
              avatarUrl: out.user.avatarUrl ?? latestAvatarUrl?.(ownerRow.id) ?? null,
              email: ownerRow.email ?? null,
            };
          }

          out.mine = isMineEmail(req, nsUsed);

          if (meta?.author) {
            out.author = {
              id: meta.author.id ?? null,
              displayName: meta.author.displayName ?? null,
              avatarUrl: meta.author.avatarUrl ?? null,
              email: meta.author.email ?? null,
            };
          }
          if (!out.author) out.author = {};
          if (!out.author.id && out.user?.id) out.author.id = out.user.id;
          if (!out.author.displayName && out.user?.displayName) out.author.displayName = out.user.displayName;
          if (!out.author.avatarUrl && out.user?.avatarUrl) out.author.avatarUrl = out.user.avatarUrl;
          if (!out.author.email && out.user?.email) out.author.email = out.user.email;

        } catch {}

        const ownerNs = out.ns;
        let ownerRow = null;
        if (Number.isFinite(Number(ownerNs))) {
          ownerRow = getUserById(Number(ownerNs));
        } else if (typeof getUserByEmail === "function") {
          ownerRow = getUserByEmail(String(ownerNs).toLowerCase());
        }

        out.owner = { ns: ownerNs };
        out.authorProfile = ownerRow ? authorProfileShape(ownerRow) : null;

        if (out.authorProfile) out.user = out.authorProfile;

        if (!out.user?.displayName && out.author?.displayName) out.user.displayName = out.author.displayName;
        if (!out.user?.avatarUrl   && out.author?.avatarUrl)   out.user.avatarUrl   = out.author.avatarUrl;

        if (!globalThis.ITEM_OWNER_NS) globalThis.ITEM_OWNER_NS = new Map();
        globalThis.ITEM_OWNER_NS.set(String(out.id), ownerNs);

        res.set('Cache-Control', 'no-store');
        return res.json({ ok: true, ...out, item: out });
      } catch (e) {
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
// server.js  — REPLACE this whole route handler

app.post(
  ["/api/gallery/upload", "/api/gallery"],
  ensureAuth,
  csrfProtection,
  upload.single("file"),
  async (req, res) => {
    try {
      const ns = emailNS(req, null);
      if (!ns) return res.status(400).json({ ok:false, error:"ns_unavailable" });

      // 0) 입력 파라미터
      const id        = String(req.body?.id || `g_${Date.now()}`);
      const label     = String(req.body?.label || "");
      const createdAt = Number(req.body?.createdAt || Date.now());

      // 1) 이미지 소스 결정 (multipart 우선, 없으면 dataURL)
      const EXT_MIME = { png:"image/png", jpg:"image/jpeg", jpeg:"image/jpeg", webp:"image/webp", gif:"image/gif" };
      let buf = null, ext = "png", mime = "image/png";

      if (req.file) {
        if (!isAllowedImageMime(req.file.mimetype)) {
          return res.status(400).json({ ok:false, error:"bad_image_mime" });
        }
        buf  = req.file.buffer;
        mime = (req.file.mimetype || "").toLowerCase();
        ext  = (mime.split("/")[1] || "png").replace("jpeg","jpg");
      } else if (req.body?.thumbDataURL) {
        const decoded = decodeDataURL(req.body.thumbDataURL);
        if (!decoded || !/^image\//.test(decoded.mime) || !isAllowedImageMime(decoded.mime)) {
          return res.status(400).json({ ok:false, error:"bad_image_mime" });
        }
        if (decoded.buf.length > 8 * 1024 * 1024) {
          return res.status(413).json({ ok:false, error:"image_too_large" });
        }
        buf = decoded.buf; ext = decoded.ext || "png"; mime = decoded.mime || EXT_MIME[ext] || "image/png";
      }

      if (!buf) return res.status(400).json({ ok:false, error:"no-image" });

      // 2) 디렉토리/파일 저장
      const dir = path.join(UPLOAD_ROOT, encodeURIComponent(ns));
      ensureDir(dir);
      const filename = `${id}.${ext}`;
      const outPath  = path.join(dir, filename);
      if (!outPath.startsWith(dir + path.sep)) {
        return res.status(400).json({ ok:false, error:"bad-path" });
      }
      fs.writeFileSync(outPath, buf);

      // 3) caption/bg 정규화
      const pickCaption = () => {
        const s = String(req.body?.caption ?? req.body?.text ?? "").trim();
        return s.length ? s : "";
      };
      const normHex = (v) => {
        let s = String(v ?? "").trim();
        if (/^#([0-9a-f]{3})$/i.test(s)) {
          s = s.replace(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/i, (_,a,b,c)=>`#${a}${a}${b}${b}${c}${c}`);
        }
        return /^#([0-9a-f]{6})$/i.test(s) ? s.toLowerCase() : null;
      };
      const pickBg = () => normHex(req.body?.bg ?? req.body?.bg_color ?? req.body?.bgHex);

      // 4) author(선택)
      const fromUser = (() => {
        try {
          const b = req.body || {};
          return typeof b.user === "string" ? JSON.parse(b.user) : (b.user || null);
        } catch { return null; }
      })();
      const author = fromUser ? {
        id:          fromUser.id ?? null,
        displayName: fromUser.displayName || fromUser.name || null,
        avatarUrl:   fromUser.avatarUrl || null,
        email:       fromUser.email || ns,
      } : { email: ns };

      // 5) 메타 구축 (info 사용 안 함: 미정의였음)
      const meta = {
        id,
        ns,
        label,
        createdAt,
        width:  Number(req.body?.width  || 0),
        height: Number(req.body?.height || 0),
        ext,
        mime: mime || EXT_MIME[ext] || "image/png",
        caption: pickCaption(),
        bg:      pickBg(),
        author
      };

      // 6) _index.json 갱신 (선두 삽입, 최대 2000)
      const indexPath = path.join(dirForNS(ns), "_index.json");
      let idx = [];
      try { idx = JSON.parse(fs.readFileSync(indexPath, "utf8")); } catch {}
      if (!Array.isArray(idx)) idx = [];

      idx = idx.filter(m => String(m?.id) !== id);
      idx.unshift(meta);
      if (idx.length > 2000) idx.length = 2000;

      writeJsonAtomic(indexPath, idx);

      // 7) 응답
      return res.json({ ok:true, id, ns, ext, mime: meta.mime });
    } catch (e) {
      console.log("[/api/gallery/upload] fatal:", e?.stack || e);
      return res.status(500).json({ ok:false, error:"upload-failed" });
    }
  }
);

/* 5) gallery.public / items/:id 등에서 mine 판정 */
function isMineEmail(req, candidateNs) {
  const meEmail = emailNS(req, null);
  return meEmail && String(candidateNs||'').toLowerCase() === meEmail;
}

// ====== item 삭제/조회 보강 헬퍼 & 라우트 ======
function writeJsonAtomic(filePath, dataObj) {
  try {
    const dir = path.dirname(filePath);
    const tmp = path.join(dir, `.${path.basename(filePath)}.tmp-${Date.now()}`);
    fs.writeFileSync(tmp, JSON.stringify(dataObj));
    fs.renameSync(tmp, filePath);
    return true;
  } catch { return false; }
}

function getMyNamespaces(req, preferNs) {
  const emailNs = emailNS(req, null);
  const pref    = String(preferNs || '').toLowerCase();
  return [...new Set([emailNs, pref].filter(isEmail))];
}

function removeItemFileAndIndexIn(ns, id) {
  try {
    const dir = dirForNS(ns);
    const indexPath = path.join(dirForNS(ns), '_index.json');

    let idx = [];
    try { idx = JSON.parse(fs.readFileSync(indexPath, 'utf8')); } catch {}

    const before = idx.length;
    idx = Array.isArray(idx) ? idx.filter(m => String(m.id) !== String(id)) : [];

    let anyFileDeleted = false;
    for (const ext of ['png','jpg','jpeg','webp','gif']) {
      const p = path.join(dir, `${id}.${ext}`);
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); anyFileDeleted = true; } catch {}
      }
    }

    if (before !== idx.length) writeJsonAtomic(indexPath, idx);
    return (before !== idx.length) || anyFileDeleted;
  } catch { return false; }
}

function removeItemEverywhere(req, id) {
  const candidates = getMyNamespaces(req, getNS(req));
  for (const ns of candidates) {
    if (!ns) continue;
    if (removeItemFileAndIndexIn(ns, id)) return ns;
  }
  return null;
}

function purgeItemDb(id) {
  try {
    db.prepare('DELETE FROM item_likes WHERE item_id=?').run(id);
    db.prepare('DELETE FROM item_votes WHERE item_id=?').run(id);
  } catch {}
}

app.delete('/api/items/:id', requireLogin, csrfProtection, (req, res) => {
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

function ensureOwnerNs(req, ns) {
  const email = emailNS(req, null);
  const want  = String(ns || '').trim().toLowerCase();
  return !!email && want === email;
}

// ── 이미지 blob (ns 힌트가 없더라도 전 ns에서 탐색)
(() => {
  const EXT_TO_MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', webp:'image/webp', gif:'image/gif' };
  const exts = ['png','jpg','jpeg','webp','gif'];

  function findBlobPath(id, preferNs) { // ← FIX: uid 제거
    const dirs = new Set();
    if (preferNs) dirs.add(dirForNS(preferNs));
    try {
      for (const d of fs.readdirSync(UPLOAD_ROOT)) {
        const p = path.join(UPLOAD_ROOT, d);
        try {
          if (d === 'avatars') continue;
          if (!fs.lstatSync(p).isDirectory()) continue;
          if (!isEmail(decodeURIComponent(d))) continue;
          dirs.add(p);
        } catch {}
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

      let hintExts = [];
      try {
        const ns = preferNs || emailNS(req, null);
        if (ns) {
          const row = JSON.parse(fs.readFileSync(path.join(dirForNS(ns), '_index.json'), 'utf8'))
            .find(m => String(m.id) === id);
          if (row?.ext) hintExts = [String(row.ext).toLowerCase()];
        }
      } catch {}
      const foundByIndex = hintExts.length
        ? (() => {
            const ns = preferNs || emailNS(req, null);
            const dir = ns ? dirForNS(ns) : null;
            if (!dir) return null;
            for (const e of hintExts) {
              const p = path.join(dir, `${id}.${e}`);
              if (fs.existsSync(p)) return { fp: p, ext: e, mime: EXT_TO_MIME[e] || 'application/octet-stream' };
            }
            return null;
          })()
        : null;

      const found = foundByIndex || findBlobPath(id, preferNs); // ← FIX: uid 제거
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
    const labels = Array.isArray(payload.labels)
      ? payload.labels
      : (payload.label ? [payload.label] : []);
    for (const lb of labels) if (typeof lb === "string" && lb) sock.join(`label:${lb}`);

    const ns = String(payload.ns || "").toLowerCase();
    if (ns) sock.join(`ns:${ns}`);
    const watch = Array.isArray(payload.watch) ? payload.watch : [];
    for (const w of watch) {
      const wn = String(w || "").toLowerCase();
      if (wn) sock.join(`ns:${wn}`);
    }

    const items = Array.isArray(payload.items) ? payload.items : [];
    for (const it of items) {
      const id = String(it || "");
      if (!id) continue;
      sock.join(`item:${id}`);
      if (ns) ITEM_OWNER_NS.set(id, ns);
    }

    const rooms = Array.isArray(payload.rooms) ? payload.rooms : [];
    for (const room of rooms) {
      const roomName = String(room || "").trim();
      if (roomName) sock.join(roomName);
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
    }
  });

  sock.on("label:update", (payload = {}, ack) => {
    try {
      const lb = normalizeLabel(payload.label);
      if (!lb) {
        if (ack) ack({ ok: false, error: "bad_label" });
        return;
      }
      const saved = putLabelStory(lb, String(payload.story || ""));
      io.to(`label:${lb}`).emit("label:story-updated", { label: lb, story: saved.story });
      if (ack) ack({ ok: true, label: lb, updatedAt: saved.updatedAt });
    } catch {
      if (ack) ack({ ok: false, error: "update_failed" });
    }
  });
  sock.on("jib:update", (payload = {}, ack) => {
    try {
      const jb = normalizeJib(payload.jib);
      if (!jb) { ack && ack({ ok:false, error:"bad_jib" }); return; }
      const saved = putJibStory(jb, String(payload.story || ""));
      io.to(`jib:${jb}`).emit("jib:story-updated", { jib: jb, story: saved.story });
      ack && ack({ ok:true, jib: jb, updatedAt: saved.updatedAt });
    } catch {
      ack && ack({ ok:false, error:"update_failed" });
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
server.listen(PORT, () => {
  console.log(`listening: http://localhost:${PORT}`);
  if (!PROD) printRoutesSafe();

  (async () => {
    try {
      await seedAdminUsers();
      console.log("[admin] seed done");
    } catch (e) {
      console.warn("[admin] seed at boot failed:", e?.message || e);
    }
  })();

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
