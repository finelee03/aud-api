// routes/gallery.public.js  — DB 우선, 없으면 파일시스템 폴백으로 위임 + HEAD 지원
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const gallery = require('../models/gallery');

const UPLOAD_ROOT = path.resolve(
  process.env.UPLOAD_ROOT || path.join(__dirname, '..', 'public', 'uploads')
);

const EXTS = ['png','jpg','jpeg','webp','gif'];
const EXT_MIME = {
  png:  'image/png',
  jpg:  'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  gif:  'image/gif'
};

// 업로드 경로 안전 조인(루트 밖 탈출 금지)
function safeJoinUpload(ns, id, ext = '.png') {
  const seg = String(ns ?? 'default').replace(/[^a-zA-Z0-9._-]/g, '_');
  const abs = path.resolve(UPLOAD_ROOT, seg, `${String(id)}${ext}`);
  if (!abs.startsWith(UPLOAD_ROOT + path.sep) && abs !== UPLOAD_ROOT) {
    throw new Error('path-outside-root');
  }
  return abs;
}

// index 힌트로 확장자 우선 탐색
function readIndexExt(ns, id) {
  try {
    const idx = JSON.parse(
      fs.readFileSync(path.join(UPLOAD_ROOT, ns, '_index.json'), 'utf8')
    );
    const row = Array.isArray(idx) ? idx.find(m => String(m.id) === String(id)) : null;
    return row?.ext ? String(row.ext).toLowerCase() : null;
  } catch { return null; }
}
function tryFindInNs(ns, id) {
  if (!ns) return null;
  const hint = readIndexExt(ns, id);
  const candidates = hint ? [hint, ...EXTS.filter(e => e !== hint)] : EXTS;
  for (const ext of candidates) {
    const p = safeJoinUpload(ns, id, '.' + ext);
    if (fs.existsSync(p)) return { fp: p, ext, mime: EXT_MIME[ext] };
  }
  return null;
}
function findBlobPath(id, preferNs, dbNs, uid) {
  const seen = new Set();
  const order = [preferNs, dbNs, uid, 'default'].map(s => String(s || '').trim()).filter(Boolean);
  for (const ns of order) {
    if (seen.has(ns)) continue;
    seen.add(ns);
    const f = tryFindInNs(ns, id);
    if (f) return f;
  }
  // 모든 ns 디렉토리 스캔(avatars 제외)
  try {
    for (const d of fs.readdirSync(UPLOAD_ROOT)) {
      if (d === 'avatars' || seen.has(d)) continue;
      const abs = path.join(UPLOAD_ROOT, d);
      try { if (!fs.lstatSync(abs).isDirectory()) continue; } catch { continue; }
      const f = tryFindInNs(d, id);
      if (f) return f;
    }
  } catch {}
  return null;
}

// ──────────────────────────────────────────────────────────
// 공개 피드 — DB에서 비어있으면 server.js 폴백(next)로 위임
// ──────────────────────────────────────────────────────────
router.get('/gallery/public', (req, res, next) => {
  try {
    const after = Number(req.query.after || 0) || null;
    const limit = Math.min(Number(req.query.limit) || 12, 60);
    const label = String(req.query.label || '').trim();
    const ns    = String(req.query.ns    || '').trim();

    const rows = gallery.getPublicFeed({ after, limit, label, ns });

    // ★ DB가 비어 있으면 파일시스템 폴백 라우트로 위임
    if (!rows || rows.length === 0) return next();

    const last = rows[rows.length - 1];
    const nextCursor =
      last && (Number(last.created_at ?? 0) > 0)
        ? `${Number(last.created_at)}-${String(last.id)}`
        : null;

    res.json({ ok: true, items: rows, nextCursor });
  } catch (err) {
    console.warn('[GET /gallery/public] DB 실패 → 폴백 시도:', err.message);
    return next(); // 폴백 라우트로 넘김
  }
});

// ──────────────────────────────────────────────────────────
// 이미지 blob — DB 가이드 + ns 힌트, 그래도 없으면 폴백(next)
// GET/HEAD 둘 다 지원
// ──────────────────────────────────────────────────────────
async function handleBlob(req, res, next, headOnly = false) {
  try {
    const id = String(req.params.id || '');
    if (!id) return res.status(400).json({ ok:false, error:'bad-id' });

    const preferNs = String(req.query.ns || '').trim();
    const uid = req.session?.uid;

    // DB에 있으면 visibility만 체크하고 ns 힌트로 사용
    let dbNs = null;
    try {
      const item = gallery.getItemBasic(id);
      if (item) {
        const visibility = String(item.visibility ?? 'public');
        if (visibility !== 'public') {
          const me    = String(uid ?? '');
          const owner = String(item.owner_id ?? item.user_id ?? item.ns ?? '');
          if (!me || me !== owner) {
            return res.status(403).json({ ok:false, error:'forbidden' });
          }
        }
        dbNs = String(item.ns ?? item.owner_id ?? item.user_id ?? '');
      }
    } catch {/* DB 에러는 폴백으로 */}

    const found = findBlobPath(id, preferNs, dbNs, uid);
    if (!found) return next(); // server.js 폴백(blob 스캐너)에게 기회 제공

    res.setHeader('Content-Type', found.mime);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    if (headOnly) return res.end();
    return fs.createReadStream(found.fp).pipe(res);
  } catch (err) {
    console.error('[GET/HEAD /gallery/:id/blob] 오류:', err);
    return next(); // 예외 시에도 폴백 시도
  }
}

router.get('/gallery/:id/blob', (req, res, next) => handleBlob(req, res, next, false));
router.head('/gallery/:id/blob', (req, res, next) => handleBlob(req, res, next, true));

module.exports = router;
