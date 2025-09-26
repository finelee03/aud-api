// FILE: audlab-router.js (place next to server.js, exports an express router)
const path = require("path");
const fs = require("fs");
const express = require("express");

const router = express.Router();

// Share helpers from server if available, else fallback
function ensureDir(dir){ try{ fs.mkdirSync(dir, { recursive:true }); } catch {} }
function decodeDataURL(dataURL) {
  const m = String(dataURL || "").match(/^data:(image\/[a-z0-9.+-]+);base64,(.+)$/i);
  if (!m) return null;
  const mime = m[1];
  const buf = Buffer.from(m[2], "base64");
  let ext = "png";
  if (/jpe?g/i.test(mime)) ext = "jpg";
  else if (/webp/i.test(mime)) ext = "webp";
  else if (/gif/i.test(mime)) ext = "gif";
  else if (/png/i.test(mime)) ext = "png";
  return { mime, buf, ext };
}

// simple auth guard (mirror server.js style)
function requireLogin(req, res, next){
  if (req.session?.uid) return next();
  return res.status(401).json({ ok:false, error:"auth_required" });
}

// Paths
const PUB = path.join(__dirname, "public");
const ROOT = path.join(PUB, "uploads", "audlab");
ensureDir(ROOT);

// Limits
const MAX_STROKES = 400;
const MAX_POINTS = 8000;
const MAX_PNG_BYTES = 5 * 1024 * 1024;

function getNS(req){
  const norm = (s='') => String(s).trim().toLowerCase();
  const raw = norm(req.body?.ns || req.query?.ns || '');
  if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(raw)) return raw;
  if (/^[a-z0-9_-]{1,64}$/.test(raw)) return raw;
  return norm(req.session?.uid || 'default');
}

// POST /api/audlab/submit
router.post("/api/audlab/submit", requireLogin, express.json({ limit: "7mb" }), (req, res)=>{
  try {
    const ns = getNS(req);
    const { width, height, strokes = [], previewDataURL } = req.body || {};
    // validate strokes
    if (!Array.isArray(strokes) || strokes.length === 0) {
      return res.status(400).json({ ok:false, error:"NO_STROKES" });
    }
    const strokeCount = strokes.length;
    const pointCount = strokes.reduce((s, st)=> s + (Array.isArray(st.points)? st.points.length : 0), 0);
    if (strokeCount > MAX_STROKES) return res.status(400).json({ ok:false, error:"TOO_MANY_STROKES" });
    if (pointCount > MAX_POINTS) return res.status(400).json({ ok:false, error:"TOO_MANY_POINTS" });

    const id = Date.now().toString(36) + "-" + Math.random().toString(36).slice(2,8);
    const dir = path.join(ROOT, encodeURIComponent(ns));
    ensureDir(dir);

    // save JSON
    const jsonPath = path.join(dir, `${id}.json`);
    const payload = { ns, width, height, strokeCount, pointCount, strokes };
    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2), "utf8");

    // preview image
    let pngUrl = null;
    if (previewDataURL) {
      const dec = decodeDataURL(previewDataURL);
      if (!dec) return res.status(400).json({ ok:false, error:"BAD_DATAURL" });
      if (dec.buf.length > MAX_PNG_BYTES) return res.status(400).json({ ok:false, error:"PNG_TOO_LARGE" });
      const imgPath = path.join(dir, `${id}.png`);
      fs.writeFileSync(imgPath, dec.buf);
      pngUrl = `/uploads/audlab/${encodeURIComponent(ns)}/${id}.png`;
    }

    return res.status(201).json({ ok:true, id, json: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`, png: pngUrl });
  } catch (e) {
    return res.status(500).json({ ok:false, error: "SERVER_ERROR" });
  }
});

// GET /api/audlab/list?ns=...
router.get("/api/audlab/list", requireLogin, (req, res)=>{
  try {
    const ns = getNS(req);
    const dir = path.join(ROOT, encodeURIComponent(ns));
    ensureDir(dir);
    const files = fs.readdirSync(dir).filter(f=>/\.json$/i.test(f)).sort().reverse();
    const out = files.slice(0, 50).map(f=>{
      const id = f.replace(/\.json$/i, "");
      return {
        id,
        json: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`,
        png:  `/uploads/audlab/${encodeURIComponent(ns)}/${id}.png`,
      };
    });
    res.json({ ok:true, items: out });
  } catch (e) {
    res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

module.exports = router;
