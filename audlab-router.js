// REPLACE WHOLE FILE: audlab-router.js
const path = require("path");
const fs = require("fs");
const express = require("express");
const router = express.Router();

function ensureDir(dir){ try{ fs.mkdirSync(dir, { recursive:true }); } catch {} }
function decodeAnyDataURL(dataURL) {
  const m = String(dataURL || "").match(/^data:([a-z0-9.+/-]+);base64,(.+)$/i);
  if (!m) return null;
  const mime = m[1].toLowerCase();
  const buf  = Buffer.from(m[2], "base64");
  const map = {
    "image/png":"png","image/jpeg":"jpg","image/jpg":"jpg","image/webp":"webp","image/gif":"gif",
    "audio/webm;codecs=opus":"webm","audio/webm":"webm","audio/ogg;codecs=opus":"ogg","audio/ogg":"ogg",
    "audio/mpeg":"mp3","audio/wav":"wav","audio/x-wav":"wav","audio/mp4":"m4a","audio/aac":"m4a",
  };
  const base = mime.split(";")[0];
  const ext = map[mime] || map[base] || (base.startsWith("image/")||base.startsWith("audio/")? base.split("/")[1] : "bin");
  return { mime, buf, ext };
}
function requireLogin(req,res,next){ if (req.session?.uid) return next(); res.status(401).json({ ok:false, error:"auth_required" }); }

const ROOT = path.join(__dirname, "public", "uploads", "audlab"); ensureDir(ROOT);
const getNS = (req) => {
  const s = String(req.body?.ns || req.query?.ns || req.session?.uid || "default").trim().toLowerCase();
  if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return s;
  if (/^[a-z0-9_-]{1,64}$/.test(s)) return s;
  return "default";
};

router.post("/api/audlab/submit", requireLogin, express.json({ limit: "30mb" }), (req, res) => {
  try {
    const ns = getNS(req);
    const { width, height, strokes = [], previewDataURL, audioDataURL } = req.body || {};
    if (!Array.isArray(strokes) || strokes.length === 0) return res.status(400).json({ ok:false, error:"NO_STROKES" });

    const id  = Date.now().toString(36) + "-" + Math.random().toString(36).slice(2,8);
    const dir = path.join(ROOT, encodeURIComponent(ns));
    ensureDir(dir);

    const meta = { ns, width, height, strokeCount: strokes.length, pointCount: strokes.reduce((s, st)=> s + (Array.isArray(st.points)? st.points.length : 0), 0), strokes };
    fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(meta, null, 2), "utf8");

    let pngUrl = null;
    if (previewDataURL) {
      const dec = decodeAnyDataURL(previewDataURL);
      if (!dec || !/^image\//.test(dec.mime)) return res.status(400).json({ ok:false, error:"BAD_PREVIEW_DATAURL" });
      fs.writeFileSync(path.join(dir, `${id}.png`), dec.buf);
      pngUrl = `/uploads/audlab/${encodeURIComponent(ns)}/${id}.png`;
    }

    let audUrl = null;
    if (audioDataURL) {
      const dec = decodeAnyDataURL(audioDataURL);
      if (dec && /^audio\//.test(dec.mime)) {
        const p = path.join(dir, `${id}.${dec.ext}`);
        fs.writeFileSync(p, dec.buf);
        audUrl = `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${dec.ext}`;
      }
    }

    return res.status(201).json({ ok:true, id, json:`/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`, png: pngUrl, audio: audUrl });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"SERVER_ERROR" });
  }
});

router.get("/api/audlab/list", requireLogin, (req, res)=>{
  try {
    const ns = getNS(req);
    const dir = path.join(ROOT, encodeURIComponent(ns));
    ensureDir(dir);
    const files = fs.readdirSync(dir).filter(f=>/\.json$/i.test(f)).sort().reverse();
    const out = files.slice(0, 50).map(f=>{
      const id = f.replace(/\.json$/i, "");
      const audio = ["webm","ogg","m4a","mp3","wav"].map(ext => fs.existsSync(path.join(dir, `${id}.${ext}`)) ? `/uploads/audlab/${encodeURIComponent(ns)}/${id}.${ext}` : null).find(Boolean) || null;
      return {
        id,
        json: `/uploads/audlab/${encodeURIComponent(ns)}/${id}.json`,
        png:  `/uploads/audlab/${encodeURIComponent(ns)}/${id}.png`,
        audio
      };
    });
    res.json({ ok:true, items: out });
  } catch (e) { res.status(500).json({ ok:false, error:"SERVER_ERROR" }); }
});

module.exports = router;
