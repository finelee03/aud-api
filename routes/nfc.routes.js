/**
 * /api/nfc/* — NFC UID↔Label 매핑 API
 *  - GET    /api/nfc/label?uid=XXXX[&ns=...]
 *  - PUT    /api/nfc/label   (JSON: { uid, label, ns? })
 *  - GET    /api/nfc/map[?ns=...] → 전체 목록(최대 500)
 *  - DELETE /api/nfc/label?uid=XXXX[&ns=...]
 */
const express = require("express");
const { db } = require("../db");

const router = express.Router();
router.use(express.json());

function normalizeUid(uid){ return String(uid || "").trim().toUpperCase(); }
function getNS(req){
  const raw = String(req.query?.ns || req.body?.ns || "").trim().toLowerCase();
  if (/^[a-z0-9_-]{1,64}$/.test(raw)) return raw;
  if (/^user:[a-z0-9_-]{1,64}$/.test(raw)) return raw.slice(5);
  if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(raw)) return raw;
  // 서버 전역 기본 네임스페이스
  return "public";
}

router.get("/nfc/label", (req, res) => {
  const ns = getNS(req);
  const uid = normalizeUid(req.query.uid || "");
  if (!uid) return res.status(400).json({ ok:false, error:"uid required" });
  const row = db.prepare("SELECT label FROM nfc_map WHERE ns=? AND uid=?").get(ns, uid);
  return res.json({ ok:true, ns, uid, label: row?.label || null });
});

router.put("/nfc/label", (req, res) => {
  const ns    = getNS(req);
  const uid   = normalizeUid(req.body?.uid || req.query?.uid || "");
  const label = String(req.body?.label ?? req.query?.label ?? "").trim();
  if (!uid || !label) return res.status(400).json({ ok:false, error:"uid and label required" });

  db.prepare(`
    INSERT INTO nfc_map (ns, uid, label, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(ns, uid) DO UPDATE
      SET label=excluded.label, updated_at=excluded.updated_at
  `).run(ns, uid, label, Math.floor(Date.now()/1000));

  return res.json({ ok:true, ns, uid, label });
});

router.get("/nfc/map", (req, res) => {
  const ns = getNS(req);
  const rows = db.prepare(`
    SELECT uid, label, updated_at
    FROM nfc_map WHERE ns=? ORDER BY updated_at DESC LIMIT 500
  `).all(ns);
  return res.json({ ok:true, ns, map: rows });
});

router.delete("/nfc/label", (req, res) => {
  const ns  = getNS(req);
  const uid = normalizeUid(req.query?.uid || req.body?.uid || "");
  if (!uid) return res.status(400).json({ ok:false, error:"uid required" });
  db.prepare("DELETE FROM nfc_map WHERE ns=? AND uid=?").run(ns, uid);
  return res.json({ ok:true, ns, uid });
});

module.exports = router;
