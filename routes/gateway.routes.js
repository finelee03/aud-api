// /Users/ihwain/projects/aud/aud-api/routes/gateway.routes.js
module.exports = (app, io) => {
  const express = require("express");
  const router = express.Router();

  const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN || "";
  if (!GATEWAY_TOKEN) {
    console.warn("[gateway] GATEWAY_TOKEN not set!");
  }

  router.use(express.json({ limit: "256kb" }));

  const UID_PREFIX = "UID:";
  const IDLE_MARK = "IDLE";

  function normalizeUid(uid) {
    const val = String(uid || "").trim().toUpperCase();
    return val ? val : null;
  }

  function pickUidFromString(str) {
    const src = String(str || "");
    const idx = src.indexOf(UID_PREFIX);
    if (idx < 0) return null;
    const tail = src.slice(idx + UID_PREFIX.length);
    const match = tail.match(/^[0-9A-F]+/i);
    return match ? normalizeUid(match[0]) : null;
  }

  function pickUidFromBytes(bytes) {
    if (!Array.isArray(bytes)) return null;
    try {
      const buf = Buffer.from(bytes);
      const idx = buf.indexOf(Buffer.from(UID_PREFIX));
      if (idx < 0) return null;
      let out = "";
      for (let i = idx + UID_PREFIX.length; i < buf.length; i += 1) {
        const c = buf[i];
        if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46)) {
          out += String.fromCharCode(c);
        } else {
          break;
        }
      }
      return normalizeUid(out);
    } catch {
      return null;
    }
  }

  function markIdleFromBytes(bytes) {
    if (!Array.isArray(bytes)) return false;
    try {
      return Buffer.from(bytes).includes(Buffer.from(IDLE_MARK));
    } catch {
      return false;
    }
  }

  function markIdleFromString(str) {
    return String(str || "").toUpperCase().includes(IDLE_MARK);
  }

  // 게이트웨이 → 서버 업링크
  router.post("/gateway/ble", (req, res) => {
    const hdr = req.get("x-gateway-token") || "";
    if (!GATEWAY_TOKEN || hdr !== GATEWAY_TOKEN) {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    const evt = req.body || {};
    const ts = Date.now();

    const payload = { ts, source: "gateway" };
    if (Array.isArray(evt.bytes)) payload.bytes = evt.bytes;
    if (typeof evt.mfg === "string") payload.mfg = evt.mfg;
    if (evt.idle === true) payload.idle = true;

    let uid = null;
    if (Array.isArray(evt.bytes)) uid = pickUidFromBytes(evt.bytes);
    if (!uid && typeof evt.mfg === "string") uid = pickUidFromString(evt.mfg);
    if (!uid && typeof evt.uid === "string") uid = normalizeUid(evt.uid);
    const label = typeof evt.label === "string" ? evt.label : null;

    if (!payload.idle) {
      const idleFromBytes = Array.isArray(evt.bytes) && markIdleFromBytes(evt.bytes);
      const idleFromString = typeof evt.mfg === "string" && markIdleFromString(evt.mfg);
      if (idleFromBytes || idleFromString) payload.idle = true;
    }

    if (uid) payload.uid = uid;

    io.emit("ble", payload);

    if (uid) {
      io.emit("nfc", { uid, label, ts, source: "gateway" });
    }

    return res.json({ ok: true });
  });

  app.use(router);
};
