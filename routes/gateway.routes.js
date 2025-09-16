// /Users/ihwain/projects/aud/aud-api/routes/gateway.routes.js
module.exports = (app, io) => {
  const express = require("express");
  const router = express.Router();

  const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN || "";
  if (!GATEWAY_TOKEN) {
    console.warn("[gateway] GATEWAY_TOKEN not set!");
  }

  router.use(express.json({ limit: "256kb" }));

  // 게이트웨이 → 서버 업링크
  router.post("/gateway/ble", (req, res) => {
    const hdr = req.get("x-gateway-token") || "";
    if (!GATEWAY_TOKEN || hdr !== GATEWAY_TOKEN) {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    const evt = req.body || {};

    // 1) bytes 배열이 오면 그대로 브로드캐스트
    if (Array.isArray(evt.bytes)) {
      io.emit("ble", { bytes: evt.bytes, ts: Date.now() });
    }
    // 2) 문자열 mfg가 오면 그대로 브로드캐스트
    else if (typeof evt.mfg === "string") {
      io.emit("ble", { mfg: evt.mfg, ts: Date.now() });
    }
    // 3) 서버에 uid가 직접 오면 nfc 채널로 브로드캐스트
    else if (typeof evt.uid === "string") {
      io.emit("nfc", { uid: evt.uid, label: evt.label || null, ts: Date.now() });
    }

    return res.json({ ok: true });
  });

  app.use(router);
};
