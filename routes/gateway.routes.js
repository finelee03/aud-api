module.exports = (app, io) => {
  const express = require("express");
  const router = express.Router();

  const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN || "";
  router.use(express.json({ limit: "256kb" }));

  // 게이트웨이 → 서버 업링크 (Manufacturer Data 그대로 수신)
  $&
  console.log(`[gateway] srv GATEWAY_TOKEN length: ${(process.env.GATEWAY_TOKEN||"").length}`);
  console.log(`[gateway] recv hdr head: ${(req.get("x-gateway-token")||"").slice(0,8)} len=${(req.get("x-gateway-token")||"").length}`);

    const token = req.get("x-gateway-token") || req.query.token;
    if (!GATEWAY_TOKEN || token !== GATEWAY_TOKEN) {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    const evt = req.body || {};
    if (Array.isArray(evt.bytes)) {
      io.emit("ble", {
        bytes: evt.bytes,
        ts: Date.now()
      });
    } else if (typeof evt.mfg === "string") {
      io.emit("ble", { mfg: evt.mfg, ts: Date.now() });
    } else if (typeof evt.uid === "string") {
      io.emit("nfc", { uid: evt.uid, label: evt.label || null, ts: Date.now() });
    }
    return res.json({ ok: true });
  });

  app.use(router);
};
