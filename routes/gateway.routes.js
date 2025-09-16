module.exports = (app, io) => {
  const express = require("express");
  const router = express.Router();

  const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN || "";
  router.use(express.json({ limit: "256kb" }));

  // bytes/mfg/uid 중 들어온 값으로 ASCII 제조사데이터와 UID 추출
  function parseAsciiAndUidFromBody(evt = {}) {
    let asciiMfg = null, uid = null, bytesArr = null;

    if (Array.isArray(evt.bytes) && evt.bytes.length >= 3) {
      const buf = Buffer.from(evt.bytes);
      bytesArr = evt.bytes;
      // [0..1] = Company ID(LE) → [2..]이 실제 제조사 데이터(ASCII)
      asciiMfg = buf.slice(2).toString("ascii");
    }

    if (!asciiMfg && typeof evt.mfg === "string") {
      asciiMfg = evt.mfg;
    }

    // 우선 바디에 uid가 문자열로 직접 왔다면 사용
    if (typeof evt.uid === "string" && evt.uid.length) {
      uid = evt.uid.toUpperCase();
    }

    // 그렇지 않다면 ASCII 제조사 데이터에서 UID:XXXX... 패턴 추출
    if (!uid && asciiMfg) {
      const m = asciiMfg.match(/UID:([0-9A-F]+)/i);
      if (m) uid = m[1].toUpperCase();
    }

    return { asciiMfg, uid, bytesArr };
  }

  // 게이트웨이 → 서버 업링크
  router.post("/gateway/ble", (req, res) => {
    // 토큰 로그(길이/앞 8자 확인)
    console.log(`[gateway] srv GATEWAY_TOKEN length: ${GATEWAY_TOKEN.length}`);
    const hdr = req.get("x-gateway-token") || "";
    console.log(`[gateway] recv hdr head: ${hdr.slice(0, 8)} len=${hdr.length}`);

    // 인증
    const token = hdr || req.query.token;
    if (!GATEWAY_TOKEN || token !== GATEWAY_TOKEN) {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }

    const { asciiMfg, uid, bytesArr } = parseAsciiAndUidFromBody(req.body || {});
    const payload = { ts: Date.now() };
    if (bytesArr) payload.bytes = bytesArr;
    if (asciiMfg) payload.mfg = asciiMfg;
    if (uid) payload.uid = uid;

    // 항상 raw ble 이벤트 송신
    io.emit("ble", payload);

    // UID가 있으면 별도 nfc 이벤트도 송신
    if (uid) {
      io.emit("nfc", { uid, ts: payload.ts });
    }

    return res.json({ ok: true, uid: uid || null });
  });

  app.use(router);
};
