// 간단한 토큰버킷 레이트리미터
const buckets = new Map(); // key -> { tokens, ts }
function limit(key, capacity, refillPerSec) {
  const now = Date.now() / 1000;
  const b = buckets.get(key) || { tokens: capacity, ts: now };
  b.tokens = Math.min(capacity, b.tokens + (now - b.ts) * refillPerSec);
  b.ts = now;
  if (b.tokens < 1) { buckets.set(key, b); return false; }
  b.tokens -= 1; buckets.set(key, b); return true;
}

function makeLimiter(name, capacity, refillPerSec) {
  return (req, res, next) => {
    const k = `${name}:${req.session?.uid || req.ip}`;
    return limit(k, capacity, refillPerSec)
      ? next()
      : res.status(429).json({ ok: false, error: 'rate' });
  };
}

module.exports = {
  likeLimiter:    makeLimiter('like', 10, 2),    // 초당 2개, 버킷 10
  commentLimiter: makeLimiter('comment', 5, 0.5) // 초당 0.5개, 버킷 5
};
