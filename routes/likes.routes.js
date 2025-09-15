const express = require('express');
const router = express.Router();
const likes = require('../models/likes');
const { likeLimiter } = require('../lib/rate-limit');

function ensureAuth(req, res, next) {
  return req.session?.uid ? next() : res.status(401).json({ ok:false, error:'auth-required' });
}

router.put('/items/:id/like', ensureAuth, likeLimiter, (req, res) => {
  const itemId = String(req.params.id);
  const count = likes.putLike(req.session.uid, itemId);
  res.json({ ok: true, liked: true, likeCount: count });
});

router.delete('/items/:id/like', ensureAuth, likeLimiter, (req, res) => {
  const itemId = String(req.params.id);
  const count = likes.deleteLike(req.session.uid, itemId);
  res.json({ ok: true, liked: false, likeCount: count });
});

module.exports = router;
