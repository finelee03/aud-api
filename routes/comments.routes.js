const express = require('express');
const router = express.Router();
const comments = require('../models/comments');
const gallery = require('../models/gallery');
const { sanitizeText, clampString } = require('../lib/sanitize');
const { commentLimiter } = require('../lib/rate-limit');

function ensureAuth(req, res, next) {
  return req.session?.uid ? next() : res.status(401).json({ ok:false, error:'auth-required' });
}

// 조회
router.get('/items/:id/comments', (req, res) => {
  const itemId = String(req.params.id);
  const after = req.query.after ? Number(req.query.after) : 0;
  const limit = req.query.limit ? Number(req.query.limit) : 20;

  const it = gallery.getItemBasic(itemId);
  if (!it) return res.status(404).json({ ok:false, error:'not-found' });
  if (it.visibility !== 'public') {
    const me = req.session?.uid;
    if (!me || me !== it.owner_id) return res.status(403).json({ ok:false, error:'forbidden' });
  }

  const rows = comments.list({ itemId, after, limit });
  const nextCursor = rows.length ? rows[rows.length - 1].created_at : null;
  res.json({ ok:true, comments: rows, nextCursor });
});

// 생성
router.post('/items/:id/comments', ensureAuth, commentLimiter, (req, res) => {
  const itemId = String(req.params.id);
  const it = gallery.getItemBasic(itemId);
  if (!it) return res.status(404).json({ ok:false, error:'not-found' });
  if (it.visibility !== 'public' && it.owner_id !== req.session.uid)
    return res.status(403).json({ ok:false, error:'forbidden' });

  const body = sanitizeText(clampString(req.body?.body, 2000));
  if (!body) return res.status(400).json({ ok:false, error:'empty' });

  const c = comments.create({ itemId, userId: req.session.uid, body });
  res.json({ ok:true, comment: c });
});

// 편집
router.patch('/comments/:cid', ensureAuth, (req, res) => {
  try {
    comments.edit({
      commentId: Number(req.params.cid),
      userId: req.session.uid,
      body: sanitizeText(req.body?.body)
    });
    res.json({ ok: true });
  } catch (e) {
    const m = String(e.message || '');
    if (m === 'not-found') return res.status(404).json({ ok:false, error:m });
    if (m === 'forbidden' || m === 'edit-window') return res.status(403).json({ ok:false, error:m });
    res.status(400).json({ ok:false, error:'bad-request' });
  }
});

// 삭제
router.delete('/comments/:cid', ensureAuth, (req, res) => {
  const cid = Number(req.params.cid);
  try {
    comments.softDelete({ commentId: cid, actorId: req.session.uid, isAdmin: req.session?.role === 'admin', itemOwnerId: null });
    res.json({ ok: true });
  } catch (e) {
    const m = String(e.message || '');
    if (m === 'not-found') return res.status(404).json({ ok:false, error:m });
    if (m === 'forbidden') return res.status(403).json({ ok:false, error:m });
    res.status(400).json({ ok:false, error:'bad-request' });
  }
});

module.exports = router;
