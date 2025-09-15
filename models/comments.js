const db = require('./db');

function create({ itemId, userId, body }) {
  const now = Date.now();
  const tx = db.transaction(() => {
    const info = db.prepare(`
      INSERT INTO item_comments(item_id,user_id,body,created_at)
      VALUES (?,?,?,?)
    `).run(itemId, userId, body, now);
    db.prepare(`UPDATE gallery_items SET comments = comments + 1 WHERE id=?`).run(itemId);
    return db.prepare(`
      SELECT c.id, c.item_id, c.user_id, c.body, c.created_at, u.display_name AS author
      FROM item_comments c JOIN users u ON u.id=c.user_id
      WHERE c.id=?
    `).get(info.lastInsertRowid);
  });
  return tx();
}

function list({ itemId, after = 0, limit = 20 }) {
  const lim = Math.min(Number(limit) || 20, 50);
  return db.prepare(`
    SELECT c.id, c.item_id, c.user_id, c.body, c.created_at, c.updated_at, c.deleted_at,
           u.display_name AS author
    FROM item_comments c JOIN users u ON u.id=c.user_id
    WHERE c.item_id=? AND (?=0 OR c.created_at > ?)
    ORDER BY c.created_at ASC
    LIMIT ?
  `).all(itemId, Number(after) || 0, Number(after) || 0, lim);
}

function edit({ commentId, userId, body, allowMs = 10 * 60 * 1000 }) {
  const row = db.prepare(`SELECT user_id, created_at, deleted_at FROM item_comments WHERE id=?`).get(commentId);
  if (!row || row.deleted_at) throw new Error('not-found');
  if (row.user_id !== userId) throw new Error('forbidden');
  if (Date.now() - row.created_at > allowMs) throw new Error('edit-window');
  db.prepare(`UPDATE item_comments SET body=?, updated_at=? WHERE id=?`).run(body, Date.now(), commentId);
  return true;
}

function softDelete({ commentId, actorId, isAdmin = false, itemOwnerId = null }) {
  const row = db.prepare(`SELECT item_id, user_id, deleted_at FROM item_comments WHERE id=?`).get(commentId);
  if (!row || row.deleted_at) throw new Error('not-found');
  const isOwner = row.user_id === actorId;
  const can = isOwner || isAdmin || (itemOwnerId && itemOwnerId === actorId);
  if (!can) throw new Error('forbidden');
  const tx = db.transaction(() => {
    db.prepare(`UPDATE item_comments SET deleted_at=? WHERE id=?`).run(Date.now(), commentId);
    db.prepare(`UPDATE gallery_items SET comments = MAX(comments - 1, 0) WHERE id=?`).run(row.item_id);
  });
  tx();
  return true;
}

module.exports = { create, list, edit, softDelete };
