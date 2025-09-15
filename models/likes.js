const db = require('./db');

function putLike(userId, itemId) {
  const now = Date.now();
  const tx = db.transaction(() => {
    try {
      db.prepare(`INSERT INTO item_likes (item_id, user_id, created_at) VALUES (?, ?, ?)`)
        .run(itemId, userId, now);
      db.prepare(`UPDATE gallery_items SET likes = likes + 1 WHERE id=?`).run(itemId);
    } catch (e) { /* UNIQUE → 이미 좋아요 */ }
    return count(itemId);
  });
  return tx();
}

function deleteLike(userId, itemId) {
  const tx = db.transaction(() => {
    const info = db.prepare(`DELETE FROM item_likes WHERE item_id=? AND user_id=?`).run(itemId, userId);
    if (info.changes > 0) {
      db.prepare(`UPDATE gallery_items SET likes = MAX(likes - 1, 0) WHERE id=?`).run(itemId);
    }
    return count(itemId);
  });
  return tx();
}

function count(itemId) {
  return db.prepare(`SELECT COUNT(*) c FROM item_likes WHERE item_id=?`).get(itemId).c;
}

function bulkLikedMap(userId, itemIds) {
  if (!itemIds.length) return {};
  const q = itemIds.map(() => '?').join(',');
  const rows = db.prepare(`SELECT item_id FROM item_likes WHERE user_id=? AND item_id IN (${q})`)
                 .all(userId, ...itemIds);
  return Object.fromEntries(rows.map(r => [r.item_id, true]));
}

module.exports = { putLike, deleteLike, count, bulkLikedMap };
