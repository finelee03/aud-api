// models/gallery.js
// 스키마를 동적으로 감지해서 owner_id/user_id, deleted_at 유무를 안전하게 처리
const db = require('./db');

/** 캐시된 컬럼셋 */
let _giCols = null;
function tableCols(name) {
  try {
    const rows = db.prepare(`PRAGMA table_info(${name})`).all();
    return new Set(rows.map(r => String(r.name)));
  } catch { return new Set(); }
}

/** gallery_items 컬럼 캐시/보장 */
function ensureGalleryTable() {
  try {
    const rows = db.prepare("PRAGMA table_info(gallery_items)").all();
    if (!rows || rows.length === 0) {
      // 테이블이 정말 없으면 최소 칼럼으로 생성(기존 DB와 충돌 없음)
      db.exec(`
        CREATE TABLE IF NOT EXISTS gallery_items (
          id         TEXT PRIMARY KEY,
          ns         TEXT,
          label      TEXT,
          created_at INTEGER,
          width      INTEGER,
          height     INTEGER,
          visibility TEXT DEFAULT 'public',
          likes      INTEGER DEFAULT 0,
          comments   INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_gallery_vis_created
          ON gallery_items(visibility, created_at DESC);
      `);
      _giCols = tableCols('gallery_items');
    } else {
      _giCols = new Set(rows.map(r => String(r.name)));
    }
  } catch {
    _giCols = new Set();
  }
}
ensureGalleryTable();

/** owner_id 선택(미존재시 user_id, 둘 다 없으면 NULL) */
function ownerIdExpr() {
  const cols = _giCols || tableCols('gallery_items');
  if (cols.has('owner_id')) return 'owner_id AS owner_id';
  if (cols.has('user_id'))  return 'user_id  AS owner_id';
  return 'NULL AS owner_id';
}

/** 주어진 컬럼이 없으면 NULL AS 로 대체 */
function colOrNull(name, asName = name) {
  const cols = _giCols || tableCols('gallery_items');
  return cols.has(name) ? `${name}${asName && asName !== name ? ` AS ${asName}` : ''}`
                        : `NULL AS ${asName}`;
}

/** 공통 SELECT 리스트(컬럼 없으면 NULL AS …로 안전 처리) */
function selectListBasic() {
  return [
    'id',
    ownerIdExpr(),
    colOrNull('ns'),
    colOrNull('label'),
    colOrNull('created_at'),
    colOrNull('width'),
    colOrNull('height'),
    colOrNull('visibility'),
    colOrNull('likes'),
    colOrNull('comments'),
  ].join(', ');
}

/** item_comments.deleted_at 존재 여부 */
let _hasDeletedAt = null;
function hasDeletedAt() {
  if (_hasDeletedAt !== null) return _hasDeletedAt;
  try {
    const rows = db.prepare(`PRAGMA table_info(item_comments)`).all();
    _hasDeletedAt = rows.some(r => r.name === 'deleted_at');
  } catch { _hasDeletedAt = false; }
  return _hasDeletedAt;
}

function getPublicFeed({ after = null, limit = 20, label = null }) {
  const lim = Math.min(Number(limit) || 20, 50);
  const list = selectListBasic();

  const hasAfter = after != null && after !== '';
  const afterClause  = hasAfter ? 'AND created_at < ?' : 'AND (? IS NULL OR created_at < ?)';
  const afterParams  = hasAfter ? [Number(after)] : [null, null];

  let sql = `SELECT ${list}
             FROM gallery_items
             WHERE visibility = 'public' `;
  const args = [];

  if (label) { sql += 'AND label = ? '; args.push(String(label)); }
  sql += `${afterClause} ORDER BY created_at DESC LIMIT ?`;

  const params = label ? [String(label), ...afterParams, lim] : [...afterParams, lim];
  return db.prepare(sql).all(...params);
}

function getItemBasic(id) {
  const list = selectListBasic();
  const sql  = `SELECT ${list} FROM gallery_items WHERE id = ?`;
  return db.prepare(sql).get(String(id));
}

function recountCounters(itemId) {
  const stmtLikes = db.prepare(`SELECT COUNT(*) c FROM item_likes WHERE item_id=?`);
  const stmtCmts  = hasDeletedAt()
    ? db.prepare(`SELECT COUNT(*) c FROM item_comments WHERE item_id=? AND deleted_at IS NULL`)
    : db.prepare(`SELECT COUNT(*) c FROM item_comments WHERE item_id=?`);

  const tx = db.transaction(() => {
    const lc = Number(stmtLikes.get(itemId).c || 0);
    const cc = Number(stmtCmts.get(itemId).c  || 0);

    // likes/comments 컬럼이 있을 때만 업데이트
    const cols = _giCols || tableCols('gallery_items');
    if (cols.has('likes') && cols.has('comments')) {
      db.prepare(`UPDATE gallery_items SET likes=?, comments=? WHERE id=?`).run(lc, cc, String(itemId));
    }
    return { likes: lc, comments: cc };
  });

  return tx();
}

module.exports = { getPublicFeed, getItemBasic, recountCounters };
