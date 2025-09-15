-- 댓글 테이블(평면형, 이후 parent_id로 스레드 확장 가능)
CREATE TABLE IF NOT EXISTS item_comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id    TEXT    NOT NULL,
  user_id    INTEGER NOT NULL,
  body       TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  deleted_at INTEGER,
  parent_id  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_comments_item ON item_comments (item_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_comments_user ON item_comments (user_id, created_at DESC);
