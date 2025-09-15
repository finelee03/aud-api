-- 좋아요 테이블
CREATE TABLE IF NOT EXISTS item_likes (
  item_id    TEXT    NOT NULL,
  user_id    INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (item_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_likes_item ON item_likes (item_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_likes_user ON item_likes (user_id, created_at DESC);
