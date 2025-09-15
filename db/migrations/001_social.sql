-- db/migrations/001_social.sql
CREATE TABLE IF NOT EXISTS item_likes (
  item_id   TEXT NOT NULL,
  user_id   TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (item_id, user_id)
);

CREATE TABLE IF NOT EXISTS item_comments (
  id         TEXT PRIMARY KEY,
  item_id    TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  text       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
