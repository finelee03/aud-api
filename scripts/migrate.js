// scripts/migrate.js
// 안전한 마이그레이션: 존재하면 건너뛰고, 없으면 생성
// - 파일시스템 기반이라도 item_likes/item_comments는 생성
// - gallery_items는 선택적(생성해도 무방; 나중에 DB 기반 피드로 확장 가능)

const path = require('path');

// 프로젝트에서 이미 쓰는 동일 DB 핸들을 재사용해 경로/옵션 불일치 방지
const { db } = require('../db');

// 성능/안정
try { db.pragma('journal_mode = WAL'); } catch {}

db.exec(`
BEGIN;

-- 좋아요
CREATE TABLE IF NOT EXISTS item_likes (
  item_id    TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (item_id, user_id)
);

-- 댓글
CREATE TABLE IF NOT EXISTS item_comments (
  id         TEXT PRIMARY KEY,
  item_id    TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  text       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- (선택) 갤러리 메타(파일시스템 병행 사용 가능)
-- 서버는 현재 uploads/<ns>/_index.json을 읽지만,
-- 향후 DB 기반 피드로 바꾸거나 보조 인덱스로 쓰고 싶을 때 대비
CREATE TABLE IF NOT EXISTS gallery_items (
  id         TEXT PRIMARY KEY,
  ns         TEXT NOT NULL,
  label      TEXT,
  mime       TEXT DEFAULT 'image/png',
  created_at INTEGER NOT NULL,
  width      INTEGER DEFAULT 0,
  height     INTEGER DEFAULT 0,
  public     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_gallery_public_created
  ON gallery_items(public, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_gallery_ns_created
  ON gallery_items(ns, created_at DESC);

COMMIT;
`);

console.log('✔ migrations applied successfully');
