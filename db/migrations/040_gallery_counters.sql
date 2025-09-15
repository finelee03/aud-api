-- (선택) gallery_items에 댓글 카운터 컬럼 추가
ALTER TABLE gallery_items ADD COLUMN comments INTEGER NOT NULL DEFAULT 0;
