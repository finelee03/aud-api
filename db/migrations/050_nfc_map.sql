-- 050_nfc_map.sql — NFC UID → Label 매핑 (ns별 격리)
CREATE TABLE IF NOT EXISTS nfc_map (
  ns         TEXT NOT NULL,
  uid        TEXT NOT NULL,
  label      TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  PRIMARY KEY (ns, uid)
);
CREATE INDEX IF NOT EXISTS idx_nfc_map_ns_label ON nfc_map(ns, label);
