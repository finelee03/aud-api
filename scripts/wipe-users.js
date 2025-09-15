// scripts/wipe-users.js
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

// ① app에서 쓰는 메인 DB (users 테이블이 들어있는 DB)
let db;
try {
  // db.js가 Database 인스턴스를 export 한다면 이게 가장 안전함
  db = require("../db");
} catch (_) {}

if (!db || typeof db.prepare !== "function") {
  // db.js에서 직접 인스턴스를 export 하지 않는다면 파일명을 직접 지정
  // ⬇️ 실제 파일명으로 바꿔주세요: 예) aud.sqlite, data.sqlite, app.sqlite 등
  const DB_FILE = path.join(__dirname, "..", "aud.sqlite");
  db = new Database(DB_FILE);
  console.log("[wipe] opened", DB_FILE);
}

const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
console.log("[wipe] users before:", count);

// 전체 계정 삭제
db.exec("DELETE FROM users; VACUUM;");
console.log("[wipe] users after :", db.prepare("SELECT COUNT(*) AS c FROM users").get().c);

// ② 세션 DB 정리(로그인 유지 쿠키를 날려서 강제 로그아웃)
try {
  const sessFile = path.join(__dirname, "..", "sessions.sqlite");
  fs.rmSync(sessFile, { force: true });
  console.log("[wipe] removed sessions file:", sessFile);
} catch (e) {
  console.log("[wipe] skip sessions:", e.message);
}

// ③ 업로드된 갤러리 이미지까지 싹 (원치 않으면 주석 처리)
try {
  const uploadsDir = path.join(__dirname, "..", "uploads");
  fs.rmSync(uploadsDir, { recursive: true, force: true });
  console.log("[wipe] removed uploads dir:", uploadsDir);
} catch (e) {
  console.log("[wipe] skip uploads:", e.message);
}

console.log("[wipe] done.");
