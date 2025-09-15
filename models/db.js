// 모든 모델이 같은 better-sqlite3 인스턴스를 쓰도록 ../db에서 끌어온다.
const { db } = require('../db');
if (!db || typeof db.prepare !== 'function') {
  throw new Error('db instance not available from ../db');
}
module.exports = db;

