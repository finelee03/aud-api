#!/usr/bin/env node
const { db } = require('../db'); // 프로젝트 루트 기준
db.exec('DELETE FROM item_likes; DELETE FROM item_comments; VACUUM;');
console.log('likes/comments cleared.');
