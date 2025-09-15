// likes/comments 카운터 재계산
const gallery = require('../models/gallery');
const db = require('../models/_db');
const argv = require('minimist')(process.argv.slice(2));
const itemId = argv.item || argv.i || null;

if (itemId) {
  const r = gallery.recountCounters(String(itemId));
  console.log('recount', itemId, r);
  process.exit(0);
}

const rows = db.prepare(`SELECT id FROM gallery_items`).all();
for (const r of rows) {
  const out = gallery.recountCounters(r.id);
  console.log('recount', r.id, out);
}
console.log('done');
