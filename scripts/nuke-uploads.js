#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const UPLOAD_ROOT = path.join(__dirname, '..', 'uploads');

const args = process.argv.slice(2);
const ns = getArg('--ns');        // 없으면 전체
const yes = args.includes('--yes');

if (!yes) {
  console.error('안전장치: --yes 를 함께 붙여 실행하세요.');
  process.exit(1);
}

const target = ns ? path.join(UPLOAD_ROOT, ns) : UPLOAD_ROOT;
fs.rmSync(target, { recursive: true, force: true });
if (!ns) fs.mkdirSync(UPLOAD_ROOT, { recursive: true });

console.log('deleted:', target);

function getArg(k){
  const i = args.findIndex(a => a===k || a.startsWith(k+'='));
  if (i<0) return null;
  return args[i].includes('=') ? args[i].split('=')[1] : args[i+1];
}
