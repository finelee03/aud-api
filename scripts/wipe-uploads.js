#!/usr/bin/env node
"use strict";

/**
 * Wipe all posts you own (and their blobs) for a given namespace.
 * 1) API-first: list → delete items (robust, multi-endpoint fallback, CSRF aware)
 * 2) FS-fallback: removes uploads folder when API is unavailable (best-effort)
 *
 * Usage:
 *   node script/wipe-uploads.js [--yes] [--dry] [--ns=xxx] [--base=http://...] [--token=...] [--cookie="k=v; ..."]
 *
 * .env (optional):
 *   BASE_URL=http://localhost:3000
 *   USER_NS=default
 *   AUTH_TOKEN=...          # Bearer token (optional)
 *   AUTH_COOKIE=connect.sid=...; another=...   # cookie string (optional)
 *   UPLOAD_DIR=./uploads    # FS fallback target
 */

const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const readline = require("readline");

// ── 0) env & argv
try { require("dotenv").config(); } catch {}
const argv = process.argv.slice(2);

const arg = (key, def=null) => {
  const pref = `${key}=`;
  const m = argv.find(a => a.startsWith(pref));
  return m ? m.slice(pref.length) : def;
};
const has = (flag) => argv.includes(flag);

const BASE_URL   = arg("--base", process.env.BASE_URL || "http://localhost:3000");
const USER_NS    = arg("--ns",   process.env.USER_NS || "default");
const AUTH_TOKEN = arg("--token", process.env.AUTH_TOKEN || process.env.ADMIN_TOKEN || null);
const AUTH_COOKIE= arg("--cookie", process.env.AUTH_COOKIE || null);
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.resolve(process.cwd(), "uploads");
const DRY_RUN    = has("--dry");
const YES        = has("--yes");

// ── 1) tiny logger
const stamp = () => new Date().toISOString().replace('T',' ').replace('Z','');
const log = (...a) => console.log(`[${stamp()}]`, ...a);
const warn= (...a) => console.warn(`[${stamp()}]`, ...a);

// ── 2) confirm
async function confirmDanger(question) {
  if (YES) return true;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(res => rl.question(q, ans => res(ans)));
  const ans = (await ask(`${question}\n  계속하려면 대문자로 "DELETE" 를 입력하세요: `)).trim();
  rl.close();
  return ans === "DELETE";
}

// ── 3) HTTP helpers (Node18+ fetch)
function buildHeaders(extra = {}) {
  const h = new Headers(extra || {});
  h.set("Accept", "application/json");
  if (AUTH_TOKEN && !h.has("Authorization")) h.set("Authorization", `Bearer ${AUTH_TOKEN}`);
  if (AUTH_COOKIE && !h.has("Cookie"))       h.set("Cookie", AUTH_COOKIE);
  return h;
}

async function http(pathOrURL, init = {}) {
  const url = new URL(pathOrURL, BASE_URL).toString();
  const headers = buildHeaders(init.headers);
  return await fetch(url, { ...init, headers });
}

async function getCSRF() {
  try {
    const r = await http("/auth/csrf", { method: "GET", cache: "no-store" });
    const j = await r.json().catch(()=> ({}));
    return j?.csrfToken || null;
  } catch { return null; }
}

async function getMe() {
  try {
    const r = await http("/auth/me", { method: "GET", cache: "no-store" });
    const j = await r.json().catch(()=> ({}));
    // common shapes: {id}, {user:{id}}, etc.
    return j?.user || j || null;
  } catch { return null; }
}

// robust delete call (DELETE → POST fallback → legacy)
async function deleteItemById(id, ns, csrfToken) {
  const pid = encodeURIComponent(id);
  const nsq = `ns=${encodeURIComponent(ns)}`;
  const common = { credentials: "include" };

  const withCSRF = (opt={}) => {
    const h = buildHeaders(opt.headers);
    if (csrfToken) h.set("x-csrf-token", csrfToken);
    return { ...opt, headers: h };
  };

  // 1) DELETE /api/items/:id?ns=...
  let r = await http(`/api/items/${pid}?${nsq}`, withCSRF({ ...common, method: "DELETE" }));

  // 2) POST /api/items/:id/delete?ns=...
  if (!r.ok && (r.status === 404 || r.status === 405)) {
    r = await http(`/api/items/${pid}/delete?${nsq}`, withCSRF({
      ...common, method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    }));
  }

  // 3) POST /api/delete?item=ID&ns=...
  if (!r.ok && (r.status === 404 || r.status === 405)) {
    r = await http(`/api/delete?item=${pid}&${nsq}`, withCSRF({
      ...common, method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    }));
  }

  const j = await r.json().catch(()=> ({}));
  if (!r.ok || j?.ok === false) throw new Error(`delete-fail(${id}) status=${r.status}`);
  return true;
}

// list all my visible items from the public feed (cursor-aware)
async function listMyItems(ns) {
  const out = [];
  let cursor = null;
  let page = 0;

  const me = await getMe();
  const myId = me?.id ?? me?.user?.id ?? null;

  do {
    page++;
    const qs = new URLSearchParams({ limit: "200", ns });
    if (cursor) qs.set("cursor", String(cursor));

    const r = await http(`/api/gallery/public?${qs.toString()}`, { method: "GET", cache: "no-store" });
    if (!r.ok) {
      warn(`feed page ${page} load failed (status=${r.status}). Stop listing.`);
      break;
    }
    const j = await r.json().catch(()=> ({}));
    const items = Array.isArray(j?.items) ? j.items : (Array.isArray(j) ? j : []);
    if (!items.length) break;

    // mine-only
    for (const it of items) {
      const uid = it?.user?.id ?? it?.user_id ?? it?.owner_id ?? it?.meta?.user_id ?? it?.meta?.owner_id ?? null;
      if (!myId || (uid && String(uid) === String(myId))) out.push({ id: it.id, ns, label: it.label });
    }

    cursor = j?.nextCursor || null;
  } while (cursor);

  return out;
}

// tight concurrency runner
function makeLimiter(n = 6) {
  let active = 0;
  const queue = [];
  const runNext = () => {
    if (active >= n || queue.length === 0) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    Promise.resolve()
      .then(fn)
      .then((v) => { active--; resolve(v); runNext(); })
      .catch((e) => { active--; reject(e); runNext(); });
  };
  return (fn) => new Promise((resolve, reject) => { queue.push({ fn, resolve, reject }); runNext(); });
}

// FS fallback — best effort (dangerous, irreversible)
async function wipeUploadsFS(dir) {
  try {
    await fsp.rm(dir, { recursive: true, force: true });
    await fsp.mkdir(dir, { recursive: true });
    return true;
  } catch (e) {
    warn("FS fallback failed:", e?.message || e);
    return false;
  }
}

// ── main
(async () => {
  log("Wipe uploads start");
  log(`BASE_URL=${BASE_URL}`);
  log(`USER_NS=${USER_NS}`);
  if (AUTH_TOKEN) log("AUTH_TOKEN: provided");
  if (AUTH_COOKIE) log("AUTH_COOKIE: provided");
  if (DRY_RUN) log("DRY RUN mode (no writes).");

  const ok = await confirmDanger(
    `네임스페이스 "${USER_NS}" 에서 당신이 올린 "모든 게시물"을 삭제합니다.\n` +
    `API 삭제가 실패하면 파일시스템("${UPLOAD_DIR}") 삭제를 시도합니다. 이 작업은 되돌릴 수 없습니다.`
  );
  if (!ok) { log("Aborted."); process.exit(1); }

  // 1) API path
  let apiSucceeded = false;
  try {
    // quick probe
    const probe = await http("/auth/me", { method: "GET", cache: "no-store" });
    if (probe.ok) {
      const csrf = await getCSRF().catch(()=> null);
      const items = await listMyItems(USER_NS);
      log(`Found ${items.length} post(s) owned by you in ns="${USER_NS}".`);

      if (items.length) {
        if (DRY_RUN) {
          items.forEach(it => log(`[dry] would delete id=${it.id} label=${it.label||""}`));
        } else {
          const limit = makeLimiter(6);
          let okCnt = 0, failCnt = 0;
          const tasks = items.map(it => limit(async () => {
            try {
              await deleteItemById(it.id, USER_NS, csrf);
              log(`Deleted: ${it.id}`);
              okCnt++;
            } catch (e) {
              warn(`Delete failed: ${it.id} — ${e?.message||e}`);
              failCnt++;
            }
          }));
          await Promise.allSettled(tasks);
          log(`API deletion done. success=${okCnt}, failed=${failCnt}`);
          if (failCnt === 0) apiSucceeded = true;
        }
      } else {
        apiSucceeded = true; // nothing to delete, but API reachable
        log("No items to delete via API.");
      }
    } else {
      warn(`API probe failed (status=${probe.status}). Will try FS fallback.`);
    }
  } catch (e) {
    warn("API path error:", e?.message || e);
  }

  // 2) FS fallback (only if API not fully successful and not DRY)
  if (!apiSucceeded && !DRY_RUN) {
    log(`Falling back to filesystem wipe: ${UPLOAD_DIR}`);
    const okFS = await wipeUploadsFS(UPLOAD_DIR);
    if (!okFS) {
      warn("Filesystem wipe failed.");
      process.exitCode = 2;
      return;
    }
    log("Filesystem wipe completed.");
  }

  log("Wipe uploads finished.");
})();
