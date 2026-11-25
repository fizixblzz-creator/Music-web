'use strict';
/*
 * Website server for Render.
 * - Serves public/index.html
 * - Proxies /api/* to your VPS API and adds the API key on the server side,
 *   so the key never reaches the browser.
 *
 * Environment variables (set in Render > Environment):
 *   API_URL        VPS API address, e.g. http://1.2.3.4:3000 or https://api.yourdomain.com
 *   API_KEY        Same API key as on the VPS
 *   SITE_PASSWORD  (recommended) Password to open this website
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Readable, pipeline } = require('stream');

const PORT = parseInt(process.env.PORT || '3000', 10);
const API_URL = String(process.env.API_URL || '').trim().replace(/\/+$/, '');
const API_KEY = String(process.env.API_KEY || '').trim();
const SITE_PASSWORD = String(process.env.SITE_PASSWORD || '');

function fatal(msg) {
  console.error('[FATAL] ' + msg);
  process.exit(1);
}

if (!/^https?:\/\/[^\s/]+/i.test(API_URL)) {
  fatal('Set API_URL to your VPS API address, e.g. http://1.2.3.4:3000 or https://api.yourdomain.com');
}
if (!API_KEY) fatal('Set API_KEY (same key as on the VPS).');
if (!SITE_PASSWORD) {
  console.warn('[WARN] SITE_PASSWORD is not set: anyone who knows this website URL can use your API.');
}

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
const SESSION_SECRET = crypto
  .createHash('sha256')
  .update('mm|' + SITE_PASSWORD + '|' + API_KEY)
  .digest();
const SESSION_MS = 30 * 24 * 3600 * 1000;

// ---------- helpers ----------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function sha(v) {
  return crypto.createHash('sha256').update(String(v)).digest();
}

function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha(a), sha(b));
}

function sign(v) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('hex');
}

function makeSession() {
  const exp = String(Date.now() + SESSION_MS);
  return exp + '.' + sign(exp);
}

function validSession(req) {
  const m = /(?:^|;\s*)mm_session=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 2) return false;
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(sign(parts[0]));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  return Number(parts[0]) > Date.now();
}

function isHttps(req) {
  return String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}

function cookieHeader(req, value, maxAgeSec) {
  return 'mm_session=' + value + '; Path=/; Max-Age=' + maxAgeSec +
    '; HttpOnly; SameSite=Lax' + (isHttps(req) ? '; Secure' : '');
}

function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xff || req.socket.remoteAddress || 'unknown';
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) {
        reject(new Error('Body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// login brute-force guard (per IP + global)
const fails = new Map();
const FAIL_WINDOW_MS = 10 * 60 * 1000;
function failCount(key) {
  const f = fails.get(key);
  if (!f || Date.now() - f.t >= FAIL_WINDOW_MS) return 0;
  return f.n;
}
function addFail(key) {
  const f = fails.get(key);
  if (!f || Date.now() - f.t >= FAIL_WINDOW_MS) fails.set(key, { n: 1, t: Date.now() });
  else f.n++;
}
function loginLocked(ip) {
  return failCount(ip) >= 10 || failCount('*') >= 100;
}
function noteLoginFail(ip) {
  if (fails.size > 1000) fails.clear();
  addFail(ip);
  addFail('*');
}

function sendLogin(res, message, status) {
  const html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>Login</title><style>' +
    'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0d12;color:#e8ecf4;font:15px system-ui,sans-serif}' +
    'form{background:#141824;border:1px solid #232a3b;border-radius:12px;padding:20px;width:min(340px,90vw)}' +
    'h1{font-size:18px;margin:0 0 12px}' +
    'input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #232a3b;background:#0f1320;color:#e8ecf4;font-size:14px;box-sizing:border-box}' +
    'button{margin-top:10px;width:100%;padding:10px;border:0;border-radius:8px;background:#7c5cff;color:#fff;font-weight:600;font-size:14px;cursor:pointer}' +
    '.e{color:#fca5a5;font-size:13px;margin-top:8px;min-height:16px}' +
    '</style></head><body>' +
    '<form method="POST" action="/login"><h1>My Music</h1>' +
    '<input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password">' +
    '<button type="submit">Login</button><div class="e">' + esc(message || '') + '</div></form></body></html>';
  res.statusCode = status || 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(html);
}

// ---------- proxy to VPS ----------
const API_RE = /^\/api\/(?:search|diag|(?:prepare|stream)\/[A-Za-z0-9_-]{11})$/;
const PASS_HEADERS = [
  'content-type', 'content-length', 'content-range', 'accept-ranges',
  'cache-control', 'etag', 'last-modified',
];

async function proxy(req, res, u) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'Method not allowed' });
  if (!API_RE.test(u.pathname)) return sendJson(res, 404, { error: 'Not found' });

  const target = new URL(API_URL + u.pathname);
  for (const [k, v] of u.searchParams) {
    if (k !== 'key') target.searchParams.append(k, v);
  }

  const headers = { 'x-api-key': API_KEY };
  if (req.headers.range) headers.range = req.headers.range;
  if (req.headers['if-range']) headers['if-range'] = req.headers['if-range'];

  const heavy = /\/(prepare|stream)\//.test(u.pathname);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), heavy ? 200000 : 90000);
  res.on('close', () => ctrl.abort());

  let up;
  try {
    up = await fetch(target, { headers, signal: ctrl.signal, redirect: 'manual' });
  } catch (e) {
    clearTimeout(timer);
    if (res.destroyed || res.writableEnded) return undefined;
    const timedOut = e && e.name === 'AbortError';
    return sendJson(res, timedOut ? 504 : 502, {
      error: timedOut
        ? 'VPS API timeout'
        : 'VPS API te connect hoy nai (API_URL, firewall, ba server cholche kina dekho)',
    });
  }
  clearTimeout(timer);

  res.statusCode = up.status;
  const encoded = !!up.headers.get('content-encoding');
  for (const h of PASS_HEADERS) {
    if (h === 'content-length' && encoded) continue;
    const v = up.headers.get(h);
    if (v) res.setHeader(h, v);
  }
  if (!up.body) {
    res.end();
    return undefined;
  }
  pipeline(Readable.fromWeb(up.body), res, () => {});
  return undefined;
}

async function status(res) {
  try {
    const r = await fetch(API_URL + '/health', { signal: AbortSignal.timeout(60000), cache: 'no-store' });
    return sendJson(res, r.ok ? 200 : 502, { ok: r.ok, upstream: r.status });
  } catch (e) {
    return sendJson(res, 502, { ok: false, error: 'VPS API offline' });
  }
}

// ---------- router ----------
async function handle(req, res) {
  const u = new URL(req.url, 'http://local');
  const p = u.pathname;

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');

  if (p === '/healthz') return sendJson(res, 200, { ok: true });

  if (p === '/logout') {
    res.setHeader('Set-Cookie', cookieHeader(req, '', 0));
    res.statusCode = 303;
    res.setHeader('Location', '/');
    return res.end();
  }

  if (SITE_PASSWORD) {
    if (p === '/login') {
      if (req.method === 'POST') {
        const ip = clientIp(req);
        if (loginLocked(ip)) return sendLogin(res, 'Onek bhul attempt. Kichukkhon por try koro.', 429);
        const body = await readBody(req, 2048).catch(() => '');
        const given = new URLSearchParams(body).get('password') || '';
        if (safeEqual(given, SITE_PASSWORD)) {
          res.setHeader('Set-Cookie', cookieHeader(req, makeSession(), SESSION_MS / 1000));
          res.statusCode = 303;
          res.setHeader('Location', '/');
          return res.end();
        }
        noteLoginFail(ip);
        return sendLogin(res, 'Password thik na.', 401);
      }
      return sendLogin(res, '', 200);
    }
    if (!validSession(req)) {
      if (p.startsWith('/api/') || p === '/status') {
        return sendJson(res, 401, { error: 'Login lagbe' });
      }
      return sendLogin(res, '', 200);
    }
  }

  if (p === '/status') return status(res);
  if (p.startsWith('/api/')) return proxy(req, res, u);

  if (p === '/' || p === '/index.html') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.end(INDEX_HTML);
  }

  return sendJson(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) sendJson(res, 500, { error: 'Server error' });
    else res.end();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('[music-site] listening on port ' + PORT + ', API_URL=' + API_URL +
    ', login ' + (SITE_PASSWORD ? 'ON' : 'OFF'));
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
