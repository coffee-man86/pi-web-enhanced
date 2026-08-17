#!/usr/bin/env node
'use strict';
/**
 * PiWeb 2FA 反向代理（脱敏可分享版）
 *
 * 功能：在 pi-web（或任意上游 Web 服务）前增加一道「密码 + TOTP 动态码」登录，
 * 登录成功后签发 24 小时签名 cookie，后续请求透明转发到上游。
 * 附带：登录限速（同 IP 60 秒 5 次失败锁 60 秒）、登录审计日志（[2fa] OK/FAIL ip=...）、
 * 可信代理密钥头（供上游校验 X-Forwarded-For）。
 *
 * 配置：/etc/piweb2fa/config.json（见 config.example.json）
 * 可选：配置 fileBrowser 段后，路径 /fb 会转发到另一个上游（如 FileBrowser 文件管理器），
 *       其余路径转发到 pi-web。
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const CFG = JSON.parse(fs.readFileSync('/etc/piweb2fa/config.json', 'utf8'));
const PORT = CFG.port;
const UPSTREAM = CFG.upstream; // {host, port} pi-web 上游
const PASSWORD = CFG.password; // 登录密码（建议与 pi-web 密码一致或独立强密码）
const COOKIE_SECRET = Buffer.from(CFG.cookieSecret, 'hex');
const TOTP_SECRET = CFG.totpSecret; // base32，供身份验证器绑定
const COOKIE_MAX_AGE = CFG.cookieMaxAge || 86400;
const PI_BASIC = 'Basic ' + Buffer.from(CFG.piUser + ':' + CFG.piPassword).toString('base64');
const FB = CFG.fileBrowser || null; // 可选：{host, port, base} 例如 {"host":"127.0.0.1","port":22055,"base":"/fb"}

// ---------- TOTP (RFC 6238) ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  s = String(s).toUpperCase().replace(/=+$/, '');
  let bits = 0, value = 0;
  const out = [];
  for (const c of s) {
    const idx = B32.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
function totpAt(secret, timeSec) {
  const counter = Math.floor(timeSec / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const code = ((h.readUInt32BE(off) & 0x7fffffff) % 1000000).toString();
  return code.padStart(6, '0');
}
function totpValid(secret, code) {
  if (!/^\d{6}$/.test(code)) return false;
  const now = Math.floor(Date.now() / 1000);
  for (const delta of [0, -1, 1]) {
    if (totpAt(secret, now + delta * 30) === code) return true;
  }
  return false;
}

// ---------- cookie 签名 ----------
function signCookie(value) {
  const mac = crypto.createHmac('sha256', COOKIE_SECRET).update(value).digest('base64url');
  return value + '.' + mac;
}
function verifyCookie(value) {
  const dot = value.lastIndexOf('.');
  if (dot < 0) return false;
  const v = value.slice(0, dot), mac = value.slice(dot + 1);
  const expect = crypto.createHmac('sha256', COOKIE_SECRET).update(v).digest('base64url');
  const a = Buffer.from(mac), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  const ts = parseInt(v, 10);
  if (!Number.isFinite(ts)) return false;
  return Date.now() / 1000 - ts < COOKIE_MAX_AGE;
}
function parseCookies(s) {
  const out = {};
  for (const part of String(s).split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ---------- 登录限速 ----------
const fails = new Map();
function throttle(ip) {
  const now = Date.now();
  let rec = fails.get(ip);
  if (!rec) { rec = { count: 0, first: now, until: 0 }; fails.set(ip, rec); }
  if (rec.until > now) return true;
  if (now - rec.first > 60000) { rec.count = 0; rec.first = now; }
  rec.count += 1;
  if (rec.count >= 5) rec.until = now + 60000;
  return false;
}

// ---------- 反向代理 ----------
function clientIp(req) {
  // 2FA 代理是公网唯一入口：直接取 TCP socket 真实地址（客户端无法伪造），
  // 并覆写转发给上游的 x-forwarded-for（消除伪造头）。
  return req.socket.remoteAddress || 'unknown';
}
function proxy(req, res, upstream, isFb) {
  const headers = { ...req.headers };
  if (!isFb) delete headers.cookie;
  delete headers.host;
  headers.host = upstream.host + ':' + upstream.port;
  if (!isFb) headers.authorization = PI_BASIC; // 透明注入 pi-web 的 Basic Auth
  headers['x-forwarded-for'] = clientIp(req);
  if (CFG.proxyToken) headers['x-piweb-proxy-token'] = CFG.proxyToken; // 可信代理密钥头
  const p = http.request({
    host: upstream.host,
    port: upstream.port,
    method: req.method,
    path: req.url,
    headers,
  }, (pr) => {
    res.writeHead(pr.statusCode, pr.headers);
    pr.pipe(res);
  });
  p.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad gateway');
  });
  req.pipe(p);
}

// ---------- 登录页 ----------
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PiWeb 登录</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#1a1d23;color:#e6e8eb;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#242830;padding:32px;border-radius:12px;width:320px;box-shadow:0 8px 24px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 20px}
label{display:block;font-size:13px;color:#9aa0a8;margin:12px 0 6px}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:6px;border:1px solid #3a3f48;background:#1a1d23;color:#e6e8eb;font-size:15px}
button{width:100%;margin-top:20px;padding:11px;border:none;border-radius:6px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#2f6fd6}
.err{color:#f87171;font-size:13px;margin-top:12px;min-height:18px}
.hint{color:#9aa0a8;font-size:12px;margin-top:14px;line-height:1.5}
</style></head><body>
<div class="card">
<h1>PiWeb 安全登录</h1>
<form method="post" action="/login" autocomplete="off">
<label>密码</label><input type="password" name="password" required autofocus>
<label>动态验证码（身份验证器）</label><input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>
<button type="submit">登 录</button>
</form>
<div class="err" id="err"></div>
<div class="hint">登录后 24 小时内免验证<br>请通过安全渠道访问</div>
</div>
<script>
if (new URLSearchParams(location.search).get('e')) document.getElementById('err').textContent = '密码或验证码错误';
if (new URLSearchParams(location.search).get('b')) document.getElementById('err').textContent = '尝试次数过多，请 60 秒后再试';
</script>
</body></html>`;

// ---------- 主服务 ----------
const server = http.createServer((req, res) => {
  const ip = clientIp(req);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/login' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(LOGIN_HTML);
    return;
  }
  if (p === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 4096) req.destroy(); });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const pass = params.get('password') || '';
      const code = params.get('code') || '';
      const ok = timingSafeEqualStr(pass, PASSWORD) && totpValid(TOTP_SECRET, code);
      if (!ok) {
        const blocked = throttle(ip);
        console.log(`[2fa] FAIL ip=${ip} blocked=${blocked ? 1 : 0}`);
        res.writeHead(302, { Location: '/login?' + (blocked ? 'b=1' : 'e=1') });
        res.end();
        return;
      }
      console.log(`[2fa] OK ip=${ip}`);
      const ts = String(Math.floor(Date.now() / 1000));
      res.writeHead(302, {
        Location: '/',
        'Set-Cookie': `piweb2fa=${signCookie(ts)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`,
      });
      res.end();
    });
    return;
  }

  const cookie = parseCookies(req.headers.cookie || '').piweb2fa;
  if (!cookie || !verifyCookie(cookie)) {
    res.writeHead(302, { Location: '/login' });
    res.end();
    return;
  }

  // 可选：/fb 前缀转发到文件管理器（如 FileBrowser），其余转发到 pi-web
  const isFb = FB !== null && (p === FB.base || p.startsWith(FB.base + '/'));
  proxy(req, res, isFb ? FB : UPSTREAM, isFb);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[2fa] PiWeb 2FA proxy listening on :${PORT} -> ${UPSTREAM.host}:${UPSTREAM.port}${FB ? `, ${FB.base} -> ${FB.host}:${FB.port}` : ''}`);
});
