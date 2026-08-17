#!/usr/bin/env node
'use strict';
/**
 * PiWeb 2FA 反向代理（脱敏可分享版）
 *
 * 功能：在 pi-web（或任意上游 Web 服务）前增加「密码 + TOTP 动态码」登录，
 * 登录成功后签发 24 小时签名 cookie，后续请求透明转发到上游。
 *
 * 首次登录引导（全新安装）：
 *   1) 安装后 setupComplete=false，登录页为「用户名 + 密码」（默认 pi / password）
 *   2) 首次登录成功 → 强制跳转 /setup 绑定页（显示二维码 + 说明）
 *   3) 手机绑定后点「我已经绑定」→ setupComplete=true → 之后按正常 2FA 流程
 *
 * 附带：登录限速（同 IP 60 秒 5 次失败锁 60 秒）、审计日志（[2fa] OK/FAIL ip=...）、
 * 可信代理密钥头（供上游校验 X-Forwarded-For）。
 *
 * 配置：/etc/piweb2fa/config.json（见 config.example.json）
 * 可选：fileBrowser 段配置后 /fb 前缀转发到文件管理器。
 * 二维码库：/opt/piweb2fa/qrcode.js（qrcode-generator，MIT）
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const CONFIG_PATH = '/etc/piweb2fa/config.json';
const CFG = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const PORT = CFG.port;
const UPSTREAM = CFG.upstream; // {host, port}
const PASSWORD = CFG.password; // 正常模式登录密码
const COOKIE_SECRET = Buffer.from(CFG.cookieSecret, 'hex');
const TOTP_SECRET = CFG.totpSecret; // base32
const COOKIE_MAX_AGE = CFG.cookieMaxAge || 86400;
const FIRST_LOGIN_USER = CFG.firstLoginUser || 'pi';
const FIRST_LOGIN_PASSWORD = CFG.firstLoginPassword || 'password';
const PI_BASIC = 'Basic ' + Buffer.from(CFG.piUser + ':' + CFG.piPassword).toString('base64');
const FB = CFG.fileBrowser || null;

// 首次登录是否已完成（全新安装为 false；已有安装缺省视为已完成，不破坏现有流程）
let setupComplete = CFG.setupComplete !== false;

function persistSetupComplete(value) {
  setupComplete = value;
  try {
    const d = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    d.setupComplete = value;
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(d, null, 2), { mode: 0o600 });
  } catch (e) {
    console.error('[2fa] 无法持久化 setupComplete:', e.message);
  }
}

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

// ---------- cookie ----------
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

// ---------- 限速 ----------
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
  return req.socket.remoteAddress || 'unknown';
}
function proxy(req, res, upstream, isFb) {
  const headers = { ...req.headers };
  if (!isFb) delete headers.cookie;
  delete headers.host;
  headers.host = upstream.host + ':' + upstream.port;
  if (!isFb) headers.authorization = PI_BASIC;
  headers['x-forwarded-for'] = clientIp(req);
  if (CFG.proxyToken) headers['x-piweb-proxy-token'] = CFG.proxyToken;
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

// ---------- 页面 ----------
const PAGE_CSS = `<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#1a1d23;color:#e6e8eb;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#242830;padding:32px;border-radius:12px;width:340px;box-shadow:0 8px 24px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 20px}
label{display:block;font-size:13px;color:#9aa0a8;margin:12px 0 6px}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:6px;border:1px solid #3a3f48;background:#1a1d23;color:#e6e8eb;font-size:15px}
button{width:100%;margin-top:20px;padding:11px;border:none;border-radius:6px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#2f6fd6}
.err{color:#f87171;font-size:13px;margin-top:12px;min-height:18px}
.hint{color:#9aa0a8;font-size:12px;margin-top:14px;line-height:1.5}
.warn{color:#f59e0b;font-size:12px;line-height:1.5;margin-top:12px}
.qrbox{display:flex;justify-content:center;margin:16px 0;padding:14px;background:#fff;border-radius:10px}
.qrbox img{width:220px;height:220px;image-rendering:pixelated}
.secret{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#e6e8eb;background:#1a1d23;border:1px solid #3a3f48;border-radius:6px;padding:8px;word-break:break-all;margin-top:8px;user-select:all}
</style>`;

function loginPage(isBootstrap) {
  const fields = isBootstrap
    ? `<label>用户名</label><input type="text" name="username" required autofocus autocomplete="username">
<label>密码</label><input type="password" name="password" required autocomplete="current-password">`
    : `<label>密码</label><input type="password" name="password" required autofocus autocomplete="current-password">
<label>动态验证码（身份验证器）</label><input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>`;
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PiWeb 登录</title>${PAGE_CSS}</head><body>
<div class="card">
<h1>PiWeb ${isBootstrap ? '首次登录' : '安全登录'}</h1>
<form method="post" action="/login" autocomplete="on">
${fields}
<button type="submit">登 录</button>
</form>
<div class="err" id="err"></div>
${isBootstrap ? '<div class="warn">⚠️ 首次登录后必须完成身份验证器绑定，否则仅凭此账号密码即可访问，请立即绑定。</div>' : '<div class="hint">登录后 24 小时内免验证</div>'}
</div>
<script>
if (new URLSearchParams(location.search).get('e')) document.getElementById('err').textContent = '${isBootstrap ? '用户名或密码错误' : '密码或验证码错误'}';
if (new URLSearchParams(location.search).get('b')) document.getElementById('err').textContent = '尝试次数过多，请 60 秒后再试';
</script>
</body></html>`;
}

function setupPage(secret) {
  const otpauth = `otpauth://totp/PiWeb?secret=${secret}&issuer=PiWeb`;
  const escaped = otpauth.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>绑定身份验证器</title>${PAGE_CSS}</head><body>
<div class="card" style="width:360px">
<h1>绑定身份验证器（仅需一次）</h1>
<ol style="font-size:13px;line-height:1.7;color:#c9ced6;margin:0;padding-left:18px">
<li>手机安装身份验证器（Google Authenticator / Microsoft Authenticator / 微信"身份验证器"）</li>
<li>选择「扫描二维码」对准下方二维码，或「手动输入」密钥</li>
<li>看到 6 位动态码后，点击底部按钮完成</li>
</ol>
<div class="qrbox"><img id="qr" alt="QR Code" /></div>
<div class="secret" id="secret">${secret}</div>
<div class="hint" style="margin-top:10px">二维码由本页面生成，密钥仅在本次安装有效</div>
<div class="warn">⚠️ 完成绑定前，仅凭初始账号密码即可登录，请立即完成。</div>
<button id="done" type="button">我已经绑定，继续使用</button>
</div>
<script src="/qrcode.js"></script>
<script>
var qr = qrcode(0, 'M');
qr.addData('${escaped}');
qr.make();
document.getElementById('qr').src = qr.createDataURL(8, 8);
document.getElementById('done').onclick = function () {
  fetch('/setup-complete', { method: 'POST' }).then(function (r) {
    if (r.ok) location.href = '/';
    else alert('操作失败，请重试');
  });
};
</script>
</body></html>`;
}

// ---------- 主服务 ----------
const server = http.createServer((req, res) => {
  const ip = clientIp(req);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/qrcode.js') {
    try {
      res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-store' });
      fs.createReadStream('/opt/piweb2fa/qrcode.js').pipe(res);
    } catch {
      res.writeHead(404); res.end();
    }
    return;
  }

  if (p === '/setup' && !setupComplete) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(setupPage(TOTP_SECRET));
    return;
  }
  if (p === '/setup-complete' && req.method === 'POST' && !setupComplete) {
    console.log(`[2fa] SETUP-COMPLETE ip=${ip}`);
    persistSetupComplete(true);
    res.writeHead(302, { Location: '/' });
    res.end();
    return;
  }

  if (p === '/login' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(loginPage(!setupComplete));
    return;
  }
  if (p === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 4096) req.destroy(); });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      let ok = false;
      if (!setupComplete) {
        // 首次登录：用户名 + 密码（默认 pi / password）
        const user = params.get('username') || '';
        const pass = params.get('password') || '';
        ok = timingSafeEqualStr(user, FIRST_LOGIN_USER) && timingSafeEqualStr(pass, FIRST_LOGIN_PASSWORD);
      } else {
        const pass = params.get('password') || '';
        const code = params.get('code') || '';
        ok = timingSafeEqualStr(pass, PASSWORD) && totpValid(TOTP_SECRET, code);
      }
      if (!ok) {
        const blocked = throttle(ip);
        console.log(`[2fa] FAIL ip=${ip} blocked=${blocked ? 1 : 0}`);
        res.writeHead(302, { Location: '/login?' + (blocked ? 'b=1' : 'e=1') });
        res.end();
        return;
      }
      console.log(`[2fa] OK ip=${ip}${setupComplete ? '' : ' (first-login)'}`);
      if (!setupComplete) {
        // 首次登录成功 → 强制去绑定页
        res.writeHead(302, { Location: '/setup' });
        res.end();
        return;
      }
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

  const isFb = FB !== null && (p === FB.base || p.startsWith(FB.base + '/'));
  proxy(req, res, isFb ? FB : UPSTREAM, isFb);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[2fa] PiWeb 2FA proxy listening on :${PORT} -> ${UPSTREAM.host}:${UPSTREAM.port}${FB ? `, ${FB.base} -> ${FB.host}:${FB.port}` : ''}`);
  console.log(`[2fa] setupComplete=${setupComplete ? 'true (正常 2FA 模式)' : 'false (首次登录引导模式)'}`);
});
