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
let PASSWORD = CFG.password; // 登录密码（引导与正常模式同一个；可修改）
const COOKIE_SECRET = Buffer.from(CFG.cookieSecret, 'hex');
const TOTP_SECRET = CFG.totpSecret; // base32
const COOKIE_MAX_AGE = CFG.cookieMaxAge || 86400;
const FIRST_LOGIN_USER = CFG.firstLoginUser || 'pi';
// 密码统一使用 PASSWORD：引导登录（+用户名）与正常登录（+动态码）同一个密码
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

function persistPassword(value) {
  PASSWORD = value;
  try {
    const d = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    d.password = value;
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(d, null, 2), { mode: 0o600 });
  } catch (e) {
    console.error('[2fa] 无法持久化密码:', e.message);
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
  // 防止 Map 无限增长：超过 10000 个条目时清理已过期记录
  if (fails.size > 10000) {
    for (const [k, v] of fails) {
      if (v.until <= now && now - v.first > 120000) fails.delete(k);
    }
  }
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
  // 关键：剥掉 accept-encoding，要求上游返回未压缩内容。
  // 否则 gzip 字节被按 utf8 转码再回传会损坏，浏览器解压失败（页面刷不出来）。
  delete headers['accept-encoding'];
  headers.host = upstream.host + ':' + upstream.port;
  // 关键：把 Origin 重写为与上游一致（否则 pi-web 的 CSRF 同源校验会把
  // 浏览器请求判为跨站 → 403 "Untrusted API request"）
  if (!isFb) headers.origin = `http://${upstream.host}:${upstream.port}`;
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
    // pi-web 上游返回 401：说明透明转发的 Basic Auth 凭据配置有误，
    // 给明确指引，避免浏览器弹出难以理解的 Basic Auth 对话框。
    if (!isFb && pr.statusCode === 401) {
      pr.resume();
      res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>配置错误</title>
<style>body{font-family:system-ui,sans-serif;background:#1a1d23;color:#e6e8eb;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#242830;padding:28px;border-radius:12px;max-width:460px;box-shadow:0 8px 24px rgba(0,0,0,.4)}
h1{font-size:17px;color:#f87171}code{background:#1a1d23;padding:2px 6px;border-radius:4px;font-size:12px}</style></head><body>
<div class="card"><h1>上游服务认证失败（401）</h1>
<p style="font-size:13px;line-height:1.7">2FA 代理向 pi-web 透明转发时被拒绝，通常是因为
<code>/etc/piweb2fa/config.json</code> 中的 <code>piUser</code> / <code>piPassword</code>
与 pi-web 实际的 Basic Auth 凭据不一致。</p>
<p style="font-size:13px;line-height:1.7">请修正后执行：<code>systemctl restart piweb2fa</code></p>
</div></body></html>`);
      return;
    }
    // 对 pi-web 的 HTML 页面注入右下角"账户 · 退出"浮动按钮
    const ct = String(pr.headers['content-type'] || '');
    if (!isFb && ct.includes('text/html')) {
      const chunks = [];
      pr.on('data', (c) => chunks.push(c));
      pr.on('end', () => {
        try {
          let html = Buffer.concat(chunks).toString('utf8');
          if (html.includes('</body>') && !html.includes('piweb2fa-account-btn')) {
            html = html.replace('</body>', ACCOUNT_BTN_SCRIPT + '</body>');
            const headers = { ...pr.headers, 'content-length': String(Buffer.byteLength(html)) };
            // 注入时删掉 transfer-encoding，避免与 content-length 冲突导致浏览器拒收
            delete headers['transfer-encoding'];
            res.writeHead(pr.statusCode, headers);
            res.end(html);
            return;
          }
          res.writeHead(pr.statusCode, pr.headers);
          res.end(Buffer.concat(chunks)); // 原始字节透传，绝不转码
        } catch (injErr) {
          // 注入失败绝不破坏页面：原样透传
          res.writeHead(pr.statusCode, pr.headers);
          res.end(Buffer.concat(chunks));
        }
      });
      return;
    }
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
<div style="text-align:center;margin-top:14px"><a href="/change-password" style="color:#9aa0a8;font-size:12px;text-decoration:none">修改密码</a></div>
</div>
<script>
if (new URLSearchParams(location.search).get('e')) document.getElementById('err').textContent = '${isBootstrap ? '用户名或密码错误' : '密码或验证码错误'}';
if (new URLSearchParams(location.search).get('b')) document.getElementById('err').textContent = '尝试次数过多，请 60 秒后再试';
if (new URLSearchParams(location.search).get('c')) document.getElementById('err').textContent = '密码已修改，请用新密码登录';
if (new URLSearchParams(location.search).get('out')) document.getElementById('err').textContent = '已退出登录';
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

function changePasswordPage(isBootstrap) {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>修改密码</title>${PAGE_CSS}</head><body>
<div class="card">
<h1>修改密码</h1>
<form method="post" action="/change-password" autocomplete="off">
<label>当前密码</label><input type="password" name="current" required autofocus autocomplete="current-password">
${isBootstrap ? '' : '<label>动态验证码（身份验证器）</label><input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>'}
<label>新密码（至少 6 位）</label><input type="password" name="new1" required autocomplete="new-password">
<label>确认新密码</label><input type="password" name="new2" required autocomplete="new-password">
<button type="submit">确认修改</button>
</form>
<div class="err" id="err"></div>
<div class="hint">${isBootstrap ? '首次登录阶段无需动态码即可修改密码' : '修改密码需验证当前密码 + 动态码'}</div>
<div style="text-align:center;margin-top:14px"><a href="/login" style="color:#9aa0a8;font-size:12px;text-decoration:none">返回登录</a></div>
</div>
<script>
if (new URLSearchParams(location.search).get('e')) document.getElementById('err').textContent = '两次输入的新密码不一致或长度不足';
if (new URLSearchParams(location.search).get('f')) document.getElementById('err').textContent = '当前密码${isBootstrap ? '' : '或动态码'}不正确';
</script>
</body></html>`;
}

// 注入到 pi-web 页面的账户按钮（JS 注入：等待 React 渲染完成后挂到「系统」侧边栏项后面）
const ACCOUNT_BTN_SCRIPT = `<script>
(function () {
  try {
    function findLabel() {
      var nodes = document.querySelectorAll('button, a, div, span');
      // 优先找侧边栏的「系统」，其次 完整历史/生成标题/分支/Pi Web
      for (var pass = 0; pass < 2; pass++) {
        for (var i = 0; i < nodes.length; i++) {
          var el = nodes[i];
          if (el.children.length > 0) continue;
          var t = el.textContent.trim();
          if (pass === 0 && t === '系统') return el;
          if (pass === 1 && (t === '完整历史' || t === '生成标题' || t === '分支' || t === 'Pi Web')) return el;
        }
      }
      return null;
    }
    function mount() {
      try {
        var btn = document.getElementById('piweb2fa-account-btn');
        if (btn) return; // 已存在则跳过；被 React 清掉后下次调用重建
        var label = findLabel();
        btn = document.createElement('a');
        btn.id = 'piweb2fa-account-btn';
        btn.href = '/account';
        btn.textContent = '帐号';
        btn.title = '账户设置 · 退出登录';
        btn.style.cssText = 'display:inline-flex;align-items:center;height:22px;padding:0 8px;margin:0 4px;border-radius:6px;border:1px solid var(--border,rgba(128,128,128,.35));background:var(--bg-panel,rgba(30,41,59,.9));color:var(--accent,#60a5fa);font-size:11px;font-weight:600;text-decoration:none;cursor:pointer;white-space:nowrap;position:relative;z-index:60';
        btn.addEventListener('click', function (e) {
          e.stopPropagation();
          e.preventDefault();
          window.location.href = '/account';
        });
        if (label && label.parentElement) {
          label.parentElement.insertBefore(btn, label.nextSibling);
        } else if (document.body) {
          document.body.appendChild(btn);
        }
      } catch (e) { /* 静默失败，绝不破坏页面 */ }
    }
    var tries = 0;
    function retry() { if (tries++ < 15) { mount(); setTimeout(retry, 400); } }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', retry);
    else retry();
    // React 重渲染导致按钮被清掉时，由观察器补挂（高频且高效）
    if (window.MutationObserver) {
      new MutationObserver(function () { mount(); }).observe(document.body, { childList: true, subtree: true });
    }
  } catch (e) { /* 绝不破坏页面 */ }
})();
</script>`;

function accountPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>账户</title>${PAGE_CSS}</head><body>
<div class="card">
<h1>账户设置</h1>
<div style="margin:14px 0;padding:12px;border:1px solid #3a3f48;border-radius:8px">
<div style="font-size:13px;color:#c9ced6">已登录（24 小时内免验证）</div>
</div>
<a href="/change-password" style="display:block;text-align:center;padding:11px;border:1px solid #3a3f48;border-radius:6px;color:#3b82f6;text-decoration:none;font-size:14px;margin-top:10px">修改密码</a>
<form method="post" action="/logout" style="margin-top:10px"><button type="submit" style="background:transparent;color:#f87171;border:1px solid #f87171">退出登录</button></form>
</div>
</body></html>`;
}

// ---------- 主服务 ----------
const server = http.createServer((req, res) => {
  const ip = clientIp(req);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/qrcode.js') {
    const qrStream = fs.createReadStream('/opt/piweb2fa/qrcode.js');
    qrStream.on('error', () => {
      if (!res.headersSent) res.writeHead(404);
      res.end();
    });
    qrStream.on('open', () => {
      res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-store' });
      qrStream.pipe(res);
    });
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

  // 账户页与退出登录（先验证 2FA cookie）
  const piweb2faCookie = parseCookies(req.headers.cookie || '').piweb2fa;
  const authed = piweb2faCookie && verifyCookie(piweb2faCookie);
  if (p === '/account') {
    if (!authed) { res.writeHead(302, { Location: '/login' }); res.end(); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(accountPage());
    return;
  }
  if (p === '/logout' && req.method === 'POST') {
    res.writeHead(302, {
      Location: '/login?out=1',
      'Set-Cookie': 'piweb2fa=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
    });
    res.end();
    return;
  }

  if (p === '/change-password' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(changePasswordPage(!setupComplete));
    return;
  }
  if (p === '/change-password' && req.method === 'POST') {
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 8192) req.destroy(); });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const cur = params.get('current') || '';
      const code = params.get('code') || '';
      const n1 = params.get('new1') || '';
      const n2 = params.get('new2') || '';
      if (n1 !== n2 || n1.length < 6) {
        res.writeHead(302, { Location: '/change-password?e=1' });
        res.end();
        return;
      }
      const curOk = timingSafeEqualStr(cur, PASSWORD) && (setupComplete ? totpValid(TOTP_SECRET, code) : true);
      if (!curOk) {
        res.writeHead(302, { Location: '/change-password?f=1' });
        res.end();
        return;
      }
      console.log(`[2fa] PASSWORD-CHANGED ip=${ip}`);
      persistPassword(n1);
      res.writeHead(302, { Location: '/login?c=1' });
      res.end();
    });
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
        // 首次登录：用户名 + 密码（默认 pi / password，与正常登录同一密码）
        const user = params.get('username') || '';
        const pass = params.get('password') || '';
        ok = timingSafeEqualStr(user, FIRST_LOGIN_USER) && timingSafeEqualStr(pass, PASSWORD);
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
