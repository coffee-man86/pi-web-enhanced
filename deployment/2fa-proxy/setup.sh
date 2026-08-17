#!/bin/bash
# 一键安装 PiWeb 2FA 代理（在运行 pi-web 的 Linux 主机上执行，需要 root）
# 用法：sudo bash setup.sh [端口] [上游端口]
# 示例：sudo bash setup.sh 42204 25133
#
# 流程：收集配置 → 生成随机密钥 → 写配置 → 装服务 → 打印绑定信息
# 首次登录引导：安装后 setupComplete=false，用 用户名 pi / 密码（你设置的首次密码）
# 登录，页面强制显示身份验证器二维码，绑定后点「我已经绑定」即进入正常 2FA。
set -e

PORT="${1:-42204}"
UPSTREAM_PORT="${2:-25133}"
CONF_DIR=/etc/piweb2fa
APP_DIR=/opt/piweb2fa

# ---------- 前置检查 ----------
command -v node >/dev/null 2>&1 || { echo "错误：需要 Node.js >= 18（node 命令未找到）"; exit 1; }
NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])" 2>/dev/null || echo 0)
[ "$NODE_MAJOR" -ge 18 ] 2>/dev/null || { echo "错误：Node.js 版本过低（当前 $(node -v 2>/dev/null || echo '未知')，需要 >= 18）"; exit 1; }
[ -f qrcode.js ] || { echo "错误：缺少 qrcode.js（请与 setup.sh 放在同一目录）"; exit 1; }
[ -f server.js ] || { echo "错误：缺少 server.js（请与 setup.sh 放在同一目录）"; exit 1; }

echo "==> 收集配置（Ctrl+C 可取消）"
read -r -p "  登录密码（默认 password，引导与正常登录同一个密码，安装后可改）: " TWOFA_PW
TWOFA_PW="${TWOFA_PW:-password}"
read -r -p "  pi-web Basic Auth 用户名（默认 pi）: " PI_USER
PI_USER="${PI_USER:-pi}"
read -r -s -p "  pi-web 的密码（用于透明转发）: " PI_PW; echo
[ -n "$PI_PW" ] || { echo "错误：pi-web 密码不能为空"; exit 1; }"

echo "==> 生成随机密钥（每次安装独立，不共享）..."
TOTP=$(head -c 20 /dev/urandom | base32 | tr -d '=' | tr -d '\n')
COOKIE=$(head -c 32 /dev/urandom | xxd -p -c 64)
TOKEN=$(head -c 24 /dev/urandom | xxd -p -c 64)

echo "==> 写入配置 $CONF_DIR/config.json"
mkdir -p "$CONF_DIR" "$APP_DIR"
cp server.js "$APP_DIR/server.js"
cp qrcode.js "$APP_DIR/qrcode.js"
cat > "$CONF_DIR/config.json" <<EOF
{
  "port": $PORT,
  "upstream": { "host": "127.0.0.1", "port": $UPSTREAM_PORT },
  "password": "$TWOFA_PW",
  "cookieSecret": "$COOKIE",
  "totpSecret": "$TOTP",
  "cookieMaxAge": 86400,
  "piUser": "$PI_USER",
  "piPassword": "$PI_PW",
  "proxyToken": "$TOKEN",
  "fileBrowser": null,
  "firstLoginUser": "pi",
  "setupComplete": false
}
EOF
chmod 600 "$CONF_DIR/config.json"

echo "==> 安装 systemd 服务"
cat > /etc/systemd/system/piweb2fa.service <<'EOF'
[Unit]
Description=PiWeb 2FA Proxy
After=network.target

[Service]
ExecStart=/usr/bin/node /opt/piweb2fa/server.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable piweb2fa >/dev/null 2>&1
systemctl restart piweb2fa
sleep 2
systemctl is-active piweb2fa

echo ""
echo "=============================================="
echo "  安装完成！当前为「首次登录引导模式」"
echo ""
echo "  1) 打开 http://你的地址:$PORT  → 登录页输入"
echo "       用户名: pi     密码: $TWOFA_PW（引导与正常登录同一个密码）"
echo ""
echo "  2) 登录后页面强制显示身份验证器二维码"
echo "     手机 Google Authenticator / Microsoft Authenticator / 微信身份验证器"
echo "     扫码绑定，看到 6 位动态码后点「我已经绑定」"
echo ""
echo "  3) 之后每次登录：密码（$TWOFA_PW）+ 手机动态码（无需用户名）"
echo "     需要改密码：登录页点「修改密码」"
echo ""
echo "  4) 后续如需改动，编辑 $CONF_DIR/config.json 后："
echo "     systemctl restart piweb2fa"
echo ""
echo "  5) 防 IP 伪造：在 pi-web 环境变量设置"
echo "     PI_WEB_TRUST_PROXY_TOKEN=$TOKEN"
echo "=============================================="
