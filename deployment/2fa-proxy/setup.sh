#!/bin/bash
# 一键安装 PiWeb 2FA 代理（在运行 pi-web 的 Linux 主机上执行，需要 root）
# 用法：sudo bash setup.sh [端口] [上游端口]
# 示例：sudo bash setup.sh 42204 25133
#
# 首次登录引导：安装后 setupComplete=false，用 用户名 pi / 密码 password 登录，
# 页面会强制显示身份验证器二维码，绑定后点「我已经绑定」即切换到正常 2FA 流程。
set -e

PORT="${1:-42204}"
UPSTREAM_PORT="${2:-25133}"
CONF_DIR=/etc/piweb2fa
APP_DIR=/opt/piweb2fa

echo "==> 生成密钥（每次安装随机，不共享）..."
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
  "password": "安装后请在 /login 登录，再在 /setup 完成绑定，并尽快修改本文件里的 password",
  "cookieSecret": "$COOKIE",
  "totpSecret": "$TOTP",
  "cookieMaxAge": 86400,
  "piUser": "pi",
  "piPassword": "请改成 pi-web 的密码",
  "proxyToken": "$TOKEN",
  "fileBrowser": null,
  "firstLoginUser": "pi",
  "firstLoginPassword": "password",
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
echo "       用户名: pi     密码: password"
echo ""
echo "  2) 登录后页面强制显示身份验证器二维码"
echo "     手机 Google Authenticator / Microsoft Authenticator / 微信身份验证器"
echo "     扫码绑定，看到 6 位动态码后点「我已经绑定」"
echo ""
echo "  3) 之后每次登录：密码 + 手机动态码（不再需要用户名）"
echo ""
echo "  4) 后续可编辑 $CONF_DIR/config.json："
echo "     - password / piPassword : 换成自己的强密码"
echo "     - firstLoginPassword    : 首次登录密码（可改）"
echo "     - proxyToken            : 同步设置到 pi-web 环境变量 PI_WEB_TRUST_PROXY_TOKEN=$TOKEN"
echo "     修改后 systemctl restart piweb2fa"
echo "=============================================="
