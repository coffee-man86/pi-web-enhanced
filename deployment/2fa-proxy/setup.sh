#!/bin/bash
# 一键安装 PiWeb 2FA 代理（在运行 pi-web 的 Linux 主机上执行，需要 root）
# 用法：sudo bash setup.sh [端口] [上游端口]
# 示例：sudo bash setup.sh 22052 30042
set -e

PORT="${1:-22052}"
UPSTREAM_PORT="${2:-30042}"
CONF_DIR=/etc/piweb2fa
APP_DIR=/opt/piweb2fa

echo "==> 生成密钥..."
TOTP=$(head -c 20 /dev/urandom | base32 | tr -d '=' | tr -d '\n')
COOKIE=$(head -c 32 /dev/urandom | xxd -p -c 64)
TOKEN=$(head -c 24 /dev/urandom | xxd -p -c 64)

echo "==> 写入配置模板 $CONF_DIR/config.json（请务必修改 password/piPassword/piUser）"
mkdir -p "$CONF_DIR" "$APP_DIR"
cp server.js "$APP_DIR/server.js"
cat > "$CONF_DIR/config.json" <<EOF
{
  "port": $PORT,
  "upstream": { "host": "127.0.0.1", "port": $UPSTREAM_PORT },
  "password": "请改成强密码",
  "cookieSecret": "$COOKIE",
  "totpSecret": "$TOTP",
  "cookieMaxAge": 86400,
  "piUser": "pi",
  "piPassword": "请改成 pi-web 的密码",
  "proxyToken": "$TOKEN",
  "fileBrowser": null
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
echo "  安装完成！"
echo ""
echo "  1) 编辑 $CONF_DIR/config.json："
echo "     - password   : 登录密码（强密码）"
echo "     - piUser/piPassword : pi-web 的 Basic Auth 凭据（用于透明转发）"
echo ""
echo "  2) 手机身份验证器绑定（Google Authenticator / Microsoft Authenticator / 微信身份验证器）："
echo "     手动输入密钥: $TOTP"
echo "     otpauth URI : otpauth://totp/PiWeb?secret=$TOTP&issuer=PiWeb"
echo ""
echo "  3) 在 pi-web 侧设置可信代理密钥（防 X-Forwarded-For 伪造）："
echo "     PI_WEB_TRUST_PROXY_TOKEN=$TOKEN"
echo ""
echo "  4) 修改配置后：systemctl restart piweb2fa"
echo "=============================================="
