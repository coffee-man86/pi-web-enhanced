# 部署层：2FA / 保活 / WSL 加固（脱敏模板）

本目录包含三个**可选**的部署组件，与 pi-web 增强版配合使用。所有模板均不含个人凭据，
安装时会现场生成随机密钥。按需选择使用：

```
deployment/
├── 2fa-proxy/      # 双因子登录代理（推荐公网部署时使用）
├── keepalive/      # WSL VM 保活（仅 WSL2 场景需要）
└── wsl-hardening/  # WSL 文件系统加固（仅 WSL2 场景需要）
```

---

## 一、2fa-proxy：双因子登录代理

### 解决的问题
pi-web 的 Basic Auth 只有密码，公网暴露时无法防暴力破解、也没有登录失败锁定。
本代理在 pi-web 前增加「密码 + TOTP 动态码」，并内置：
- 登录限速（同 IP 60 秒 5 次失败 → 锁 60 秒）
- 登录审计日志（`[2fa] OK/FAIL ip=...`，journald）
- 可信代理密钥头（配合 pi-web 的 `PI_WEB_TRUST_PROXY_TOKEN`，防 X-Forwarded-For 伪造）

### 架构
```
公网用户 → 2FA 代理(:22052) → 登录页(密码+动态码) → 24h cookie → 透明代理
                                    ├→ pi-web(:30042)（注入 Basic Auth，用户免二次登录）
                                    └→（可选）文件管理器 /fb（如 FileBrowser）
```

### 安装（在运行 pi-web 的 Linux 主机上）
```bash
# 需要 Node.js >= 18（无任何第三方依赖）
sudo bash setup.sh 22052 30042
```
脚本会生成随机 TOTP 密钥 / cookie 密钥 / 代理令牌，写入 `/etc/piweb2fa/config.json`。

### 配置
编辑 `/etc/piweb2fa/config.json`：
| 字段 | 说明 |
| --- | --- |
| `password` | 登录密码（强密码） |
| `piUser` / `piPassword` | pi-web 的 Basic Auth 凭据（透明转发用） |
| `totpSecret` | 身份验证器绑定密钥（脚本已生成，也可自定） |
| `fileBrowser` | 可选；配置后 `/fb` 前缀转发到文件管理器，其余到 pi-web |

### 绑定身份验证器
手机装 Google Authenticator / Microsoft Authenticator / 微信"身份验证器"，
手动输入脚本输出的密钥，或扫 otpauth 二维码。

### 与 pi-web 联动（防 IP 伪造）
在 pi-web 环境设置：
```
PI_WEB_TRUST_PROXY_TOKEN=<setup.sh 输出的令牌>
```
这样 pi-web 的登录日志只信任带正确令牌的 `X-Forwarded-For`，直连访问一律记 `unknown`。

### 安全提醒
- **必须前置 HTTPS**（Caddy/nginx + 证书），否则密码和 cookie 明文传输
- 不要把这个代理直接暴露公网而不加 HTTPS
- 24h cookie 无 IP 绑定，可接受；要求更高可自行加绑定

---

## 二、keepalive：WSL VM 保活

### 解决的问题
WSL2（2.3+）在**最后一个客户端断开后约 60 秒回收 VM**（`vmIdleTimeout` 默认值），
即使 systemd 常驻也会被回收。这会导致 pi-web 等服务在无人连接时被关停。

### 原理
只要有一个 `wsl.exe` 会话持续挂着，VM 就不会被回收。本脚本保持一个
永不退出的会话，并在 VM 意外停止后自动重连拉起。

### 安装
1. 在 WSL 发行版内创建常驻脚本：
```bash
sudo tee /usr/local/bin/piweb-keepalive.sh <<'EOF'
#!/bin/bash
while true; do sleep 60; done
EOF
sudo chmod +x /usr/local/bin/piweb-keepalive.sh
```
2. 把 `keepalive.cmd.template` 复制到 Windows，把 `DISTRO_NAME` 改成你的发行版名
   （`wsl -l -v` 可查看），直接双击运行验证。
3. 开机自启：把 `PiWeb-KeepAlive.vbs.template` 复制到启动文件夹
   （Win+R → `shell:startup`），并修改其中的 `.cmd` 路径。

### 说明
- 一个发行版的保活即可维持**整个共享 VM**（所有发行版在同一 VM 内）
- 多个发行版各需一条时，复制多份 .cmd 即可
- 关闭保活 = `任务管理器` 结束对应的 cmd.exe

---

## 三、wsl-hardening：WSL 文件系统加固

### 解决的问题
WSL2 默认把宿主机**所有磁盘**（C/D/E/F）自动挂载到 `/mnt/*`，且默认开启 interop
（Linux 里可直接执行 `cmd.exe` 读宿主机 C 盘）。这意味着每个发行版内的进程
（包括 AI 智能体）都能访问宿主机全部文件——没有文件系统隔离。

### 安装
1. 备份并替换发行版内的 `/etc/wsl.conf`（用 `wsl.conf.example`，改用户名）
2. 写入 `/etc/fstab`（用 `fstab.example`，改成你的工作目录）
3. 重启生效：`wsl --shutdown`（Windows 上执行），再重新进入发行版

### 效果
- `/mnt/c`、`/mnt/d` 等全部消失，只保留 fstab 里显式挂载的目录
- `cmd.exe` / `powershell` 无法再执行
- 工作目录仍可通过挂载点访问（如 `/workspace`）

### 注意
- 修改是**每发行版独立**的（每个发行版各自的 `/etc/wsl.conf`）
- 若之后需要智能体访问其他宿主目录，在 fstab 里加一行即可
- 这是"进程边界"加固：WSL 本身仍以宿主用户权限运行，不能替代虚拟机/容器隔离

---

## 组合建议（公网 + WSL2 场景）

```
公网 → [HTTPS 反代] → 2FA 代理 → pi-web（文件操作/上传/审计日志）
                          └→ 可选 /fb 文件管理器
WSL2 内：automount/interop 已关（只暴露工作目录）+ 保活脚本防 VM 回收
```
