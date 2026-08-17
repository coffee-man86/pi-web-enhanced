# pi-web 部署层 v1.0.0 发行说明（2FA 代理 / WSL 保活 / WSL 加固）

**发布日期**：2026-08-17
**适用场景**：公网部署 pi-web（或任意 Web 服务）时的安全增强与 WSL2 运维模板
**依赖**：Node.js >= 18（2FA 代理，零第三方依赖）；Linux / WSL2（按组件）

> 本包为**部署模板**（脱敏），不含任何个人配置；安装时自动生成随机密钥。

---

## 组件一：2fa-proxy（双因子登录代理）

### 🚨 登录无需用户名
登录页只有「密码 + 动态码」，代理自动注入 pi-web 的 Basic Auth 凭据——用户完全感知不到用户名。

### 解决的问题
Basic Auth 只有密码：无法防暴力破解、无失败锁定、无登录记录。

### 功能
- **双因子登录**：密码 + TOTP 动态码（标准 RFC 6238，兼容 Google Authenticator / Microsoft Authenticator / 微信身份验证器）
- **首次登录引导**：全新安装自动进入引导模式——首次用 `pi` + 默认密码登录 → 强制绑定页（本机专属二维码，每次安装随机生成不共享）→ 点「我已经绑定」→ 切换为正常 2FA
- **统一密码模型**：引导登录与正常登录同一个密码，绑定后不变；登录页可随时「修改密码」（未绑定阶段无需动态码，绑定后需当前密码 + 动态码）
- **账户页 + 退出登录**：pi-web 页面自动注入「帐号」按钮（放在侧边栏「系统」项后），点进账户页可修改密码/退出登录
- **登录限速**：同 IP 60 秒内 5 次失败 → 锁定 60 秒
- **登录审计日志**：`[2fa] OK/FAIL ip=...`（journald）
- **24h 签名 cookie**：HttpOnly + SameSite=Lax，可退出清除
- **透明转发**：向 pi-web 注入 Basic Auth，用户免二次登录
- **可信代理密钥头**：`X-Piweb-Proxy-Token`，配合 pi-web 的 `PI_WEB_TRUST_PROXY_TOKEN` 防 IP 伪造
- **上游兼容修复**：转发时重写 `Origin`（防 403 Untrusted API）、剥离 `accept-encoding`（防 gzip 字节损坏导致页面刷不出来）、上游 401 时给出配置指引页
- **可选 /fb 路由**：配置 `fileBrowser` 字段后，`/fb` 前缀转发到文件管理器（如 FileBrowser）

### 安装（3 步）
```bash
sudo bash setup.sh 42204 25133   # 代理端口 上游端口
# 1) 编辑 /etc/piweb2fa/config.json 设置密码
# 2) 手机身份验证器绑定脚本输出的密钥
# 3) pi-web 环境设 PI_WEB_TRUST_PROXY_TOKEN=<脚本输出的令牌>
```

### 架构
```
公网 → 2FA 代理(:42204) → 登录(密码+动态码) → 24h cookie → 透明代理
                              ├→ pi-web(:25133)
                              └→ 可选 /fb 文件管理器
```

### ⚠️ 安全要求
- **必须前置 HTTPS**（Caddy/nginx + 证书），否则密码与 cookie 明文传输
- 禁止把代理直接暴露公网而不加 TLS
- 24h cookie 无 IP 绑定；要求更高可自行扩展

---

## 组件二：keepalive（WSL VM 保活）

### 解决的问题
WSL2（2.3+）在最后一个客户端断开约 60 秒后回收 VM（`vmIdleTimeout`），即使 systemd 常驻也会被关停，导致 pi-web 等服务无人连接即停止。

### 原理
保持一个 `wsl.exe` 会话常驻（VM 内脚本永不退出），VM 意外停止后自动重连拉起。

### 使用
1. 发行版内创建 `/usr/local/bin/piweb-keepalive.sh`（模板已附）
2. 复制 `keepalive.cmd.template`，替换 `DISTRO_NAME`
3. 开机自启：`PiWeb-KeepAlive.vbs.template` 放入启动文件夹

### 说明
- 一个发行版的保活即可维持整个共享 VM（WSL2 所有发行版共用一个 VM）
- 关闭保活：任务管理器结束对应 cmd.exe

---

## 组件三：wsl-hardening（WSL 文件系统加固）

### 解决的问题
WSL2 默认把宿主机全部磁盘（C/D/E/F）自动挂载到 `/mnt/*`，并默认开启 interop（Linux 内可执行 `cmd.exe` 读宿主机 C 盘）——每个发行版内的进程都能访问宿主机全部文件。

### 使用
1. 按 `wsl.conf.example` 替换发行版内 `/etc/wsl.conf`（改用户名）
2. 按 `fstab.example` 写入 `/etc/fstab`（只挂载工作目录）
3. `wsl --shutdown` 重启生效

### 效果
- `/mnt/c` `/mnt/d` 等全部消失，仅保留 fstab 显式挂载的目录
- `cmd.exe` / `powershell` 无法执行
- 工作目录正常访问（如 `/workspace`）

### 说明
- 每发行版独立配置
- 属于进程边界加固，不能替代虚拟机/容器隔离

---

## 组合推荐（公网 + WSL2）

```
公网 → [HTTPS 反代] → 2FA 代理(:42204) → pi-web(:25133)
                      └→ 可选 /fb 文件管理器
WSL2 内：automount/interop 已关 + 保活脚本防 VM 回收
```

## 免责声明

本包为通用部署模板，使用者需根据自身环境调整端口、路径与安全策略；作者不对部署后的安全性作任何保证。
