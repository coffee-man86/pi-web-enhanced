# pi-web-enhanced

[pi-web](https://github.com/agegr/pi-web) 的增强分支：在保持原版功能的基础上，增加**文件管理操作**与**可配置化改进**。

## 快速开始：登录方式（重要）

**推荐：部署 2FA 代理（见 `deployment/2fa-proxy/`），登录只需「密码 + 动态码」，无需用户名。**

| 访问方式 | 登录界面 | 需要用户名吗 |
| --- | --- | --- |
| 经 2FA 代理（推荐） | 密码 + 手机动态码 | ❌ 不需要（代理自动注入） |
| 直连 pi-web 端口 | Basic Auth 弹窗 | ✅ **默认 `pi`**（或你配置的 `PI_WEB_USERNAME`） |

直连时：
- **用户名**：默认 `pi`（原版一致）；想改则设置 `PI_WEB_USERNAME`
- **密码**：`PI_WEB_PASSWORD`

## 特性

### 文件/文件夹操作（直接集成在文件浏览器中）
- **新建文件夹**：文件列表顶部按钮；目录选择器内也可直接新建
- **重命名**：悬停文件 → "⋯" → 重命名
- **移动**：悬停 → "⋯" → 移动 → GUI 目录选择器（无需手输路径）
- **删除**：悬停 → "⋯" → 删除（带确认）
- 后端 API：`DELETE`（删除）、`PATCH`（rename/move）、`POST ?type=mkdir`（新建文件夹）
- 安全性：所有操作沿用原版的 Host/CSRF 校验 + 允许根目录检查，并补充了
  - 符号链接逃逸防护（目标父目录 realpath 校验，防止写入被重定向到根目录外）
  - 移动进自身子目录的友好错误
- 上传限制：单文件 1GB、单次 2GB（原版 25MB/100MB）

### 可配置化（通过环境变量，无需改代码）
| 变量 | 作用 | 默认 |
| --- | --- | --- |
| `PI_WEB_USERNAME` | Basic Auth 用户名（原版写死 `pi`） | `pi` |
| `PI_WEB_DEFAULT_CWD` | 默认工作目录（新建会话/目录选择器起始位置） | `~/pi-cwd-<日期>` |
| `PI_WEB_TRUST_PROXY_TOKEN` | 可信反代密钥：仅当请求携带匹配的密钥头时才信任 `X-Forwarded-For`（防伪造 IP 污染日志） | 未设置 |

### 其他
- 登录审计日志：`[piweb-auth] OK/FAIL user=... ip=...`（写 journald / stdout）
- `WWW-Authenticate` 去掉 `charset="UTF-8"`（Edge 兼容）
- `proxyClientMaxBodySize=5GB`（修复大文件上传的 multipart 解析失败）

## 安装

### 方式一：直接应用补丁（推荐）
```bash
git clone https://github.com/agegr/pi-web
cd pi-web
git apply /path/to/pi-web-enhanced.patch
npm install
npm run build
npm start   # 或 npx next start -H 0.0.0.0 -p 30141
```

### 方式二：使用本分支源码
```bash
git clone <本仓库地址>
cd pi-web-enhanced
npm install
npm run build
npm start
```

## 配置示例

```bash
# /etc/pi-web/env 或 systemd EnvironmentFile / 命令行环境
PORT=30141
PI_WEB_PASSWORD=你的密码
PI_WEB_ALLOWED_HOSTS=your.domain.com
PI_WEB_USERNAME=admin
PI_WEB_DEFAULT_CWD=/workspace
# 如果前置了可信反代（如 2FA 代理），设置共享密钥：
PI_WEB_TRUST_PROXY_TOKEN=<随机字符串>
```

## 安全说明

- 本分支不包含任何个人配置/凭据，所有个性化内容通过环境变量注入
- 建议公网部署时前置 HTTPS 反代 + 强密码 + 登录限速（参考原版安全文档）
- 移动/删除/新建文件夹 API 均限定在允许根目录内

## 与上游同步

本分支基于 pi-web 0.8.x。上游更新后，可用 `git fetch upstream && git rebase` 合并；改动集中在上述 9 个文件，冲突通常很小。

## License

MIT（保留上游 [agegr/pi-web](https://github.com/agegr/pi-web) 版权声明）
