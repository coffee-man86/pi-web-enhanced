# pi-web-enhanced v1.0.0 发行说明

**发布日期**：2026-08-17
**基础版本**：pi-web 0.8.x（上游 [agegr/pi-web](https://github.com/agegr/pi-web)，MIT）
**兼容性**：Node.js >= 22.19.0

---

## 主要更新

### ✨ 新增：文件管理操作（直接集成在文件浏览器中）
原版仅支持浏览/上传/下载，本版新增完整的文件管理：

- **新建文件夹**：文件列表顶部"＋ 新建文件夹"按钮
- **重命名**：悬停文件 → "⋯" 菜单 → 重命名
- **移动**：悬停 → "⋯" → 移动 → **GUI 目录选择器**（无需手动输入路径）
- **删除**：悬停 → "⋯" → 删除（带确认框）
- **目录选择器增强**：选择项目/移动时可直接在弹窗内"＋ 新建文件夹"，创建后自动进入

### ✨ 新增：环境变量可配置化（原版需改代码）
| 变量 | 作用 | 默认值 |
| --- | --- | --- |
| `PI_WEB_USERNAME` | Basic Auth 用户名 | `pi` |
| `PI_WEB_DEFAULT_CWD` | 默认工作目录（新建会话/选择器起始） | `~/pi-cwd-<日期>` |
| `PI_WEB_TRUST_PROXY_TOKEN` | 可信反代密钥（防 X-Forwarded-For 伪造） | 未设置 |

### 🔒 安全加固
- **符号链接逃逸防护**：移动/改名时对目标父目录做 realpath 校验，防止符号链接把写入重定向到允许根之外
- **登录审计日志**：`[piweb-auth] OK/FAIL user=... ip=...`（journald/stdout）
- **IP 伪造防护**：仅当请求携带与 `PI_WEB_TRUST_PROXY_TOKEN` 匹配的密钥头时信任 X-Forwarded-For
- **移动进自身子目录**：返回明确错误而非原始 EINVAL

### 🐛 问题修复
- **大文件上传 multipart 解析失败**（"Failed to parse body as FormData"）：通过 `proxyClientMaxBodySize=5GB` 修复（Next.js 16.3+ 默认仅缓冲 10MB 请求体）
- **允许根目录重启丢失**：`PI_WEB_DEFAULT_CWD` 直接纳入允许根计算，重启后无需浏览器加载即可操作文件
- **Edge 登录循环**：`WWW-Authenticate` 移除 `charset="UTF-8"` 参数

### 📦 上传能力
- 单文件上限：25MB → **1GB**
- 单次总量：100MB → **2GB**

---

## 安装方式

**方式一：应用补丁（推荐，透明可审计）**
```bash
git clone https://github.com/agegr/pi-web
cd pi-web
git apply pi-web-enhanced.patch
npm install
npm run build
npm start
```

**方式二：使用本分支源码**
```bash
git clone <本仓库地址>
cd pi-web-enhanced
npm install
npm run build
npm start
```

## 配置示例

```bash
PORT=25133
PI_WEB_PASSWORD=你的密码
PI_WEB_ALLOWED_HOSTS=your.domain.com
PI_WEB_USERNAME=admin
PI_WEB_DEFAULT_CWD=/workspace
PI_WEB_TRUST_PROXY_TOKEN=<随机字符串>   # 前置可信反代时设置
```

## 兼容性与升级

- 无破坏性变更：所有新功能均为增量，环境变量全部可选（不设置则行为与原版一致）
- 与上游同步：改动集中在 9 个文件（+433/-18 行），`git rebase` 冲突极小
- 升级 pi-web 时请保留 `next.config.ts` 中的 `proxyClientMaxBodySize` 设置，否则大文件上传会回归

## 鸣谢

基于 [agegr/pi-web](https://github.com/agegr/pi-web) 二次开发，保留上游 MIT 版权。
