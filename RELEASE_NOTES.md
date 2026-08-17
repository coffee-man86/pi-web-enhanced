# pi-web-enhanced v1.0.0 发行说明

> 基于 pi-web 0.8.x（上游 [agegr/pi-web](https://github.com/agegr/pi-web)，MIT），Node >= 22.19

---

## 为什么用它（适用场景）

- **多设备同步**：有公网端口，希望工作电脑和手机都能访问同一套 pi + web UI，对话进度统一维护，只维护一套环境
- **文件边界**：在 WSL 中部署，工作区是宿主机某个文件夹的直接映射，确保 AI 只能访问这个工作区
- **访问控制**：域名白名单 + 双因子认证，公网访问有安全兜底

## 🚨 登录方式（务必先读）

**推荐配合 `deployment/2fa-proxy/` 使用：登录只需「密码 + 手机动态码」，无需用户名。**

| 访问方式 | 登录界面 | 需要用户名 |
| --- | --- | --- |
| 经 2FA 代理（推荐） | 密码 + 动态码 | ❌ 不需要 |
| 直连 pi-web | Basic Auth 弹窗 | ✅ 默认 `pi`（或 `PI_WEB_USERNAME`） |

---

## 基础包（可单独安装，不依赖 2FA）

针对 pi-web 的一些使用习惯做的改进：

### ✨ 文件管理增强
- 为文件/文件夹加入**重命名 / 移动 / 删除**功能（入口：文件悬停后「@提及」旁的 **⋯** 菜单）
- 移动使用 **GUI 目录选择器**（无需手动输入路径）
- 删除带确认框，防止误操作
- 后端 API 自带安全防护：符号链接逃逸拦截、移动进自身子目录的友好报错

### ✨ 目录习惯优化
- 工作区目录默认选择 `/workspace`（无需每次手动选）
- 文件目录树和目录选择窗口都增加**「新建文件夹」**按钮（选择器内新建后自动进入）

### 🔒 域名白名单（公网安全基础）
- 只允许通过配置的域名访问（`PI_WEB_ALLOWED_HOSTS`），阻止 DNS 重绑定攻击
- 非白名单主机名一律 403

### 📦 其它
- 上传限制：单文件 1GB、单次 2GB（原版 25MB/100MB）
- 登录审计日志（journald）
- 大文件上传 multipart 解析修复、Edge 登录循环修复

## 配置示例

```bash
PORT=25133
PI_WEB_PASSWORD=你的密码
PI_WEB_ALLOWED_HOSTS=your.domain.com   # 域名白名单
PI_WEB_USERNAME=admin                  # 可选：改用户名
PI_WEB_DEFAULT_CWD=/workspace          # 可选：默认工作目录
PI_WEB_TRUST_PROXY_TOKEN=<随机串>      # 前置 2FA 代理时设置
```

## 安装

```bash
# 方式一：应用补丁（透明可审计）
git clone https://github.com/agegr/pi-web && cd pi-web
git apply pi-web-enhanced.patch
npm install && npm run build && npm start

# 方式二：使用本分支源码
git clone <本仓库> && cd pi-web-enhanced
npm install && npm run build && npm start
```

## 与上游同步

改动集中在 9 个文件（+433/-18），`git rebase` 冲突极小；升级时保留 `next.config.ts` 的 `proxyClientMaxBodySize`。

## 鸣谢

基于 [agegr/pi-web](https://github.com/agegr/pi-web) 二次开发，保留上游 MIT 版权。
