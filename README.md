# GeminiCLI to API

**将 Gemini 转换为 OpenAI 兼容 API 接口**

专业解决方案，旨在解决 Gemini API 服务中频繁的 API 密钥中断和质量下降问题。

## 核心功能

**OpenAI 兼容性**
- 标准 `/v1/chat/completions` 和 `/v1/models` 端点
- 完全符合 OpenAI API 规范

**流式支持**
- 实时流式响应
- 伪流式回退机制

**智能凭证管理**
- 多个 Google OAuth 凭证自动轮换
- 通过冗余认证增强稳定性
- 负载均衡与并发请求支持

**Web 认证界面**
- 简化的 OAuth 认证工作流
- 简易的凭证配置流程

## 支持的模型

所有模型均具备 1M 上下文窗口容量。每个凭证文件提供 1500 次请求额度。

- `gemini-2.5-pro`
- `gemini-2.5-pro-preview-06-05`
- `gemini-2.5-pro-preview-05-06`

*注：所有模型均支持伪流式变体*

## 安装指南

### Termux 环境

**初始安装**
```bash
curl -o install-termux.sh "https://raw.githubusercontent.com/su-kaka/gcli2api/refs/heads/master/install-termux.sh" && chmod +x install-termux.sh && ./install-termux.sh
```

**重启服务**
```bash
cd gcli2api
bash start.sh
```

### Windows 环境

**初始安装**
```powershell
iex (iwr "https://raw.githubusercontent.com/su-kaka/gcli2api/refs/heads/master/install.ps1" -UseBasicParsing).Content
```

### Linux 环境

**初始安装**
```bash
curl -o install.sh "https://raw.githubusercontent.com/su-kaka/gcli2api/refs/heads/master/install.sh" && chmod +x install.sh && ./install.sh
```

**重启服务**
```bash
cd gcli2api
bash start.sh
```

**重启服务**
双击执行 `start.bat`

## 配置说明

1. 访问 `http://127.0.0.1:7861/auth`
2. 完成 OAuth 认证流程（默认密码：`pwd`）
3. 配置 OpenAI 兼容客户端：
   - **端点地址**：`http://127.0.0.1:7861/v1`
   - **API 密钥**：`pwd`（默认值）

## 故障排除

**400 错误解决方案**
```bash
npx https://github.com/google-gemini/gemini-cli
```
1. 选择选项 1
2. 按回车确认
3. 完成浏览器中的 Google 账户认证
4. 系统将自动完成授权