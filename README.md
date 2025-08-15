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

---

## 安装指南

### Termux 环境

**初始安装**
```bash
curl -o termux-install.sh "https://raw.githubusercontent.com/su-kaka/gcli2api/refs/heads/master/termux-install.sh" && chmod +x termux-install.sh && ./termux-install.sh
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

**重启服务**
双击执行 `start.bat`

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

### Docker 环境

**Docker 运行命令**
```bash
docker run -d --name gcli2api --network host -e PASSWORD=pwd -v $(pwd)/data/creds:/app/geminicli/creds ghcr.io/cetaceang/gcli2api:latest
```

**Docker Compose 运行命令**
1. 将以下内容保存为 `docker-compose.yml` 文件：
    ```yaml
    version: '3.8'

    services:
      gcli2api:
        image: ghcr.io/cetaceang/gcli2api:latest
        container_name: gcli2api
        restart: unless-stopped
        network_mode: host
        environment:
          - PASSWORD=pwd
        volumes:
          - ./data/creds:/app/geminicli/creds
        healthcheck:
          test: ["CMD-SHELL", "python -c \"import sys, urllib.request, os; req = urllib.request.Request('http://localhost:7861/v1/models', headers={'Authorization': 'Bearer ' + os.environ.get('PASSWORD', 'pwd')}); sys.exit(0 if urllib.request.urlopen(req, timeout=5).getcode() == 200 else 1)\""]
          interval: 30s
          timeout: 10s
          retries: 3
          start_period: 40s
    ```
2. 启动服务：
    ```bash
    docker-compose up -d
    ```

---

---

## ⚠️ 注意事项

- 当前 OAuth 验证流程**仅支持本地主机（localhost）访问**，即须通过 `http://127.0.0.1:7861/auth` 完成认证。
- **如需在云服务器或其他远程环境部署，请先在本地运行服务并完成 OAuth 验证，获得生成的 json 凭证文件（位于 `./geminicli/creds` 目录）后，再在auth面板将该文件上传即可。**

---

## 配置说明

1. 访问 `http://127.0.0.1:7861/auth`
2. 完成 OAuth 认证流程（默认密码：`pwd`）
3. 配置 OpenAI 兼容客户端：
   - **端点地址**：`http://127.0.0.1:7861/v1`
   - **API 密钥**：`pwd`（默认值）

---

## 故障排除

**400 错误解决方案**
```bash
npx https://github.com/google-gemini/gemini-cli
```
1. 选择选项 1
2. 按回车确认
3. 完成浏览器中的 Google 账户认证
4. 系统将自动完成授权

---