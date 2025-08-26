# GeminiCLI to API

**将 Gemini 转换为 OpenAI 兼容 API 接口**

专业解决方案，旨在解决 Gemini API 服务中频繁的 API 密钥中断和质量下降问题。

---

## ⚠️ 许可证声明

**本项目采用 Cooperative Non-Commercial License (CNC-1.0)**

这是一个反商业化的严格开源协议，详情请查看 [LICENSE](LICENSE) 文件。

### ✅ 允许的用途：
- 个人学习、研究、教育用途
- 非营利组织使用
- 开源项目集成（需遵循相同协议）
- 学术研究和论文发表

### ❌ 禁止的用途：
- 任何形式的商业使用
- 年收入超过100万美元的企业使用
- 风投支持或公开交易的公司使用  
- 提供付费服务或产品
- 商业竞争用途

### 📝 贡献指南：
请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何为项目贡献代码。

---

## 核心功能

**双格式支持**
- 同一端点 `/v1/chat/completions` 自动识别并支持：
  - OpenAI 格式请求（messages 结构）
  - Gemini 原生格式请求（contents 结构）
- 自动格式检测和转换，无需手动切换

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
bash termux-start.sh
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
docker run -d --name gcli2api --network host -e PASSWORD=pwd -e PORT=7861 -v $(pwd)/data/creds:/app/creds ghcr.io/su-kaka/gcli2api:latest
```

**Docker Compose 运行命令**
1. 将以下内容保存为 `docker-compose.yml` 文件：
    ```yaml
    version: '3.8'

    services:
      gcli2api:
        image: ghcr.io/su-kaka/gcli2api:latest
        container_name: gcli2api
        restart: unless-stopped
        network_mode: host
        environment:
          - PASSWORD=pwd
          - PORT=7861
        volumes:
          - ./data/creds:/app/creds
        healthcheck:
          test: ["CMD-SHELL", "python -c \"import sys, urllib.request, os; port = os.environ.get('PORT', '7861'); req = urllib.request.Request(f'http://localhost:{port}/v1/models', headers={'Authorization': 'Bearer ' + os.environ.get('PASSWORD', 'pwd')}); sys.exit(0 if urllib.request.urlopen(req, timeout=5).getcode() == 200 else 1)\""]
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

## ⚠️ 注意事项

- 当前 OAuth 验证流程**仅支持本地主机（localhost）访问**，即须通过 `http://127.0.0.1:7861/auth` 完成认证（默认端口 7861，可通过 PORT 环境变量修改）。
- **如需在云服务器或其他远程环境部署，请先在本地运行服务并完成 OAuth 验证，获得生成的 json 凭证文件（位于 `./geminicli/creds` 目录）后，再在auth面板将该文件上传即可。**
- **请严格遵守使用限制，仅用于个人学习和非商业用途**

---

## 配置说明

1. 访问 `http://127.0.0.1:7861/auth` （默认端口，可通过 PORT 环境变量修改）
2. 完成 OAuth 认证流程（默认密码：`pwd`，可通过 PASSWORD 环境变量修改）
3. 配置 OpenAI 兼容客户端：
   - **端点地址**：`http://127.0.0.1:7861/v1` （默认端口）
   - **API 密钥**：`pwd`（默认值）

### 环境变量配置
- `PORT`: 服务端口（默认：7861）
- `PASSWORD`: API 密钥（默认：pwd）
- `GOOGLE_CREDENTIALS`: Google OAuth 凭证 JSON（支持原始 JSON 或 base64 编码）
- `GOOGLE_CREDENTIALS_2` 到 `GOOGLE_CREDENTIALS_10`: 额外的凭证（用于多凭证轮换）

#### 凭证环境变量使用示例

**方式 1：直接传入 JSON**
```bash
export GOOGLE_CREDENTIALS='{"type":"authorized_user","client_id":"...","client_secret":"...","refresh_token":"..."}'
```

**方式 2：Base64 编码（推荐，更安全）**
```bash
# 将凭证文件转为 base64
cat credential.json | base64 -w 0 > credential.b64
# 设置环境变量
export GOOGLE_CREDENTIALS=$(cat credential.b64)
```

**方式 3：多凭证轮换**
```bash
export GOOGLE_CREDENTIALS='{"type":"authorized_user",...}'  # 第一个凭证
export GOOGLE_CREDENTIALS_2='{"type":"authorized_user",...}' # 第二个凭证
export GOOGLE_CREDENTIALS_3='{"type":"authorized_user",...}' # 第三个凭证
```

**Docker 使用示例**
```bash
docker run -d --name gcli2api \
  -e PASSWORD=mypassword \
  -e PORT=8080 \
  -e GOOGLE_CREDENTIALS="$(cat credential.json | base64 -w 0)" \
  ghcr.io/cetaceang/gcli2api:latest
```

注意：当设置了凭证环境变量时，系统将优先使用环境变量中的凭证，忽略 `creds` 目录中的文件。

### API 格式支持

该服务现在支持两种请求格式，会自动检测并处理：

**OpenAI 格式示例：**
```json
{
  "model": "gemini-2.5-pro",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "user", "content": "Hello"}
  ],
  "temperature": 0.7
}
```

**Gemini 原生格式示例：**
```json
{
  "model": "gemini-2.5-pro",
  "contents": [
    {"role": "user", "parts": [{"text": "Hello"}]}
  ],
  "systemInstruction": {"parts": [{"text": "You are a helpful assistant"}]},
  "generationConfig": {
    "temperature": 0.7
  }
}
```

两种格式都会返回 OpenAI 兼容的响应格式。

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

## 许可证与免责声明

本项目仅供学习和研究用途。使用本项目表示您同意：
- 不将本项目用于任何商业用途
- 承担使用本项目的所有风险和责任
- 遵守相关的服务条款和法律法规

项目作者对因使用本项目而产生的任何直接或间接损失不承担责任。