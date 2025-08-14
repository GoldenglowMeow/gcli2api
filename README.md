# GeminiCLI to API

将 Google Gemini CLI 封装为兼容 OpenAI API 的反向代理服务，提供 `/v1/chat/completions` 与 `/v1/models`。在多凭据场景下，支持轮询调度与并发控制，保障吞吐与稳定性。

## 主要特性

- OpenAI 兼容端点：`/v1/chat/completions`、`/v1/models`
- 简单鉴权：Bearer Token（环境变量 PASSWORD，默认 `pwd`）
- 可选 OAuth：内置网页引导完成 Google OAuth 并保存凭据
- Web 页面：提供 OAuth 引导页
- 反代增强：多凭据轮询、后端并发

## 轮询

- 轮询
  - 支持配置多个oath文件
  - 默认使用轮询（Round-Robin）分发请求，实现负载均衡
  - 支持并发

## 安装与运行

- 环境
  - Python 3.13+
  - 可选：Google Cloud Project 与 OAuth 客户端配置（JSON）

- 安装
  ```bat
  git clone <repository-url>
  cd gcli2api
  pip install -r requirements.txt
  ```

- 设置密码（示例）
  - Windows CMD:
    ```bat
    set PASSWORD=your_custom_password
    ```
  - PowerShell:
    ```powershell
    $env:PASSWORD = "your_custom_password"
    ```

- 启动
  ```bat
  python web.py
  ```

- 访问
  - API 基址: http://127.0.0.1:7861/v1
  - OAuth 页面: http://127.0.0.1:7861/auth

## API 示例

- 列出模型
  ```bat
  curl -H "Authorization: Bearer pwd" ^
    http://127.0.0.1:7861/v1/models
  ```

- 非流式对话
  ```bat
  curl -H "Authorization: Bearer pwd" ^
    -H "Content-Type: application/json" ^
    -d "{
      \"model\": \"gemini-2.5-pro\",
      \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}],
      \"max_tokens\": 1000
    }" ^
    http://127.0.0.1:7861/v1/chat/completions
  ```

- 流式对话
  ```bat
  curl -H "Authorization: Bearer pwd" ^
    -H "Content-Type: application/json" ^
    -d "{
      \"model\": \"gemini-2.5-pro\",
      \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}],
      \"stream\": true
    }" ^
    http://127.0.0.1:7861/v1/chat/completions
  ```

## 可选 OAuth 流程

1. 打开 http://127.0.0.1:7861/auth
2. 输入站点密码（默认 `pwd`，建议改为强密码）
3. 填写 Google Cloud Project 信息
4. 按页面提示完成 Google 账户授权
5. 自动保存凭据 JSON 到 `geminicli/creds/`（程序会读取该目录）

## 目录结构

```
gcli2api/
├─ web.py                      # FastAPI 启动入口
├─ models.py                   # Pydantic 模型
├─ log.py                      # 日志
├─ geminicli/                  # Gemini CLI 相关
│  ├─ client.py                # 核心客户端
│  ├─ auth_api.py              # OAuth API
│  ├─ auth_web.html            # OAuth 网页
│  ├─ config.py                # 配置
│  ├─ credential_manager.py    # 凭据管理
│  ├─ google_api_client.py     # Google API 客户端
│  ├─ models.py                # 子模块模型
│  ├─ openai_transformers.py   # OpenAI 兼容转换
│  ├─ utils.py                 # 工具函数
│  ├─ web_routes.py            # Web 路由
│  └─ creds/                   # OAuth 凭据存放
└─ requirements.txt            # 依赖列表
```

## 安全建议

- 在生产环境务必设置强密码（PASSWORD）
- 建议使用 HTTPS，妥善保管 OAuth 凭据
- 为后端设置合理并发上限与队列长度，避免过载

## 许可证

以仓库 LICENSE 为准
