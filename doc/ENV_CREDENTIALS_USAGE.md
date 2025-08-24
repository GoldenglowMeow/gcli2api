# 环境变量凭证导入功能使用指南

本功能允许你通过环境变量批量导入Google Cloud认证凭证，特别适合Docker部署和CI/CD自动化场景。

## 基本用法

### 1. 设置环境变量

支持两种命名格式：

**方式一：编号格式**
```bash
export GCLI_CREDS_1='{"client_id":"your-client-id","client_secret":"your-secret","refresh_token":"your-token","token_uri":"https://oauth2.googleapis.com/token","project_id":"your-project"}'
export GCLI_CREDS_2='{"client_id":"...","project_id":"project2",...}'
```

**方式二：项目名格式**
```bash
export GCLI_CREDS_myproject='{"client_id":"your-client-id","client_secret":"your-secret","refresh_token":"your-token","token_uri":"https://oauth2.googleapis.com/token","project_id":"myproject"}'
export GCLI_CREDS_testproject='{"client_id":"...","project_id":"testproject",...}'
```

### 2. 启用自动加载（可选）

```bash
export AUTO_LOAD_ENV_CREDS=true
```

启用后，程序启动时会自动导入所有环境变量中的凭证文件。

### 3. 手动触发导入

如果没有启用自动加载，可以通过Web控制面板手动导入：

1. 访问控制面板：`http://localhost:7861/auth`
2. 登录后点击 "环境变量" 标签页
3. 点击 "从环境变量导入" 按钮

## Docker 部署示例

### Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

# 设置自动加载
ENV AUTO_LOAD_ENV_CREDS=true

EXPOSE 7861
CMD ["python", "web.py"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  gcli2api:
    build: .
    ports:
      - "7861:7861"
    environment:
      - AUTO_LOAD_ENV_CREDS=true
      - GCLI_CREDS_1={"client_id":"your-client-id","client_secret":"your-secret","refresh_token":"your-token","token_uri":"https://oauth2.googleapis.com/token","project_id":"your-project"}
      - GCLI_CREDS_2={"client_id":"...","project_id":"project2"}
      - PASSWORD=your_panel_password
```

### 直接运行
```bash
docker run -d \
  -p 7861:7861 \
  -e AUTO_LOAD_ENV_CREDS=true \
  -e 'GCLI_CREDS_1={"client_id":"your-client-id","client_secret":"your-secret","refresh_token":"your-token","token_uri":"https://oauth2.googleapis.com/token","project_id":"your-project"}' \
  -e PASSWORD=your_password \
  your-image-name
```

## API 端点

### 查看环境变量状态
```bash
GET /auth/env-creds-status
Authorization: Bearer your-token
```

### 手动导入环境变量凭证
```bash
POST /auth/load-env-creds
Authorization: Bearer your-token
```

### 清除环境变量凭证文件
```bash
DELETE /auth/env-creds
Authorization: Bearer your-token
```

## 注意事项

1. **安全性**：环境变量中的凭证内容会被日志系统显示为 `***已设置***`，不会泄露实际内容
2. **文件命名**：从环境变量导入的文件会以 `env-` 前缀命名，便于管理
3. **去重**：相同时间戳的文件会自动添加序号避免冲突
4. **验证**：导入前会验证JSON格式和必要字段
5. **清理**：清除功能只会删除以 `env-` 开头的文件，不影响其他凭证

## 常见问题

**Q: 环境变量的凭证从哪里获得？**
A: 可以先通过OAuth认证获得凭证文件，然后将文件内容设置为环境变量。

**Q: 支持多少个凭证？**
A: 理论上无限制，只要环境变量名以 `GCLI_CREDS_` 开头即可。

**Q: 如何更新凭证？**
A: 更新环境变量后重新导入，旧文件可以通过控制面板删除。

**Q: Docker容器重启后凭证会丢失吗？**
A: 如果启用了自动加载，重启后会重新导入。建议使用数据卷持久化 `creds` 目录。