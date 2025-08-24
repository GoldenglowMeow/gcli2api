# Web Routes 测试指南

这个文档描述了如何测试更新后的web_routes.py中的各个端点。

## 测试准备

1. 启动服务：
```bash
python web.py
```

2. 获取认证令牌：
```bash
curl -X POST http://localhost:7861/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password":"your_password"}'
```

保存返回的token用于后续请求。

## 主要端点测试

### 1. 控制面板访问
```bash
# 访问主控制面板
curl http://localhost:7861/panel

# 访问认证页面（应该重定向到控制面板）
curl http://localhost:7861/auth
```

### 2. 环境变量凭证管理

**设置测试环境变量：**
```bash
export GCLI_CREDS_1='{"client_id":"test","client_secret":"test","refresh_token":"test","token_uri":"https://oauth2.googleapis.com/token","project_id":"test-project"}'
export AUTO_LOAD_ENV_CREDS=true
```

**测试环境变量状态：**
```bash
curl -X GET http://localhost:7861/auth/env-creds-status \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**测试环境变量导入：**
```bash
curl -X POST http://localhost:7861/auth/load-env-creds \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**测试环境变量清除：**
```bash
curl -X DELETE http://localhost:7861/auth/env-creds \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. 配置管理

**获取配置：**
```bash
curl -X GET http://localhost:7861/config/get \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**保存配置：**
```bash
curl -X POST http://localhost:7861/config/save \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "calls_per_rotation": 15,
      "http_timeout": 45,
      "retry_429_enabled": true,
      "retry_429_max_retries": 25,
      "retry_429_interval": 0.2,
      "log_level": "debug",
      "log_file": "app.log",
      "anti_truncation_max_attempts": 5
    }
  }'
```

### 4. 凭证文件管理

**获取凭证状态：**
```bash
curl -X GET http://localhost:7861/creds/status \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**文件操作（启用/禁用/删除）：**
```bash
# 禁用文件
curl -X POST http://localhost:7861/creds/action \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "test-file.json", "action": "disable"}'

# 启用文件
curl -X POST http://localhost:7861/creds/action \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "test-file.json", "action": "enable"}'
```

### 5. OAuth 认证流程

**开始认证：**
```bash
curl -X POST http://localhost:7861/auth/start \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project_id": "optional-project-id"}'
```

**处理回调：**
```bash
curl -X POST http://localhost:7861/auth/callback \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project_id": "optional-project-id"}'
```

### 6. 批量上传

**上传文件：**
```bash
curl -X POST http://localhost:7861/auth/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "files=@test-creds1.json" \
  -F "files=@test-creds2.json"
```

### 7. 日志管理

**WebSocket日志流：**
使用WebSocket客户端连接到：
```
ws://localhost:7861/auth/logs/stream
```

**清空日志文件：**
```bash
curl -X POST http://localhost:7861/auth/logs/clear \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 错误测试

### 1. 测试无效认证
```bash
curl -X GET http://localhost:7861/config/get \
  -H "Authorization: Bearer INVALID_TOKEN"
# 应该返回401错误
```

### 2. 测试无效配置
```bash
curl -X POST http://localhost:7861/config/save \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "calls_per_rotation": -1,
      "log_level": "invalid"
    }
  }'
# 应该返回400验证错误
```

### 3. 测试路径遍历攻击
```bash
curl -X POST http://localhost:7861/creds/action \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "../../../etc/passwd", "action": "delete"}'
# 应该返回400安全错误
```

## 预期结果

- 所有端点应该正确响应
- 环境变量功能应该能够检测、导入和管理凭证
- 配置系统应该能够保存和加载所有配置项
- 安全检查应该阻止路径遍历等攻击
- WebSocket日志应该能够实时显示日志内容
- 错误处理应该返回适当的HTTP状态码和错误信息

## 常见问题

1. **401 未授权**：检查token是否正确获取并传递
2. **404 页面不存在**：确保front/control_panel.html文件存在
3. **500 内部错误**：检查日志文件确定具体错误原因
4. **WebSocket连接失败**：确保没有防火墙阻止WebSocket连接