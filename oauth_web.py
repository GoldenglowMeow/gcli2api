#!/usr/bin/env python3
"""
OAuth Web 服务器 - 独立的OAuth认证服务
提供简化的OAuth认证界面，只包含验证功能，不包含上传和管理功能
"""

import os
import sys
from log import log
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# 导入本地模块
try:
    from geminicli.auth_api import (
        create_auth_url, 
        verify_password, 
        generate_auth_token, 
        verify_auth_token,
        asyncio_complete_auth_flow,
        start_oauth_server,
        stop_oauth_server,
        CALLBACK_URL,
        CALLBACK_PORT,
    )
except ImportError as e:
    log.error(f"导入模块失败: {e}")
    sys.exit(1)

# 创建FastAPI应用
app = FastAPI(
    title="Google OAuth 认证服务",
    description="独立的OAuth认证服务，用于获取Google Cloud认证文件",
    version="1.0.0"
)

# HTTP Bearer认证
security = HTTPBearer()

# 请求模型
class LoginRequest(BaseModel):
    password: str

class AuthStartRequest(BaseModel):
    project_id: str

class AuthCallbackRequest(BaseModel):
    project_id: str

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证认证令牌"""
    if not verify_auth_token(credentials.credentials):
        raise HTTPException(status_code=401, detail="无效的认证令牌")
    return credentials.credentials


@app.get("/", response_class=HTMLResponse)
async def serve_oauth_page():
    """提供OAuth认证页面"""
    try:
        # 读取HTML文件
        html_file_path = "./geminicli/oauth_auth.html"
        
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="认证页面不存在")
    except Exception as e:
        log.error(f"加载认证页面失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")

@app.post("/auth/login")
async def login(request: LoginRequest):
    """用户登录"""
    try:
        if verify_password(request.password):
            token = generate_auth_token()
            return JSONResponse(content={"token": token, "message": "登录成功"})
        else:
            raise HTTPException(status_code=401, detail="密码错误")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"登录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/start")
async def start_auth(request: AuthStartRequest, token: str = Depends(verify_token)):
    """开始认证流程"""
    try:
        if not request.project_id:
            raise HTTPException(status_code=400, detail="Project ID 不能为空")
        
        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        result = create_auth_url(request.project_id, user_session)
        
        if result['success']:
            return JSONResponse(content={
                "auth_url": result['auth_url'],
                "state": result['state'],
                "callback_url": CALLBACK_URL
            })
        else:
            raise HTTPException(status_code=500, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"开始认证流程失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/callback")
async def auth_callback(request: AuthCallbackRequest, token: str = Depends(verify_token)):
    """处理认证回调（异步等待）"""
    try:
        if not request.project_id:
            raise HTTPException(status_code=400, detail="Project ID 不能为空")
        
        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        # 异步等待OAuth回调完成
        result = await asyncio_complete_auth_flow(request.project_id, user_session)
        
        if result['success']:
            return JSONResponse(content={
                "credentials": result['credentials'],
                "file_path": result['file_path'],
                "message": "认证成功，凭证已保存"
            })
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"处理认证回调失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("OAuth认证服务启动中...")

    # 启动OAuth回调服务器
    if start_oauth_server():
        log.info(f"OAuth回调服务器已启动: {CALLBACK_URL}")
    else:
        log.warning(f"OAuth回调服务器启动失败，端口 {CALLBACK_PORT} 可能被占用")

    # 检查环境变量配置
    password = os.getenv('PASSWORD')
    if not password:
        log.warning("未设置PASSWORD环境变量，将使用默认密码 'pwd'")
        log.warning("建议设置环境变量: export PASSWORD=your_password")

    # 显示配置信息
    log.info(f"OAuth回调地址: {CALLBACK_URL}")
    log.info("Web服务已由 ASGI 服务器启动")

    print("\n" + "="*60)
    print("🚀 Google OAuth 认证服务已启动")
    print("="*60)
    print(f"📱 Web界面: http://localhost:7861")
    print(f"🔗 OAuth回调: {CALLBACK_URL}")
    print(f"🔐 默认密码: {'已设置' if password else 'pwd (请设置PASSWORD环境变量)'}")
    print("="*60 + "\n")

    try:
        yield
    finally:
        log.info("OAuth认证服务关闭中...")
        stop_oauth_server()
        log.info("OAuth认证服务已关闭")

# 注册 lifespan 处理器
app.router.lifespan_context = lifespan

def get_available_port(start_port: int = 8000) -> int:
    """获取可用端口"""
    import socket
    
    for port in range(start_port, start_port + 100):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    
    return start_port  # 如果都被占用，返回起始端口


def main():
    """主函数"""
    print("启动 Google OAuth 认证服务...")
    
    # 解析命令行参数
    import argparse
    parser = argparse.ArgumentParser(description='Google OAuth 认证服务')
    parser.add_argument('--host', default='localhost', help='服务器主机地址')
    parser.add_argument('--port', type=int, default=8000, help='服务器端口')
    parser.add_argument('--auto-port', action='store_true', help='自动寻找可用端口')
    parser.add_argument('--log-level', default='info', 
                       choices=['debug', 'info', 'warning', 'error'],
                       help='日志级别')
    
    args = parser.parse_args()
    
    # 自动寻找可用端口
    if args.auto_port:
        args.port = get_available_port(args.port)
        print(f"使用端口: {args.port}")
    
    # 保留原有 main 定义以兼容，但 __main__ 中改用 hypercorn 直接启动
    return True


if __name__ == "__main__":
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = ["0.0.0.0:7861"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.loglevel = "INFO"
    
    asyncio.run(serve(app, config))