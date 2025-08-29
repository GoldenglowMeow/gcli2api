"""
Web路由模块 - 处理认证相关的HTTP请求和控制面板功能
用于与上级web.py集成
"""
import os
import json
import asyncio
import zipfile
import io
import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from log import log
import config
from .auth_api import (
    create_auth_url, get_auth_status,
    verify_password, generate_auth_token, verify_auth_token,
    asyncio_complete_auth_flow,
    load_credentials_from_env, clear_env_credentials
)
# 核心依赖
from .user_database import user_db
from .user_aware_credential_manager import UserCredentialManager


# --- 路由器和安全设置 ---
router = APIRouter()
security = HTTPBearer()

# --- WebSocket 连接管理器 ---
class ConnectionManager:
    def __init__(self, max_connections: int = 10):
        self.active_connections: List[WebSocket] = []
        self.max_connections = max_connections

    async def connect(self, websocket: WebSocket):
        if len(self.active_connections) >= self.max_connections:
            await websocket.close(code=1008, reason="Too many connections")
            return False
        await websocket.accept()
        self.active_connections.append(websocket)
        log.debug(f"WebSocket连接建立，当前连接数: {len(self.active_connections)}")
        return True

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        log.debug(f"WebSocket连接断开，当前连接数: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(message)
            except Exception:
                self.active_connections.remove(connection)

manager = ConnectionManager()

# --- 请求模型 ---
class LoginRequest(BaseModel):
    password: str

class AuthStartRequest(BaseModel):
    project_id: Optional[str] = None

class AuthCallbackRequest(BaseModel):
    project_id: Optional[str] = None

class UserCredActionRequest(BaseModel):
    username: str
    name: str # 从 filename 改为 name
    action: str  # "enable", "disable", "delete"

class ConfigSaveRequest(BaseModel):
    config: dict

# --- 认证依赖 ---
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证认证令牌"""
    if not verify_auth_token(credentials.credentials):
        raise HTTPException(status_code=401, detail="无效的认证令牌")
    return credentials.credentials

# --- 静态页面服务 ---
@router.get("/admin", response_class=HTMLResponse)
async def serve_control_panel():
    """提供统一控制面板"""
    try:
        with open("front/control_panel.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="控制面板页面不存在")

@router.get("/", response_class=HTMLResponse)
async def serve_user_login():
    """提供用户登录界面"""
    try:
        with open("front/user_login.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="用户登录页面不存在")

@router.get("/dashboard", response_class=HTMLResponse)
async def serve_user_dashboard():
    """提供用户面板界面"""
    try:
        with open("front/user_dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="用户面板页面不存在")

# --- 管理员认证和授权流程 ---
@router.post("/auth/login")
async def login(request: LoginRequest):
    """管理员登录"""
    if verify_password(request.password):
        token = generate_auth_token()
        return JSONResponse(content={"token": token, "message": "登录成功"})
    else:
        raise HTTPException(status_code=401, detail="密码错误")

@router.get("/auth/verify")
async def verify_auth(token: str = Depends(verify_token)):
    """验证令牌有效性"""
    return JSONResponse(content={"valid": True, "message": "令牌有效"})

@router.post("/auth/start")
async def start_auth(request: AuthStartRequest, token: str = Depends(verify_token)):
    """开始认证流程，为管理员添加凭证"""
    project_id = request.project_id
    user_session = token
    result = create_auth_url(project_id, user_session)
    if result['success']:
        return JSONResponse(content=result)
    else:
        raise HTTPException(status_code=500, detail=result['error'])

@router.post("/auth/callback")
async def auth_callback(request: AuthCallbackRequest, token: str = Depends(verify_token)):
    """处理认证回调"""
    project_id = request.project_id
    user_session = token
    result = await asyncio_complete_auth_flow(project_id, user_session)
    if result['success']:
        return JSONResponse(content=result)
    else:
        # 使用JSON响应而不是HTTPException来传递复杂数据
        status_code = 400 if result.get('requires_manual_project_id') or result.get('requires_project_selection') else 500
        return JSONResponse(status_code=status_code, content=result)

# --- 管理员面板数据接口 (重构后) ---
@router.get("/admin/dashboard-data")
async def get_admin_dashboard_data(token: str = Depends(verify_token)):
    """获取管理员仪表盘的综合数据"""
    users_data = await user_db.get_all_users()
    all_credentials = []
    
    # 确保用户数据包含api_key字段
    for user in users_data:
        # 保留用户的api_key字段
        if 'api_key' not in user:
            user_detail = await user_db.get_user_by_id(user['id'])
            if user_detail and 'api_key' in user_detail:
                user['api_key'] = user_detail['api_key']
    
    for user in users_data:
        user_creds = await user_db.list_credentials_for_user(user['id'])
        for cred in user_creds:
            cred['username'] = user['username']
            cred['is_active'] = bool(cred['is_active'])
            # 移除credential_data字段
            if 'credential_data' in cred:
                del cred['credential_data']
            all_credentials.append(cred)
            
    return JSONResponse(content={
        "users": users_data,
        "credentials": all_credentials
    })

@router.post("/admin/user-credential-action")
async def admin_user_credential_action(request: UserCredActionRequest, token: str = Depends(verify_token)):
    """管理员对指定用户的凭证文件执行操作"""
    user = await user_db.get_user_by_username(request.username)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    cred_mgr = UserCredentialManager(request.username)
    await cred_mgr.initialize()

    try:
        if request.action == "enable":
            success = await cred_mgr.set_credential_active_status(request.name, True)
            message = "凭证已启用"
        elif request.action == "disable":
            success = await cred_mgr.set_credential_active_status(request.name, False)
            message = "凭证已禁用"
        elif request.action == "delete":
            success = await cred_mgr.delete_credential(request.name)
            message = "凭证已删除"
        else:
            raise HTTPException(status_code=400, detail="无效的操作类型")

        if success:
            return JSONResponse(content={"success": True, "message": message})
        else:
            raise HTTPException(status_code=404, detail="操作失败，凭证未找到或发生错误")
    finally:
        await cred_mgr.close()

# --- 配置管理 ---
@router.get("/config/get")
async def get_config(token: str = Depends(verify_token)):
    """获取当前配置"""
    current_config = {}
    env_locked = []
    
    # 使用一个辅助函数来填充配置和锁定状态
    def add_config(key, getter_func, env_var):
        current_config[key] = getter_func()
        if os.getenv(env_var):
            env_locked.append(key)

    # 服务器基本配置
    add_config("host", config.get_server_host, "HOST")
    add_config("port", config.get_server_port, "PORT")
    add_config("api_password", config.get_api_password, "API_PASSWORD")
    add_config("panel_password", config.get_panel_password, "PANEL_PASSWORD")
    add_config("password", config.get_server_password, "PASSWORD")
    add_config("credentials_dir", config.get_credentials_dir, "CREDENTIALS_DIR")
    
    # API和服务配置
    add_config("code_assist_endpoint", config.get_code_assist_endpoint, "CODE_ASSIST_ENDPOINT")
    add_config("proxy", lambda: config.get_proxy_config() or "", "PROXY")
    add_config("auto_ban_enabled", config.get_auto_ban_enabled, "AUTO_BAN")
    current_config["auto_ban_error_codes"] = config.get_auto_ban_error_codes()
    add_config("calls_per_rotation", config.get_calls_per_rotation, "CALLS_PER_ROTATION")
    add_config("http_timeout", config.get_http_timeout, "HTTP_TIMEOUT")
    add_config("max_connections", config.get_max_connections, "MAX_CONNECTIONS")
    add_config("retry_429_max_retries", config.get_retry_429_max_retries, "RETRY_429_MAX_RETRIES")
    add_config("retry_429_enabled", config.get_retry_429_enabled, "RETRY_429_ENABLED")
    add_config("retry_429_interval", config.get_retry_429_interval, "RETRY_429_INTERVAL")
    add_config("log_level", config.get_log_level, "LOG_LEVEL")
    add_config("log_file", config.get_log_file, "LOG_FILE")
    add_config("anti_truncation_max_attempts", config.get_anti_truncation_max_attempts, "ANTI_TRUNCATION_MAX_ATTEMPTS")
    add_config("bot_api_key", config.get_bot_api_key, "BOT_API_KEY")

    return JSONResponse(content={"config": current_config, "env_locked": list(set(env_locked))})

@router.post("/config/save")
async def save_config(request: ConfigSaveRequest, token: str = Depends(verify_token)):
    """保存配置到TOML文件"""
    try:
        config.save_config_to_toml(request.config)
        return JSONResponse(content={"message": "配置保存成功，部分配置项可能需要重启生效"})
    except Exception as e:
        log.error(f"保存配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --- 环境变量凭证管理 ---
@router.post("/auth/load-env-creds")
async def load_env_credentials(token: str = Depends(verify_token)):
    """从环境变量加载凭证文件"""
    result = load_credentials_from_env()
    return JSONResponse(content=result)

@router.delete("/auth/env-creds")
async def clear_env_creds(token: str = Depends(verify_token)):
    """清除所有从环境变量导入的凭证文件"""
    result = clear_env_credentials()
    if 'error' in result:
        raise HTTPException(status_code=500, detail=result['error'])
    return JSONResponse(content=result)

# --- 文件下载 ---
@router.get("/creds/download-all-backup")
async def download_all_creds_backup(token: str = Depends(verify_token)):
    """打包下载所有用户的凭证备份文件"""
    creds_backup_dir = os.path.join(os.path.dirname(__file__), '..', 'creds')
    if not os.path.isdir(creds_backup_dir):
        raise HTTPException(status_code=404, detail="凭证备份目录不存在")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(creds_backup_dir):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, creds_backup_dir)
                    zip_file.write(file_path, arcname)
    
    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=credentials_backup.zip"}
    )

# --- 实时日志 ---
@router.post("/auth/logs/clear")
async def clear_logs(token: str = Depends(verify_token)):
    """清空日志文件"""
    log_file_path = config.get_log_file()
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, 'w', encoding='utf-8') as f:
                f.write('')
            log.info(f"日志文件已清空: {log_file_path}")
            await manager.broadcast("--- 日志文件已清空 ---")
            return JSONResponse(content={"message": f"日志文件已清空: {os.path.basename(log_file_path)}"})
        except Exception as e:
            log.error(f"清空日志文件失败: {e}")
            raise HTTPException(status_code=500, detail=f"清空日志文件失败: {str(e)}")
    else:
        return JSONResponse(content={"message": "日志文件不存在"})

@router.get("/auth/logs/download")
async def download_logs(token: str = Depends(verify_token)):
    """下载日志文件"""
    log_file_path = config.get_log_file()
    if not os.path.exists(log_file_path) or os.path.getsize(log_file_path) == 0:
        raise HTTPException(status_code=404, detail="日志文件不存在或为空")
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"gcli2api_logs_{timestamp}.txt"
    return FileResponse(path=log_file_path, filename=filename, media_type='text/plain')

@router.websocket("/auth/logs/stream")
async def websocket_logs(websocket: WebSocket):
    """WebSocket端点，用于实时日志流"""
    if not await manager.connect(websocket):
        return

    log_file_path = config.get_log_file()
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, "r", encoding="utf-8") as f:
                # 发送最后50行
                lines = f.readlines()
                for line in lines[-50:]:
                    if line.strip():
                        await websocket.send_text(line.strip())
                last_pos = f.tell()
        else:
            last_pos = 0

        while websocket.client_state == WebSocketState.CONNECTED:
            await asyncio.sleep(1)
            if os.path.exists(log_file_path):
                with open(log_file_path, "r", encoding="utf-8") as f:
                    # 获取文件大小
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()
                    
                    # 如果文件被截断（如清空）
                    if file_size < last_pos:
                        # 文件确实被截断了，重置位置并只发送一次通知
                        last_pos = 0
                        f.seek(0)
                        await websocket.send_text("--- 日志已清空 ---")
                    
                    # 从上次位置继续读取
                    f.seek(last_pos)
                    new_content = f.read()
                    if new_content:
                        for line in new_content.splitlines():
                            if line.strip():
                                await websocket.send_text(line.strip())
                    last_pos = f.tell()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"WebSocket logs error: {e}")
    finally:
        manager.disconnect(websocket)
