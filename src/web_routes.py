"""
Web路由模块 - 处理认证相关的HTTP请求和控制面板功能
用于与上级web.py集成
"""
import os
from log import log
import json
import asyncio
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from .auth_api import (
    create_auth_url, get_auth_status,
    verify_password, generate_auth_token, verify_auth_token,
    asyncio_complete_auth_flow,
    load_credentials_from_env, clear_env_credentials
)
from .user_aware_credential_manager import UserCredentialManager
from .usage_stats import get_usage_stats, get_aggregated_stats
import config

# 创建路由器
router = APIRouter()
security = HTTPBearer()

# WebSocket连接管理
class ConnectionManager:
    def __init__(self, max_connections: int = 10):
        self.active_connections: List[WebSocket] = []
        self.max_connections = max_connections

    async def connect(self, websocket: WebSocket):
        # 限制最大连接数，防止内存无限增长
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

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        # 使用倒序遍历，安全地移除失效连接
        for i in range(len(self.active_connections) - 1, -1, -1):
            try:
                await self.active_connections[i].send_text(message)
            except Exception:
                self.active_connections.pop(i)
                
    def cleanup_dead_connections(self):
        """清理已断开的连接"""
        self.active_connections = [
            conn for conn in self.active_connections 
            if conn.client_state != WebSocketState.DISCONNECTED
        ]

manager = ConnectionManager()

# 移除了全局凭证管理器相关的函数

def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """验证用户密码（控制面板使用）"""
    from config import get_panel_password
    password = get_panel_password()
    token = credentials.credentials
    if token != password:
        raise HTTPException(status_code=403, detail="密码错误")
    return token

class LoginRequest(BaseModel):
    password: str

class AuthStartRequest(BaseModel):
    project_id: Optional[str] = None  # 现在是可选的

class AuthCallbackRequest(BaseModel):
    project_id: Optional[str] = None  # 现在是可选的

class CredFileActionRequest(BaseModel):
    filename: str
    action: str  # enable, disable, delete

class CredFileBatchActionRequest(BaseModel):
    action: str  # "enable", "disable", "delete"
    filenames: List[str]  # 批量操作的文件名列表

class ConfigSaveRequest(BaseModel):
    config: dict

class UserCredActionRequest(BaseModel):
    username: str
    filename: str
    action: str  # enable, disable, delete

class UserUploadRequest(BaseModel):
    username: str



def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证认证令牌"""
    if not verify_auth_token(credentials.credentials):
        raise HTTPException(status_code=401, detail="无效的认证令牌")
    return credentials.credentials

@router.get("/admin", response_class=HTMLResponse)
# @router.get("/admin/v1", response_class=HTMLResponse)
# @router.get("/auth", response_class=HTMLResponse)
async def serve_control_panel():
    """提供统一控制面板（包含认证、文件管理、配置等功能）"""
    try:
        # 读取统一的控制面板HTML文件
        html_file_path = "front/control_panel.html"
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="控制面板页面不存在")
    except Exception as e:
        log.error(f"加载控制面板页面失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.get("/", response_class=HTMLResponse)
async def serve_user_login():
    """提供用户登录界面"""
    try:
        html_file_path = "front/user_login.html"
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="用户登录页面不存在")
    except Exception as e:
        log.error(f"加载用户登录页面失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.get("/dashboard", response_class=HTMLResponse)
async def serve_user_dashboard():
    """提供用户面板界面"""
    try:
        html_file_path = "front/user_dashboard.html"
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="用户面板页面不存在")
    except Exception as e:
        log.error(f"加载用户面板页面失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.post("/auth/login")
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


@router.post("/auth/start")
async def start_auth(request: AuthStartRequest, token: str = Depends(verify_token)):
    """开始认证流程，支持自动检测项目ID"""
    try:
        # 如果没有提供项目ID，尝试自动检测
        project_id = request.project_id
        if not project_id:
            log.info("用户未提供项目ID，后续将使用自动检测...")
        
        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        result = create_auth_url(project_id, user_session)
        
        if result['success']:
            return JSONResponse(content={
                "auth_url": result['auth_url'],
                "state": result['state'],
                "auto_project_detection": result.get('auto_project_detection', False),
                "detected_project_id": result.get('detected_project_id')
            })
        else:
            raise HTTPException(status_code=500, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"开始认证流程失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/callback")
async def auth_callback(request: AuthCallbackRequest, token: str = Depends(verify_token)):
    """处理认证回调，支持自动检测项目ID"""
    try:
        # 项目ID现在是可选的，在回调处理中进行自动检测
        project_id = request.project_id
        
        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        # 异步等待OAuth回调完成
        result = await asyncio_complete_auth_flow(project_id, user_session)
        
        if result['success']:
            return JSONResponse(content={
                "credentials": result['credentials'],
                "file_path": result['file_path'],
                "message": "认证成功，凭证已保存",
                "auto_detected_project": result.get('auto_detected_project', False)
            })
        else:
            # 如果需要手动项目ID或项目选择，在响应中标明
            if result.get('requires_manual_project_id'):
                # 使用JSON响应而不是HTTPException来传递复杂数据
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": result['error'],
                        "requires_manual_project_id": True
                    }
                )
            elif result.get('requires_project_selection'):
                # 返回项目列表供用户选择
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": result['error'],
                        "requires_project_selection": True,
                        "available_projects": result['available_projects']
                    }
                )
            else:
                raise HTTPException(status_code=400, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"处理认证回调失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/auth/status/{project_id}")
async def check_auth_status(project_id: str, token: str = Depends(verify_token)):
    """检查认证状态"""
    try:
        if not project_id:
            raise HTTPException(status_code=400, detail="Project ID 不能为空")
        
        status = get_auth_status(project_id)
        return JSONResponse(content=status)
        
    except Exception as e:
        log.error(f"检查认证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/list")
async def get_users_list(token: str = Depends(verify_token)):
    """获取用户列表"""
    try:
        from .user_database import user_db
        from .user_aware_credential_manager import UserCredentialManager

        # 获取所有用户
        users = user_db.get_all_users()

        users_info = []
        for user in users:
            # 获取用户的凭证统计
            try:
                manager = UserCredentialManager(user["username"])
                await manager.initialize()
                filenames = manager.get_user_credential_files()
                credentials = []
                for filename in filenames:
                    cred_state = manager._get_cred_state(filename)
                    credentials.append({
                        "filename": filename,
                        "is_enabled": not cred_state.get("disabled", False)
                    })
                await manager.close()

                total_creds = len(credentials)
                enabled_creds = sum(1 for cred in credentials if cred.get("is_enabled", False))
            except Exception as e:
                log.warning(f"获取用户 {user['username']} 凭证统计失败: {e}")
                total_creds = 0
                enabled_creds = 0

            users_info.append({
                "user_id": user["user_id"],
                "username": user["username"],
                "created_at": user["created_at"],
                "total_credentials": total_creds,
                "enabled_credentials": enabled_creds
            })

        return JSONResponse(content={"users": users_info})
        
    except Exception as e:
        log.error(f"获取用户列表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/creds/status")
async def get_creds_status(user: Optional[str] = None, token: str = Depends(verify_token)):
    """获取凭证文件的状态，支持按用户过滤"""
    try:
        if user:
            # 获取指定用户的凭证
            from .user_aware_credential_manager import UserCredentialManager
            from .user_database import user_db

            # 通过username获取user_id
            user_info = user_db.get_user_by_username(user)
            if not user_info:
                return JSONResponse(content={"creds": {}, "error": f"用户 {user} 不存在"})

            try:
                manager = UserCredentialManager(user)
                await manager.initialize()
                filenames = manager.get_user_credential_files()

                creds_info = {}
                for filename in filenames:
                    cred_state = manager._get_cred_state(filename)
                    is_enabled = not cred_state.get("disabled", False)

                    # 构建文件路径
                    user_creds_dir = manager._get_user_credentials_dir()
                    filepath = os.path.join(user_creds_dir, filename)

                    # 检查文件是否存在
                    if not os.path.exists(filepath):
                        creds_info[filename] = {
                            "status": {
                                "enabled": is_enabled,
                                "disabled": not is_enabled,
                                "valid": False
                            },
                            "content": None,
                            "filename": filename,
                            "error": "文件不存在"
                        }
                        continue

                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = json.loads(f.read())

                        creds_info[filename] = {
                            "status": {
                                "enabled": is_enabled,
                                "disabled": not is_enabled,
                                "valid": True,
                                "user_email": content.get("client_email", "未知")
                            },
                            "content": content,
                            "filename": filename,
                            "size": os.path.getsize(filepath),
                            "modified_time": os.path.getmtime(filepath),
                            "user_email": content.get("client_email", "未知")
                        }
                    except Exception as e:
                        log.error(f"读取用户凭证文件失败 {filepath}: {e}")
                        creds_info[filename] = {
                            "status": {
                                "enabled": is_enabled,
                                "disabled": not is_enabled,
                                "valid": False
                            },
                            "content": None,
                            "filename": filename,
                            "error": str(e)
                        }

                await manager.close()
                return JSONResponse(content={"creds": creds_info})

            except Exception as e:
                log.error(f"获取用户 {user} 凭证失败: {e}")
                return JSONResponse(content={"creds": {}, "error": str(e)})
        else:
            # 管理员模式：获取所有用户的凭证状态
            from .user_aware_credential_manager import UserCredentialManager
            from .user_database import user_db

            try:
                users = user_db.get_all_users()
                creds_info = {}

                for user_info in users:
                    username = user_info["username"]
                    manager = UserCredentialManager(username)
                    await manager.initialize()
                    filenames = manager.get_user_credential_files()

                    for filename in filenames:
                        cred_state = manager._get_cred_state(filename)
                        is_enabled = not cred_state.get("disabled", False)

                        # 构建文件路径
                        user_creds_dir = manager._get_user_credentials_dir()
                        filepath = os.path.join(user_creds_dir, filename)

                        creds_info[filename] = {
                            "status": {
                                "enabled": is_enabled,
                                "disabled": not is_enabled,
                                "valid": os.path.exists(filepath),
                                "user_email": cred_state.get("user_email", "未知")
                            },
                            "content": None,  # 出于安全考虑，不返回完整内容
                            "filename": filename,
                            "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0,
                            "modified_time": os.path.getmtime(filepath) if os.path.exists(filepath) else 0,
                            "user_email": cred_state.get("user_email", "未知"),
                            "username": username
                        }

                    await manager.close()

                return JSONResponse(content={"creds": creds_info})

            except Exception as e:
                log.error(f"获取所有用户凭证失败: {e}")
                return JSONResponse(content={"creds": {}, "error": str(e)})
        
    except Exception as e:
        log.error(f"获取凭证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/action")
async def creds_action(request: CredFileActionRequest, token: str = Depends(verify_token)):
    """对凭证文件执行操作（启用/禁用/删除）"""
    try:
        from .user_aware_credential_manager import UserCredentialManager
        from .user_database import user_db

        log.info(f"Received request: {request}")

        filename = request.filename
        action = request.action

        log.info(f"Performing action '{action}' on file: {filename}")

        # 验证文件类型
        if not filename.endswith('.json'):
            log.error(f"Invalid file type: {filename}")
            raise HTTPException(status_code=400, detail="无效的文件类型，必须是JSON文件")

        # 查找文件所属的用户
        users = user_db.get_all_users()
        username = None
        for user_info in users:
            user = user_info["username"]
            manager = UserCredentialManager(user)
            await manager.initialize()
            filenames = manager.get_user_credential_files()
            await manager.close()

            if filename in filenames:
                username = user
                break

        if not username:
            raise HTTPException(status_code=404, detail="找不到对应的用户凭证文件")

        try:
            manager = UserCredentialManager(username)
            await manager.initialize()

            if action == "enable":
                await manager.set_cred_disabled(filename, False)
                result = {"success": True, "message": f"已启用用户 {username} 的凭证文件 {filename}"}
            elif action == "disable":
                await manager.set_cred_disabled(filename, True)
                result = {"success": True, "message": f"已禁用用户 {username} 的凭证文件 {filename}"}
            elif action == "delete":
                success = await manager.delete_user_credential(filename)
                if success:
                    result = {"success": True, "message": f"已删除用户 {username} 的凭证文件 {filename}"}
                else:
                    result = {"success": False, "error": "删除失败"}
            else:
                await manager.close()
                raise HTTPException(status_code=400, detail="无效的操作类型")

            await manager.close()

            if result["success"]:
                return JSONResponse(content={"message": result["message"]})
            else:
                raise HTTPException(status_code=400, detail=result["error"])

        except Exception as e:
            log.error(f"用户凭证操作失败: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"凭证文件操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/user-action")
async def user_creds_action(request: UserCredActionRequest, token: str = Depends(verify_token)):
    """对指定用户的凭证文件执行操作（启用/禁用/删除）"""
    try:
        from .user_aware_credential_manager import UserCredentialManager

        username = request.username
        filename = request.filename
        action = request.action

        log.info(f"Performing action '{action}' on user {username} file: {filename}")

        try:
            manager = UserCredentialManager(username)
            await manager.initialize()

            if action == "enable":
                await manager.set_cred_disabled(filename, False)
                result = {"success": True, "message": f"成功启用用户 {username} 的凭证文件 {filename}"}
            elif action == "disable":
                await manager.set_cred_disabled(filename, True)
                result = {"success": True, "message": f"成功禁用用户 {username} 的凭证文件 {filename}"}
            elif action == "delete":
                success = await manager.delete_user_credential(filename)
                if success:
                    result = {"success": True, "message": f"成功删除用户 {username} 的凭证文件 {filename}"}
                else:
                    result = {"success": False, "error": "删除失败"}
            else:
                await manager.close()
                raise HTTPException(status_code=400, detail="无效的操作类型")

            await manager.close()

            if result["success"]:
                return JSONResponse(content={
                    "success": True,
                    "message": result["message"]
                })
            else:
                raise HTTPException(status_code=400, detail=result["error"])

        except Exception as e:
            log.error(f"用户凭证操作失败: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"用户凭证操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/creds/batch-action")
async def creds_batch_action(request: CredFileBatchActionRequest, token: str = Depends(verify_token)):
    """批量对凭证文件执行操作（启用/禁用/删除）"""
    try:
        from .user_aware_credential_manager import UserCredentialManager
        from .user_database import user_db

        action = request.action
        filenames = request.filenames

        if not filenames:
            raise HTTPException(status_code=400, detail="文件名列表不能为空")

        log.info(f"Performing batch action '{action}' on {len(filenames)} files")

        success_count = 0
        errors = []

        # 获取所有用户
        users = user_db.get_all_users()

        # 创建文件名到用户名的映射
        filename_to_username = {}
        for user_info in users:
            username = user_info["username"]
            manager = UserCredentialManager(username)
            await manager.initialize()
            user_filenames = manager.get_user_credential_files()
            await manager.close()

            for filename in user_filenames:
                filename_to_username[filename] = username

        for filename in filenames:
            try:
                # 验证文件类型
                if not filename.endswith('.json'):
                    errors.append(f"{filename}: 无效的文件类型")
                    continue

                # 查找文件所属的用户
                username = filename_to_username.get(filename)
                if not username:
                    errors.append(f"{filename}: 找不到对应的用户")
                    continue

                # 执行相应操作
                try:
                    manager = UserCredentialManager(username)
                    await manager.initialize()

                    if action == "enable":
                        await manager.set_cred_disabled(filename, False)
                        success_count += 1
                    elif action == "disable":
                        await manager.set_cred_disabled(filename, True)
                        success_count += 1
                    elif action == "delete":
                        success = await manager.delete_user_credential(filename)
                        if success:
                            success_count += 1
                        else:
                            errors.append(f"{filename}: 删除失败")
                    else:
                        errors.append(f"{filename}: 无效的操作类型")

                    await manager.close()

                except Exception as e:
                    errors.append(f"{filename}: 操作失败 - {str(e)}")

            except Exception as e:
                log.error(f"Processing {filename} failed: {e}")
                errors.append(f"{filename}: 处理失败 - {str(e)}")
                continue

        # 构建返回消息
        result_message = f"批量操作完成：成功处理 {success_count}/{len(filenames)} 个文件"
        if errors:
            result_message += f"\n错误详情：\n" + "\n".join(errors)

        response_data = {
            "success_count": success_count,
            "total_count": len(filenames),
            "errors": errors,
            "message": result_message
        }

        return JSONResponse(content=response_data)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"批量凭证文件操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/creds/download/{filename}")
async def download_cred_file(filename: str, token: str = Depends(verify_token)):
    """下载单个凭证文件"""
    try:
        # 构建完整路径
        from config import CREDENTIALS_DIR
        filepath = os.path.join(CREDENTIALS_DIR, filename)
        
        # 验证文件路径安全性
        if not filepath.endswith('.json') or not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="文件不存在")
        
        # 读取文件内容
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        from fastapi.responses import Response
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"下载凭证文件失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/fetch-email/{filename}")
async def fetch_user_email(filename: str, token: str = Depends(verify_token)):
    """获取指定凭证文件的用户邮箱地址"""
    try:
        from .user_aware_credential_manager import UserCredentialManager
        from .user_database import user_db

        # 查找文件所属的用户
        users = user_db.get_all_users()
        username = None
        user_creds_dir = None

        for user_info in users:
            user = user_info["username"]
            manager = UserCredentialManager(user)
            await manager.initialize()
            filenames = manager.get_user_credential_files()

            if filename in filenames:
                username = user
                user_creds_dir = manager._get_user_credentials_dir()
                await manager.close()
                break
            else:
                await manager.close()

        if not username or not user_creds_dir:
            raise HTTPException(status_code=404, detail="找不到对应的用户凭证文件")

        filepath = os.path.join(user_creds_dir, filename)

        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="文件不存在")

        # 读取凭证文件获取邮箱
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                cred_data = json.loads(f.read())
                email = cred_data.get("client_email", "未知")

            return JSONResponse(content={
                "filename": filename,
                "user_email": email,
                "message": "成功获取用户邮箱"
            })
        except Exception as e:
            log.error(f"读取凭证文件失败: {e}")
            return JSONResponse(content={
                "filename": filename,
                "user_email": None,
                "message": "无法读取凭证文件"
            }, status_code=400)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取用户邮箱失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/creds/refresh-all-emails")
async def refresh_all_user_emails(token: str = Depends(verify_token)):
    """刷新所有凭证文件的用户邮箱地址"""
    try:
        from .user_aware_credential_manager import UserCredentialManager
        from .user_database import user_db

        # 获取所有用户
        users = user_db.get_all_users()

        results = []
        success_count = 0

        for user_info in users:
            username = user_info["username"]
            manager = UserCredentialManager(username)
            await manager.initialize()
            filenames = manager.get_user_credential_files()
            user_creds_dir = manager._get_user_credentials_dir()

            for filename in filenames:
                filepath = os.path.join(user_creds_dir, filename)

                try:
                    if os.path.exists(filepath):
                        with open(filepath, 'r', encoding='utf-8') as f:
                            cred_data = json.loads(f.read())
                            email = cred_data.get("client_email", "未知")

                        if email and email != "未知":
                            success_count += 1
                            results.append({
                                "filename": filename,
                                "user_email": email,
                                "username": username,
                                "success": True
                            })
                        else:
                            results.append({
                                "filename": filename,
                                "user_email": None,
                                "username": username,
                                "success": False,
                                "error": "无法获取邮箱"
                            })
                    else:
                        results.append({
                            "filename": filename,
                            "user_email": None,
                            "username": username,
                            "success": False,
                            "error": "文件不存在"
                        })
                except Exception as e:
                    results.append({
                        "filename": filename,
                        "user_email": None,
                        "username": username,
                        "success": False,
                        "error": str(e)
                    })

            await manager.close()

        return JSONResponse(content={
            "success_count": success_count,
            "total_count": len(results),
            "results": results,
            "message": f"成功获取 {success_count}/{len(results)} 个邮箱地址"
        })

    except Exception as e:
        log.error(f"批量获取用户邮箱失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/creds/download-all")
async def download_all_creds(token: str = Depends(verify_token)):
    """打包下载所有凭证文件"""
    try:
        import zipfile
        import io
        from config import CREDENTIALS_DIR
        
        # 创建内存中的ZIP文件
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # 遍历所有JSON文件
            for filename in os.listdir(CREDENTIALS_DIR):
                if filename.endswith('.json'):
                    filepath = os.path.join(CREDENTIALS_DIR, filename)
                    if os.path.isfile(filepath):
                        zip_file.write(filepath, filename)
        
        zip_buffer.seek(0)
        
        from fastapi.responses import Response
        return Response(
            content=zip_buffer.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=credentials.zip"}
        )
        
    except Exception as e:
        log.error(f"打包下载失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config/get")
async def get_config(token: str = Depends(verify_token)):
    """获取当前配置"""
    try:
        # 导入配置相关模块
        import config
        import toml

        # 读取当前配置（包括环境变量和TOML文件中的配置）
        current_config = {}
        env_locked = []

        # 基础配置
        current_config["code_assist_endpoint"] = config.get_code_assist_endpoint()
        current_config["credentials_dir"] = config.get_credentials_dir()
        current_config["proxy"] = config.get_proxy_config() or ""

        # 检查环境变量锁定状态
        if os.getenv("CODE_ASSIST_ENDPOINT"):
            env_locked.append("code_assist_endpoint")
        if os.getenv("CREDENTIALS_DIR"):
            env_locked.append("credentials_dir")
        if os.getenv("PROXY"):
            env_locked.append("proxy")

        # 自动封禁配置
        current_config["auto_ban_enabled"] = config.get_auto_ban_enabled()
        current_config["auto_ban_error_codes"] = config.get_auto_ban_error_codes()

        # 检查环境变量锁定状态
        if os.getenv("AUTO_BAN"):
            env_locked.append("auto_ban_enabled")

        # 尝试从config.toml文件读取额外配置
        try:
            config_file = os.path.join(config.CREDENTIALS_DIR, "config.toml")
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as f:
                    toml_data = toml.load(f)

                # 合并TOML配置（不覆盖环境变量）
                for key, value in toml_data.items():
                    if key not in env_locked:
                        current_config[key] = value
        except Exception as e:
            log.warning(f"读取TOML配置失败: {e}")

        # 性能配置
        current_config["calls_per_rotation"] = config.get_calls_per_rotation()
        current_config["http_timeout"] = config.get_http_timeout()
        current_config["max_connections"] = config.get_max_connections()

        # 429重试配置
        current_config["retry_429_max_retries"] = config.get_retry_429_max_retries()
        current_config["retry_429_enabled"] = config.get_retry_429_enabled()
        current_config["retry_429_interval"] = config.get_retry_429_interval()

        # 日志配置
        current_config["log_level"] = config.get_log_level()
        current_config["log_file"] = config.get_log_file()

        # 抗截断配置
        current_config["anti_truncation_max_attempts"] = config.get_anti_truncation_max_attempts()

        # 服务器配置
        current_config["host"] = config.get_server_host()
        current_config["port"] = config.get_server_port()
        current_config["api_password"] = config.get_api_password()
        current_config["panel_password"] = config.get_panel_password()
        current_config["password"] = config.get_server_password()

        # 检查其他环境变量锁定状态
        if os.getenv("RETRY_429_MAX_RETRIES"):
            env_locked.append("retry_429_max_retries")
        if os.getenv("RETRY_429_ENABLED"):
            env_locked.append("retry_429_enabled")
        if os.getenv("RETRY_429_INTERVAL"):
            env_locked.append("retry_429_interval")
        if os.getenv("LOG_LEVEL"):
            env_locked.append("log_level")
        if os.getenv("LOG_FILE"):
            env_locked.append("log_file")
        if os.getenv("ANTI_TRUNCATION_MAX_ATTEMPTS"):
            env_locked.append("anti_truncation_max_attempts")
        if os.getenv("HOST"):
            env_locked.append("host")
        if os.getenv("PORT"):
            env_locked.append("port")
        if os.getenv("API_PASSWORD"):
            env_locked.append("api_password")
        if os.getenv("PANEL_PASSWORD"):
            env_locked.append("panel_password")
        if os.getenv("PASSWORD"):
            env_locked.append("password")

        return JSONResponse(content={
            "config": current_config,
            "env_locked": env_locked
        })

    except Exception as e:
        log.error(f"获取配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/save")
async def save_config(request: ConfigSaveRequest, token: str = Depends(verify_token)):
    """保存配置到TOML文件"""
    try:
        import config
        import toml

        new_config = request.config

        log.info(f"收到的配置数据: {list(new_config.keys())}")
        log.info(f"收到的password值: {new_config.get('password', 'NOT_FOUND')}")

        # 验证配置项
        if "calls_per_rotation" in new_config:
            if not isinstance(new_config["calls_per_rotation"], int) or new_config["calls_per_rotation"] < 1:
                raise HTTPException(status_code=400, detail="凭证轮换调用次数必须是大于0的整数")

        if "http_timeout" in new_config:
            if not isinstance(new_config["http_timeout"], int) or new_config["http_timeout"] < 5:
                raise HTTPException(status_code=400, detail="HTTP超时时间必须是大于等于5的整数")

        if "max_connections" in new_config:
            if not isinstance(new_config["max_connections"], int) or new_config["max_connections"] < 10:
                raise HTTPException(status_code=400, detail="最大连接数必须是大于等于10的整数")

        if "retry_429_max_retries" in new_config:
            if not isinstance(new_config["retry_429_max_retries"], int) or new_config["retry_429_max_retries"] < 0:
                raise HTTPException(status_code=400, detail="最大429重试次数必须是大于等于0的整数")

        if "retry_429_enabled" in new_config:
            if not isinstance(new_config["retry_429_enabled"], bool):
                raise HTTPException(status_code=400, detail="429重试开关必须是布尔值")

        # 验证新的配置项
        if "retry_429_interval" in new_config:
            try:
                interval = float(new_config["retry_429_interval"])
                if interval < 0.01 or interval > 10:
                    raise HTTPException(status_code=400, detail="429重试间隔必须在0.01-10秒之间")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="429重试间隔必须是有效的数字")

        if "log_level" in new_config:
            valid_levels = ["debug", "info", "warning", "error", "critical"]
            if new_config["log_level"].lower() not in valid_levels:
                raise HTTPException(status_code=400, detail=f"日志级别必须是以下之一: {', '.join(valid_levels)}")

        if "anti_truncation_max_attempts" in new_config:
            if not isinstance(new_config["anti_truncation_max_attempts"], int) or new_config["anti_truncation_max_attempts"] < 1 or new_config["anti_truncation_max_attempts"] > 10:
                raise HTTPException(status_code=400, detail="抗截断最大重试次数必须是1-10之间的整数")

        # 验证服务器配置
        if "host" in new_config:
            if not isinstance(new_config["host"], str) or not new_config["host"].strip():
                raise HTTPException(status_code=400, detail="服务器主机地址不能为空")

        if "port" in new_config:
            if not isinstance(new_config["port"], int) or new_config["port"] < 1 or new_config["port"] > 65535:
                raise HTTPException(status_code=400, detail="端口号必须是1-65535之间的整数")

        if "api_password" in new_config:
            if not isinstance(new_config["api_password"], str):
                raise HTTPException(status_code=400, detail="API访问密码必须是字符串")

        if "panel_password" in new_config:
            if not isinstance(new_config["panel_password"], str):
                raise HTTPException(status_code=400, detail="控制面板密码必须是字符串")

        if "password" in new_config:
            if not isinstance(new_config["password"], str):
                raise HTTPException(status_code=400, detail="访问密码必须是字符串")

        # 读取现有的配置文件
        config_file = os.path.join(config.CREDENTIALS_DIR, "config.toml")
        existing_config = {}

        try:
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as f:
                    existing_config = toml.load(f)
        except Exception as e:
            log.warning(f"读取现有配置文件失败: {e}")

        # 只更新不被环境变量锁定的配置项
        env_locked_keys = set()
        if os.getenv("CODE_ASSIST_ENDPOINT"):
            env_locked_keys.add("code_assist_endpoint")
        if os.getenv("CREDENTIALS_DIR"):
            env_locked_keys.add("credentials_dir")
        if os.getenv("PROXY"):
            env_locked_keys.add("proxy")
        if os.getenv("AUTO_BAN"):
            env_locked_keys.add("auto_ban_enabled")
        if os.getenv("RETRY_429_MAX_RETRIES"):
            env_locked_keys.add("retry_429_max_retries")
        if os.getenv("RETRY_429_ENABLED"):
            env_locked_keys.add("retry_429_enabled")
        if os.getenv("RETRY_429_INTERVAL"):
            env_locked_keys.add("retry_429_interval")
        if os.getenv("LOG_LEVEL"):
            env_locked_keys.add("log_level")
        if os.getenv("LOG_FILE"):
            env_locked_keys.add("log_file")
        if os.getenv("ANTI_TRUNCATION_MAX_ATTEMPTS"):
            env_locked_keys.add("anti_truncation_max_attempts")
        if os.getenv("HOST"):
            env_locked_keys.add("host")
        if os.getenv("PORT"):
            env_locked_keys.add("port")
        if os.getenv("API_PASSWORD"):
            env_locked_keys.add("api_password")
        if os.getenv("PANEL_PASSWORD"):
            env_locked_keys.add("panel_password")
        if os.getenv("PASSWORD"):
            env_locked_keys.add("password")

        for key, value in new_config.items():
            if key not in env_locked_keys:
                existing_config[key] = value
                if key == 'password':
                    log.info(f"设置password字段为: {value}")
                elif key == 'api_password':
                    log.info(f"设置api_password字段为: {value}")
                elif key == 'panel_password':
                    log.info(f"设置panel_password字段为: {value}")

        log.info(f"最终保存的existing_config中password = {existing_config.get('password', 'NOT_FOUND')}")

        # 使用config模块的保存函数
        config.save_config_to_toml(existing_config)

        # 验证保存后的结果
        test_api_password = config.get_api_password()
        test_panel_password = config.get_panel_password()
        test_password = config.get_server_password()
        log.info(f"保存后立即读取的API密码: {test_api_password}")
        log.info(f"保存后立即读取的面板密码: {test_panel_password}")
        log.info(f"保存后立即读取的通用密码: {test_password}")

        # 配置已保存，不需要热更新凭证管理器
        log.info("配置保存成功，不需要重启服务器即可生效")

        return JSONResponse(content={
            "message": "配置保存成功",
            "saved_config": {k: v for k, v in new_config.items() if k not in env_locked_keys}
        })

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"保存配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/load-env-creds")
async def load_env_credentials(token: str = Depends(verify_token)):
    """从环境变量加载凭证文件"""
    try:
        result = load_credentials_from_env()
        
        if result['loaded_count'] > 0:
            return JSONResponse(content={
                "loaded_count": result['loaded_count'],
                "total_count": result['total_count'],
                "results": result['results'],
                "message": result['message']
            })
        else:
            return JSONResponse(content={
                "loaded_count": 0,
                "total_count": result['total_count'],
                "message": result['message'],
                "results": result['results']
            })
            
    except Exception as e:
        log.error(f"从环境变量加载凭证失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/auth/env-creds")
async def clear_env_creds(token: str = Depends(verify_token)):
    """清除所有从环境变量导入的凭证文件"""
    try:
        result = clear_env_credentials()
        
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return JSONResponse(content={
            "deleted_count": result['deleted_count'],
            "deleted_files": result.get('deleted_files', []),
            "message": result['message']
        })
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"清除环境变量凭证失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/auth/env-creds-status")
async def get_env_creds_status(token: str = Depends(verify_token)):
    """获取环境变量凭证状态"""
    try:
        # 检查有哪些环境变量可用
        available_env_vars = {key: "***已设置***" for key, value in os.environ.items() 
                              if key.startswith('GCLI_CREDS_') and value.strip()}
        
        # 检查自动加载设置
        auto_load_enabled = config.get_auto_load_env_creds()
        
        # 统计已存在的环境变量凭证文件
        from config import CREDENTIALS_DIR
        existing_env_files = []
        if os.path.exists(CREDENTIALS_DIR):
            for filename in os.listdir(CREDENTIALS_DIR):
                if filename.startswith('env-') and filename.endswith('.json'):
                    existing_env_files.append(filename)
        
        return JSONResponse(content={
            "available_env_vars": available_env_vars,
            "auto_load_enabled": auto_load_enabled,
            "existing_env_files_count": len(existing_env_files),
            "existing_env_files": existing_env_files
        })
        
    except Exception as e:
        log.error(f"获取环境变量凭证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# 实时日志WebSocket (Real-time Logs WebSocket)
# =============================================================================

@router.post("/auth/logs/clear")
async def clear_logs(token: str = Depends(verify_token)):
    """清空日志文件"""
    try:
        import config
        log_file_path = config.get_log_file()
        
        # 检查日志文件是否存在
        if os.path.exists(log_file_path):
            try:
                # 清空文件内容（保留文件），确保以UTF-8编码写入
                with open(log_file_path, 'w', encoding='utf-8', newline='') as f:
                    f.write('')
                    f.flush()  # 强制刷新到磁盘
                log.info(f"日志文件已清空: {log_file_path}")
                
                # 通知所有WebSocket连接日志已清空
                await manager.broadcast("--- 日志文件已清空 ---")
                
                return JSONResponse(content={"message": f"日志文件已清空: {os.path.basename(log_file_path)}"})
            except Exception as e:
                log.error(f"清空日志文件失败: {e}")
                raise HTTPException(status_code=500, detail=f"清空日志文件失败: {str(e)}")
        else:
            return JSONResponse(content={"message": "日志文件不存在"})
            
    except Exception as e:
        log.error(f"清空日志文件失败: {e}")
        raise HTTPException(status_code=500, detail=f"清空日志文件失败: {str(e)}")

@router.get("/auth/logs/download")
async def download_logs(token: str = Depends(verify_token)):
    """下载日志文件"""
    try:
        import config
        log_file_path = config.get_log_file()
        
        # 检查日志文件是否存在
        if not os.path.exists(log_file_path):
            raise HTTPException(status_code=404, detail="日志文件不存在")
        
        # 检查文件是否为空
        file_size = os.path.getsize(log_file_path)
        if file_size == 0:
            raise HTTPException(status_code=404, detail="日志文件为空")
        
        # 生成文件名（包含时间戳）
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gcli2api_logs_{timestamp}.txt"
        
        log.info(f"下载日志文件: {log_file_path}")
        
        return FileResponse(
            path=log_file_path,
            filename=filename,
            media_type='text/plain',
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"下载日志文件失败: {e}")
        raise HTTPException(status_code=500, detail=f"下载日志文件失败: {str(e)}")

@router.websocket("/auth/logs/stream")
async def websocket_logs(websocket: WebSocket):
    """WebSocket端点，用于实时日志流"""
    # 检查连接数限制
    if not await manager.connect(websocket):
        return
    
    try:
        # 从配置获取日志文件路径
        import config
        log_file_path = config.get_log_file()
        
        # 发送初始日志（限制为最后50行，减少内存占用）
        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    # 只发送最后50行，减少初始内存消耗
                    for line in lines[-50:]:
                        if line.strip():
                            await websocket.send_text(line.strip())
            except Exception as e:
                await websocket.send_text(f"Error reading log file: {e}")
        
        # 监控日志文件变化
        last_size = os.path.getsize(log_file_path) if os.path.exists(log_file_path) else 0
        max_read_size = 8192  # 限制单次读取大小为8KB，防止大量日志造成内存激增
        check_interval = 2    # 增加检查间隔，减少CPU和I/O开销
        
        while websocket.client_state == WebSocketState.CONNECTED:
            await asyncio.sleep(check_interval)
            
            if os.path.exists(log_file_path):
                current_size = os.path.getsize(log_file_path)
                if current_size > last_size:
                    # 限制读取大小，防止单次读取过多内容
                    read_size = min(current_size - last_size, max_read_size)
                    
                    try:
                        with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(last_size)
                            new_content = f.read(read_size)
                            
                            # 处理编码错误的情况
                            if not new_content:
                                last_size = current_size
                                continue
                            
                            # 分行发送，避免发送不完整的行
                            lines = new_content.splitlines(keepends=True)
                            if lines:
                                # 如果最后一行没有换行符，保留到下次处理
                                if not lines[-1].endswith('\n') and len(lines) > 1:
                                    # 除了最后一行，其他都发送
                                    for line in lines[:-1]:
                                        if line.strip():
                                            await websocket.send_text(line.rstrip())
                                    # 更新位置，但要退回最后一行的字节数
                                    last_size += len(new_content.encode('utf-8')) - len(lines[-1].encode('utf-8'))
                                else:
                                    # 所有行都发送
                                    for line in lines:
                                        if line.strip():
                                            await websocket.send_text(line.rstrip())
                                    last_size += len(new_content.encode('utf-8'))
                    except UnicodeDecodeError as e:
                        # 遇到编码错误时，跳过这部分内容
                        log.warning(f"WebSocket日志读取编码错误: {e}, 跳过部分内容")
                        last_size = current_size
                    except Exception as e:
                        await websocket.send_text(f"Error reading new content: {e}")
                        # 发生其他错误时，重置文件位置
                        last_size = current_size
                        
                # 如果文件被截断（如清空日志），重置位置
                elif current_size < last_size:
                    last_size = 0
                    await websocket.send_text("--- 日志已清空 ---")
                    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"WebSocket logs error: {e}")
    finally:
        manager.disconnect(websocket)


# =============================================================================
# Usage Statistics API (使用统计API)
# =============================================================================

@router.get("/usage/stats")
async def get_usage_statistics(filename: Optional[str] = None, user: Optional[str] = None, token: str = Depends(verify_token)):
    """
    获取使用统计信息
    
    Args:
        filename: 可选，指定凭证文件名。如果不提供则返回所有文件的统计
        user: 可选，指定用户名。如果提供则只返回该用户的凭证文件统计
    
    Returns:
        usage statistics for the specified file or all files
    """
    try:
        if user:
            # 获取指定用户的凭证文件列表
            from .user_aware_credential_manager import UserCredentialManager
            from .user_database import user_db

            user_obj = user_db.get_user_by_username(user)
            if not user_obj:
                raise HTTPException(status_code=404, detail="用户不存在")

            try:
                manager = UserCredentialManager(user)
                await manager.initialize()
                user_filenames = manager.get_user_credential_files()
                await manager.close()

                if filename:
                    # 检查文件是否属于该用户
                    if filename not in user_filenames:
                        raise HTTPException(status_code=404, detail="该用户没有此凭证文件")
                    stats = await get_usage_stats(filename)
                else:
                    # 获取该用户所有凭证文件的统计
                    all_stats = await get_usage_stats()
                    stats = {}
                    for cred_filename in user_filenames:
                        if cred_filename in all_stats:
                            stats[cred_filename] = all_stats[cred_filename]
            except Exception as e:
                log.warning(f"获取用户 {user} 凭证列表失败: {e}")
                stats = {}
        else:
            stats = await get_usage_stats(filename)
            
        return JSONResponse(content={
            "success": True,
            "data": stats
        })
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取使用统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/usage/aggregated")
async def get_aggregated_usage_statistics(user: Optional[str] = None, token: str = Depends(verify_token)):
    """
    获取聚合使用统计信息
    
    Args:
        user: 可选，指定用户名。如果提供则只返回该用户的聚合统计
    
    Returns:
        Aggregated statistics across all credential files or user-specific files
    """
    try:
        if user:
            # 获取指定用户的凭证文件列表
            from .user_aware_credential_manager import UserCredentialManager
            from .user_database import user_db

            user_obj = user_db.get_user_by_username(user)
            if not user_obj:
                raise HTTPException(status_code=404, detail="用户不存在")

            try:
                manager = UserCredentialManager(user)
                await manager.initialize()
                user_filenames = manager.get_user_credential_files()
                await manager.close()

                # 获取该用户所有凭证文件的统计并聚合
                all_stats = await get_usage_stats()
                user_stats = {}
                for cred_filename in user_filenames:
                    if cred_filename in all_stats:
                        user_stats[cred_filename] = all_stats[cred_filename]
            except Exception as e:
                log.warning(f"获取用户 {user} 凭证列表失败: {e}")
                user_stats = {}
            
            # 手动聚合用户统计数据
            total_gemini_calls = 0
            total_calls = 0
            total_gemini_limit = 0
            total_limit = 0
            
            for filename, file_stats in user_stats.items():
                total_gemini_calls += file_stats.get("gemini_2_5_pro_calls", 0)
                total_calls += file_stats.get("total_calls", 0)
                total_gemini_limit += file_stats.get("daily_limit_gemini_2_5_pro", 0)
                total_limit += file_stats.get("daily_limit_total", 0)
            
            stats = {
                "total_gemini_2_5_pro_calls": total_gemini_calls,
                "total_calls": total_calls,
                "total_daily_limit_gemini_2_5_pro": total_gemini_limit,
                "total_daily_limit_total": total_limit,
                "credential_count": len(user_stats)
            }
        else:
            stats = await get_aggregated_stats()
            
        return JSONResponse(content={
            "success": True,
            "data": stats
        })
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取聚合统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class UsageLimitsUpdateRequest(BaseModel):
    filename: str
    gemini_2_5_pro_limit: Optional[int] = None
    total_limit: Optional[int] = None


@router.post("/usage/update-limits")
async def update_usage_limits(request: UsageLimitsUpdateRequest, token: str = Depends(verify_token)):
    """
    更新指定凭证文件的每日使用限制
    
    Args:
        request: 包含文件名和新限制值的请求
    
    Returns:
        Success message
    """
    try:
        from .usage_stats import get_usage_stats_instance
        stats_instance = await get_usage_stats_instance()
        
        await stats_instance.update_daily_limits(
            filename=request.filename,
            gemini_2_5_pro_limit=request.gemini_2_5_pro_limit,
            total_limit=request.total_limit
        )
        
        return JSONResponse(content={
            "success": True,
            "message": f"已更新 {request.filename} 的使用限制"
        })
        
    except Exception as e:
        log.error(f"更新使用限制失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class UsageResetRequest(BaseModel):
    filename: Optional[str] = None


@router.post("/usage/reset")
async def reset_usage_statistics(request: UsageResetRequest, token: str = Depends(verify_token)):
    """
    重置使用统计
    
    Args:
        request: 包含可选文件名的请求。如果不提供文件名则重置所有统计
    
    Returns:
        Success message
    """
    try:
        from .usage_stats import get_usage_stats_instance
        stats_instance = await get_usage_stats_instance()
        
        await stats_instance.reset_stats(filename=request.filename)
        
        if request.filename:
            message = f"已重置 {request.filename} 的使用统计"
        else:
            message = "已重置所有文件的使用统计"
        
        return JSONResponse(content={
            "success": True,
            "message": message
        })
        
    except Exception as e:
        log.error(f"重置使用统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

