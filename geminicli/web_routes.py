"""
Web路由模块 - 处理认证相关的HTTP请求
用于与上级web.py集成
"""
import os
import logging
import json
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from .auth_api import (
    create_auth_url, get_auth_status,
    verify_password, generate_auth_token, verify_auth_token,
    batch_upload_credentials, asyncio_complete_auth_flow, auto_detect_project_id
)
from .credential_manager import CredentialManager

# 创建路由器
router = APIRouter()
security = HTTPBearer()

# 创建credential manager实例
credential_manager = CredentialManager()

async def ensure_credential_manager_initialized():
    """确保credential manager已初始化"""
    if not credential_manager._initialized:
        await credential_manager.initialize()

class LoginRequest(BaseModel):
    password: str

class AuthStartRequest(BaseModel):
    project_id: Optional[str] = None  # 现在是可选的

class AuthCallbackRequest(BaseModel):
    project_id: Optional[str] = None  # 现在是可选的

class CredFileActionRequest(BaseModel):
    filename: str
    action: str  # enable, disable, delete

class ConfigSaveRequest(BaseModel):
    config: dict


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证认证令牌"""
    if not verify_auth_token(credentials.credentials):
        raise HTTPException(status_code=401, detail="无效的认证令牌")
    return credentials.credentials


@router.get("/auth", response_class=HTMLResponse)
async def serve_auth_page():
    """提供认证页面"""
    try:
        # 读取HTML文件
        html_file_path = "./geminicli/auth_web_manager.html"
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="认证页面不存在")
    except Exception as e:
        logging.error(f"加载认证页面失败: {e}")
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
        logging.error(f"登录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/start")
async def start_auth(request: AuthStartRequest, token: str = Depends(verify_token)):
    """开始认证流程，支持自动检测项目ID"""
    try:
        # 如果没有提供项目ID，尝试自动检测
        project_id = request.project_id
        if not project_id:
            logging.info("用户未提供项目ID，后续将使用自动检测...")
        
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
        logging.error(f"开始认证流程失败: {e}")
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
        logging.error(f"处理认证回调失败: {e}")
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
        logging.error(f"检查认证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/upload")
async def upload_credentials(files: List[UploadFile] = File(...), token: str = Depends(verify_token)):
    """批量上传认证文件"""
    try:
        if not files:
            raise HTTPException(status_code=400, detail="请选择要上传的文件")
        
        files_data = []
        for file in files:
            if not file.filename.endswith('.json'):
                raise HTTPException(status_code=400, detail=f"文件 {file.filename} 不是JSON格式")
            
            content = await file.read()
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                raise HTTPException(status_code=400, detail=f"文件 {file.filename} 编码格式不支持")
            
            files_data.append({
                'filename': file.filename,
                'content': content_str
            })
        
        result = batch_upload_credentials(files_data)
        
        if result['uploaded_count'] > 0:
            return JSONResponse(content={
                "uploaded_count": result['uploaded_count'],
                "total_count": result['total_count'],
                "results": result['results'],
                "message": f"成功上传 {result['uploaded_count']}/{result['total_count']} 个文件"
            })
        else:
            raise HTTPException(status_code=400, detail="没有文件上传成功")
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"批量上传失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/creds/status")
async def get_creds_status(token: str = Depends(verify_token)):
    """获取所有凭证文件的状态"""
    try:
        await ensure_credential_manager_initialized()
        
        # 强制从文件重新加载最新状态
        await credential_manager._load_state()
        
        # 获取状态时不要调用_discover_credential_files，因为它会过滤被禁用的文件
        # 直接获取所有文件的状态
        status = credential_manager.get_creds_status()
        
        # 读取文件内容
        creds_info = {}
        for filename, file_status in status.items():
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = json.loads(f.read())
                
                creds_info[filename] = {
                    "status": file_status,
                    "content": content,
                    "filename": os.path.basename(filename),
                    "size": os.path.getsize(filename),
                    "modified_time": os.path.getmtime(filename)
                }
            except Exception as e:
                logging.error(f"读取凭证文件失败 {filename}: {e}")
                creds_info[filename] = {
                    "status": file_status,
                    "content": None,
                    "filename": os.path.basename(filename),
                    "error": str(e)
                }
        
        return JSONResponse(content={"creds": creds_info})
        
    except Exception as e:
        logging.error(f"获取凭证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/action")
async def creds_action(request: CredFileActionRequest, token: str = Depends(verify_token)):
    """对凭证文件执行操作（启用/禁用/删除）"""
    try:
        await ensure_credential_manager_initialized()
        
        logging.info(f"Received request: {request}")
        
        filename = request.filename
        action = request.action
        
        logging.info(f"Performing action '{action}' on file: {filename}")
        
        # 验证文件路径安全性
        logging.info(f"Validating file path: {repr(filename)}")
        logging.info(f"Is absolute: {os.path.isabs(filename)}")
        logging.info(f"Ends with .json: {filename.endswith('.json')}")
        
        # 如果不是绝对路径，转换为绝对路径
        if not os.path.isabs(filename):
            from .config import CREDENTIALS_DIR
            filename = os.path.abspath(os.path.join(CREDENTIALS_DIR, os.path.basename(filename)))
            logging.info(f"Converted to absolute path: {filename}")
        
        if not filename.endswith('.json'):
            logging.error(f"Invalid file path: {filename} (not a .json file)")
            raise HTTPException(status_code=400, detail=f"无效的文件路径: {filename}")
        
        # 确保文件在CREDENTIALS_DIR内（安全检查）
        from .config import CREDENTIALS_DIR
        credentials_dir_abs = os.path.abspath(CREDENTIALS_DIR)
        filename_abs = os.path.abspath(filename)
        if not filename_abs.startswith(credentials_dir_abs):
            logging.error(f"Security violation: file outside credentials directory: {filename}")
            raise HTTPException(status_code=400, detail="文件路径不在允许的目录内")
        
        if not os.path.exists(filename):
            logging.error(f"File not found: {filename}")
            raise HTTPException(status_code=404, detail="文件不存在")
        
        if action == "enable":
            await credential_manager.set_cred_disabled(filename, False)
            return JSONResponse(content={"message": f"已启用凭证文件 {os.path.basename(filename)}"})
        
        elif action == "disable":
            await credential_manager.set_cred_disabled(filename, True)
            return JSONResponse(content={"message": f"已禁用凭证文件 {os.path.basename(filename)}"})
        
        elif action == "delete":
            try:
                os.remove(filename)
                # 同时从状态中移除（使用标准化路径）
                normalized_filename = os.path.abspath(filename)
                if normalized_filename in credential_manager._creds_state:
                    del credential_manager._creds_state[normalized_filename]
                    await credential_manager._save_state()
                return JSONResponse(content={"message": f"已删除凭证文件 {os.path.basename(filename)}"})
            except OSError as e:
                raise HTTPException(status_code=500, detail=f"删除文件失败: {str(e)}")
        
        else:
            raise HTTPException(status_code=400, detail="无效的操作类型")
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"凭证文件操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/creds/download/{filename}")
async def download_cred_file(filename: str, token: str = Depends(verify_token)):
    """下载单个凭证文件"""
    try:
        # 构建完整路径
        from .config import CREDENTIALS_DIR
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
        logging.error(f"下载凭证文件失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/creds/download-all")
async def download_all_creds(token: str = Depends(verify_token)):
    """打包下载所有凭证文件"""
    try:
        import zipfile
        import io
        from .config import CREDENTIALS_DIR
        
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
        logging.error(f"打包下载失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config/get")
async def get_config(token: str = Depends(verify_token)):
    """获取当前配置"""
    try:
        await ensure_credential_manager_initialized()
        
        # 导入配置相关模块
        from . import config
        import toml
        
        # 读取当前配置（包括环境变量和TOML文件中的配置）
        current_config = {}
        env_locked = []
        
        # 基础配置
        if os.getenv("CODE_ASSIST_ENDPOINT"):
            current_config["code_assist_endpoint"] = os.getenv("CODE_ASSIST_ENDPOINT")
            env_locked.append("code_assist_endpoint")
        else:
            current_config["code_assist_endpoint"] = getattr(config, 'CODE_ASSIST_ENDPOINT', '')
        
        if os.getenv("CREDENTIALS_DIR"):
            current_config["credentials_dir"] = os.getenv("CREDENTIALS_DIR")
            env_locked.append("credentials_dir")
        else:
            current_config["credentials_dir"] = getattr(config, 'CREDENTIALS_DIR', '')
        
        if os.getenv("PROXY"):
            current_config["proxy"] = os.getenv("PROXY")
            env_locked.append("proxy")
        else:
            current_config["proxy"] = ""
        
        # 自动封禁配置
        if os.getenv("AUTO_BAN"):
            current_config["auto_ban_enabled"] = os.getenv("AUTO_BAN", "true").lower() in ("true", "1", "yes", "on")
            env_locked.append("auto_ban_enabled")
        else:
            current_config["auto_ban_enabled"] = getattr(config, 'AUTO_BAN_ENABLED', True)
        
        current_config["auto_ban_error_codes"] = getattr(config, 'AUTO_BAN_ERROR_CODES', [400, 403])
        
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
            logging.warning(f"读取TOML配置失败: {e}")
        
        # 设置默认值
        current_config.setdefault("calls_per_rotation", 10)
        current_config.setdefault("http_timeout", 30)
        current_config.setdefault("max_connections", 100)
        
        return JSONResponse(content={
            "config": current_config,
            "env_locked": env_locked
        })
        
    except Exception as e:
        logging.error(f"获取配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/save")
async def save_config(request: ConfigSaveRequest, token: str = Depends(verify_token)):
    """保存配置到TOML文件"""
    try:
        await ensure_credential_manager_initialized()
        
        from . import config
        import toml
        
        new_config = request.config
        
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
        
        # 读取现有的配置文件
        config_file = os.path.join(config.CREDENTIALS_DIR, "config.toml")
        existing_config = {}
        
        try:
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as f:
                    existing_config = toml.load(f)
        except Exception as e:
            logging.warning(f"读取现有配置文件失败: {e}")
        
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
        
        for key, value in new_config.items():
            if key not in env_locked_keys:
                existing_config[key] = value
        
        # 使用config模块的保存函数
        config.save_config_to_toml(existing_config)
        
        # 热更新配置到内存中的模块（如果可能）
        try:
            # 重新加载配置缓存
            config.reload_config_cache()
            
            # 更新credential_manager的配置
            if "calls_per_rotation" in new_config and "calls_per_rotation" not in env_locked_keys:
                credential_manager._calls_per_rotation = new_config["calls_per_rotation"]
            
            # 重新初始化HTTP客户端以应用新的代理配置（如果代理配置更改了）
            if "proxy" in new_config and "proxy" not in env_locked_keys:
                # 重新创建HTTP客户端
                if credential_manager._http_client:
                    await credential_manager._http_client.aclose()
                    proxy = config.get_proxy_config()
                    client_kwargs = {
                        "timeout": new_config.get("http_timeout", 30),
                        "limits": __import__('httpx').Limits(
                            max_keepalive_connections=20, 
                            max_connections=new_config.get("max_connections", 100)
                        )
                    }
                    if proxy:
                        client_kwargs["proxy"] = proxy
                    credential_manager._http_client = __import__('httpx').AsyncClient(**client_kwargs)
        except Exception as e:
            logging.warning(f"热更新配置失败: {e}")
        
        return JSONResponse(content={
            "message": "配置保存成功",
            "saved_config": {k: v for k, v in new_config.items() if k not in env_locked_keys}
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"保存配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))
