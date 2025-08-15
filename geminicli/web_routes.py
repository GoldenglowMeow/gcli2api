"""
Web路由模块 - 处理认证相关的HTTP请求
用于与上级web.py集成
"""
import os
import logging
import json
from typing import List
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from .auth_api import (
    create_auth_url, get_auth_status,
    verify_password, generate_auth_token, verify_auth_token,
    batch_upload_credentials, asyncio_complete_auth_flow,
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
    project_id: str

class AuthCallbackRequest(BaseModel):
    project_id: str

class CredFileActionRequest(BaseModel):
    filename: str
    action: str  # enable, disable, delete


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
        html_file_path = os.path.join(os.path.dirname(__file__), "auth_web.html")
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
                "state": result['state']
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