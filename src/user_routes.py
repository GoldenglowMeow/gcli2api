from fastapi import APIRouter, HTTPException, Depends, Cookie, Response, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from log import log
from .user_database import user_db
from .user_credential_manager import user_credential_manager

router = APIRouter()
security = HTTPBearer(auto_error=False)

# 请求模型
class UserRegisterRequest(BaseModel):
    username: str
    password: str

class UserLoginRequest(BaseModel):
    username: str
    password: str

class RegenerateApiKeyRequest(BaseModel):
    pass

class CredentialActionRequest(BaseModel):
    filename: str
    action: str  # "enable", "disable", "delete"

# 用户认证依赖
def get_current_user(session_token: Optional[str] = Cookie(None)):
    """获取当前登录用户"""
    if not session_token:
        raise HTTPException(status_code=401, detail="未登录")
    
    user = user_db.validate_session(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="会话已过期，请重新登录")
    
    return user

# API密钥认证依赖
def get_user_by_api_key(credentials = None):
    """通过API密钥获取用户信息"""
    # 如果传入的是字符串，直接使用
    if isinstance(credentials, str):
        api_key = credentials
    # 如果传入的是HTTPAuthorizationCredentials对象，提取credentials
    elif hasattr(credentials, 'credentials'):
        api_key = credentials.credentials
    else:
        raise HTTPException(status_code=401, detail="需要API密钥")
    
    user = user_db.get_user_by_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="无效的API密钥")
    
    return user

# 用于FastAPI依赖注入的版本
def get_user_by_api_key_dependency(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """通过API密钥获取用户信息（用于FastAPI依赖注入）"""
    return get_user_by_api_key(credentials)

@router.post("/user/register")
async def register_user(request: UserRegisterRequest):
    """用户注册"""
    try:
        result = user_db.create_user(request.username, request.password)
        
        if result["success"]:
            return {
                "success": True,
                "message": "注册成功",
                "username": result["username"],
                "api_key": result["api_key"]
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except Exception as e:
        log.error(f"用户注册失败: {e}")
        raise HTTPException(status_code=500, detail="注册时发生错误")

@router.post("/user/login")
async def login_user(request: UserLoginRequest, response: Response):
    """用户登录"""
    try:
        auth_result = user_db.authenticate_user(request.username, request.password)
        
        if auth_result["success"]:
            # 创建会话
            session_token = user_db.create_session(auth_result["user_id"])
            
            if session_token:
                # 设置会话Cookie
                response.set_cookie(
                    key="session_token",
                    value=session_token,
                    max_age=24 * 60 * 60,  # 24小时
                    httponly=True,
                    secure=False,  # 开发环境设为False
                    samesite="lax"
                )
                
                return {
                    "success": True,
                    "message": "登录成功",
                    "username": auth_result["username"],
                    "api_key": auth_result["api_key"]
                }
            else:
                raise HTTPException(status_code=500, detail="创建会话失败")
        else:
            raise HTTPException(status_code=401, detail=auth_result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"用户登录失败: {e}")
        raise HTTPException(status_code=500, detail="登录时发生错误")

@router.post("/user/logout")
async def logout_user(response: Response, session_token: Optional[str] = Cookie(None)):
    """用户登出"""
    try:
        if session_token:
            user_db.invalidate_session(session_token)
        
        # 清除会话Cookie
        response.delete_cookie(key="session_token")
        
        return {
            "success": True,
            "message": "登出成功"
        }
        
    except Exception as e:
        log.error(f"用户登出失败: {e}")
        raise HTTPException(status_code=500, detail="登出时发生错误")

@router.get("/user/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """获取用户信息"""
    try:
        return {
            "success": True,
            "username": current_user["username"],
            "api_key": current_user["api_key"]
        }
        
    except Exception as e:
        log.error(f"获取用户信息失败: {e}")
        raise HTTPException(status_code=500, detail="获取用户信息时发生错误")

@router.post("/user/regenerate-api-key")
async def regenerate_user_api_key(request: RegenerateApiKeyRequest, current_user: dict = Depends(get_current_user)):
    """重新生成API密钥"""
    try:
        result = user_db.regenerate_api_key(current_user["user_id"])
        
        if result["success"]:
            return {
                "success": True,
                "message": "API密钥重新生成成功",
                "api_key": result["api_key"]
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"重新生成API密钥失败: {e}")
        raise HTTPException(status_code=500, detail="重新生成API密钥时发生错误")

@router.get("/user/check-auth")
async def check_user_auth(current_user: dict = Depends(get_current_user)):
    """检查用户认证状态"""
    return {
        "success": True,
        "authenticated": True,
        "username": current_user["username"]
    }

# API密钥验证接口（供其他服务调用）
@router.get("/user/validate-api-key")
async def validate_api_key(user: dict = Depends(get_user_by_api_key_dependency)):
    """验证API密钥"""
    return {
        "success": True,
        "valid": True,
        "username": user["username"],
        "user_id": user["user_id"]
    }

# 用户凭证管理接口
@router.post("/user/credentials/upload")
async def upload_user_credentials(files: List[UploadFile] = File(...), current_user: dict = Depends(get_current_user)):
    """上传用户凭证文件"""
    try:
        results = []
        
        for file in files:
            if not file.filename.endswith('.json'):
                results.append({
                    "filename": file.filename,
                    "success": False,
                    "error": "只支持JSON格式的凭证文件"
                })
                continue
            
            # 读取文件内容
            content = await file.read()
            file_content = content.decode('utf-8')
            
            # 保存凭证文件
            result = user_credential_manager.save_user_credential(
                user_id=current_user["user_id"],
                username=current_user["username"],
                file_content=file_content,
                original_filename=file.filename
            )
            
            results.append({
                "filename": file.filename,
                "success": result["success"],
                "error": result.get("error"),
                "saved_filename": result.get("filename")
            })
        
        return {
            "success": True,
            "results": results
        }
        
    except Exception as e:
        log.error(f"上传用户凭证失败: {e}")
        raise HTTPException(status_code=500, detail="上传凭证时发生错误")

@router.get("/user/credentials/list")
async def get_user_credentials(current_user: dict = Depends(get_current_user)):
    """获取用户凭证列表"""
    try:
        credentials = user_credential_manager.get_user_credentials(current_user["user_id"])
        
        return {
            "success": True,
            "credentials": credentials
        }
        
    except Exception as e:
        log.error(f"获取用户凭证列表失败: {e}")
        raise HTTPException(status_code=500, detail="获取凭证列表时发生错误")

@router.post("/user/credentials/action")
async def credential_action(request: CredentialActionRequest, current_user: dict = Depends(get_current_user)):
    """凭证文件操作（启用/禁用/删除）"""
    try:
        if request.action == "enable":
            result = user_credential_manager.toggle_credential_status(
                current_user["user_id"], request.filename, True
            )
        elif request.action == "disable":
            result = user_credential_manager.toggle_credential_status(
                current_user["user_id"], request.filename, False
            )
        elif request.action == "delete":
            result = user_credential_manager.delete_credential(
                current_user["user_id"], request.filename
            )
        else:
            raise HTTPException(status_code=400, detail="无效的操作类型")
        
        if result["success"]:
            return result
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"凭证操作失败: {e}")
        raise HTTPException(status_code=500, detail="操作失败")

@router.get("/user/credentials/{filename}/content")
async def get_credential_content(filename: str, current_user: dict = Depends(get_current_user)):
    """获取凭证文件内容（隐藏敏感信息）"""
    try:
        content = user_credential_manager.get_credential_content(
            current_user["user_id"], filename
        )
        
        if not content:
            raise HTTPException(status_code=404, detail="凭证文件不存在")
        
        # 隐藏敏感信息
        safe_content = content.copy()
        sensitive_fields = ['client_secret', 'refresh_token', 'token']
        for field in sensitive_fields:
            if field in safe_content:
                safe_content[field] = "***隐藏***"
        
        return {
            "success": True,
            "content": safe_content
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取凭证内容失败: {e}")
        raise HTTPException(status_code=500, detail="获取凭证内容时发生错误")