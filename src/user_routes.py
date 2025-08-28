from fastapi import APIRouter, HTTPException, Depends, Cookie, Response, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import time
import json
import os
from log import log
from .user_database import user_db
from .user_aware_credential_manager import UserCredentialManager

# 移除对 usage_stats 的导入

router = APIRouter()
security = HTTPBearer(auto_error=False)

# --- 请求模型 ---

class UserRegisterRequest(BaseModel):
    username: str
    password: str

class UserLoginRequest(BaseModel):
    username: str
    password: str

class RegenerateApiKeyRequest(BaseModel):
    pass

class CredentialActionRequest(BaseModel):
    name: str  # 从 filename 改为 name 以匹配数据库字段
    action: str  # "enable", "disable", "delete"

class UserLimitsUpdateRequest(BaseModel):
    name: str # 从 filename 改为 name
    gemini_2_5_pro_limit: Optional[int] = None
    total_limit: Optional[int] = None

# --- 认证依赖 ---

async def get_current_user(session_token: Optional[str] = Cookie(None)):
    """获取当前登录用户"""
    if not session_token:
        raise HTTPException(status_code=401, detail="未登录")
    user = await user_db.validate_session(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="会话已过期，请重新登录")
    return user

async def get_user_by_api_key(credentials = None):
    """通过API密钥获取用户信息"""
    if isinstance(credentials, str):
        api_key = credentials
    elif hasattr(credentials, 'credentials'):
        api_key = credentials.credentials
    else:
        raise HTTPException(status_code=401, detail="需要API密钥")
    user = await user_db.get_user_by_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="无效的API密钥")
    return user

async def get_user_by_api_key_dependency(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """通过API密钥获取用户信息（用于FastAPI依赖注入）"""
    return await get_user_by_api_key(credentials)

# --- 用户账户路由 ---

# 公开注册API已禁用，改为使用Bot API进行注册
# @router.post("/register")
# async def register_user(request: UserRegisterRequest):
#     """用户注册"""
#     try:
#         result = await user_db.create_user(request.username, request.password)
#         if result["success"]:
#             return {"success": True, "message": "注册成功", "username": result["username"], "api_key": result["api_key"]}
#         else:
#             raise HTTPException(status_code=400, detail=result["error"])
#     except Exception as e:
#         log.error(f"用户注册失败: {e}")
#         raise HTTPException(status_code=500, detail="注册时发生错误")

@router.post("/login")
async def login_user(request: UserLoginRequest, response: Response):
    """用户登录"""
    try:
        auth_result = await user_db.authenticate_user(request.username, request.password)
        if auth_result["success"]:
            session_token = await user_db.create_session(auth_result["user_id"])
            if session_token:
                response.set_cookie(key="session_token", value=session_token, max_age=24 * 60 * 60, httponly=True, secure=False, samesite="lax")
                return {"success": True, "message": "登录成功", "username": auth_result["username"], "api_key": auth_result["api_key"]}
            else:
                raise HTTPException(status_code=500, detail="创建会话失败")
        else:
            raise HTTPException(status_code=401, detail=auth_result["error"])
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"用户登录失败: {e}")
        raise HTTPException(status_code=500, detail="登录时发生错误")

@router.post("/logout")
async def logout_user(response: Response, session_token: Optional[str] = Cookie(None)):
    """用户登出"""
    if session_token:
        await user_db.invalidate_session(session_token)
    response.delete_cookie(key="session_token")
    return {"success": True, "message": "登出成功"}

@router.get("/user/profile")
async def get_user_profile(current_user = Depends(get_current_user)):
    """获取用户信息"""
    # 确保current_user不是协程对象
    if hasattr(current_user, "__await__"):
        current_user = await current_user
    return {"success": True, "username": current_user["username"], "api_key": current_user["api_key"]}

@router.post("/user/regenerate-api-key")
async def regenerate_user_api_key(request: RegenerateApiKeyRequest, current_user = Depends(get_current_user)):
    """重新生成API密钥"""
    # 确保current_user不是协程对象
    if hasattr(current_user, "__await__"):
        current_user = await current_user
    result = await user_db.regenerate_api_key(current_user["id"])
    if result["success"]:
        return {"success": True, "message": "API密钥重新生成成功", "api_key": result["api_key"]}
    else:
        raise HTTPException(status_code=400, detail=result["error"])

@router.get("/user/check-auth")
async def check_user_auth(current_user = Depends(get_current_user)):
    """检查用户认证状态"""
    # 确保current_user不是协程对象
    if hasattr(current_user, "__await__"):
        current_user = await current_user
    return {"success": True, "authenticated": True, "username": current_user["username"]}

@router.get("/user/validate-api-key")
async def validate_api_key(user: dict = Depends(get_user_by_api_key_dependency)):
    """验证API密钥"""
    return {"success": True, "valid": True, "username": user["username"], "user_id": user["id"]}

# --- 用户凭证和统计路由 (重构后) ---

@router.post("/user/credentials/upload")
async def upload_user_credentials(files: List[UploadFile] = File(...), current_user: dict = Depends(get_current_user)):
    """上传用户凭证文件"""
    cred_mgr = UserCredentialManager(current_user["username"])
    await cred_mgr.initialize()
    
    try:
        results = []
        existing_creds = await cred_mgr.get_all_credentials_status()
        if len(existing_creds) + len(files) > 10:
            raise HTTPException(status_code=400, detail=f"凭证总数不能超过10个（当前{len(existing_creds)}个）")

        for file in files:
            if not file.filename.endswith('.json'):
                results.append({"filename": file.filename, "success": False, "error": "只支持JSON文件"})
                continue
            
            content = await file.read()
            if len(content) > 4 * 1024: # 增加到4KB
                results.append({"filename": file.filename, "success": False, "error": "文件大小不能超过4KB"})
                continue

            try:
                creds_data = json.loads(content.decode('utf-8'))
                if 'client_id' not in creds_data or 'client_secret' not in creds_data:
                    raise ValueError("缺少 'client_id' 或 'client_secret' 字段")
                
                timestamp = int(time.time())
                unique_name = f"{os.path.splitext(file.filename)[0]}-{timestamp}.json"
                
                success = await cred_mgr.add_credential(unique_name, creds_data)
                if success:
                    results.append({"filename": file.filename, "success": True, "saved_as": unique_name})
                else:
                    results.append({"filename": file.filename, "success": False, "error": "添加凭证失败，可能名称已存在"})

            except (json.JSONDecodeError, ValueError) as e:
                results.append({"filename": file.filename, "success": False, "error": f"文件内容无效: {e}"})
            except Exception as e:
                results.append({"filename": file.filename, "success": False, "error": str(e)})

        return {"success": True, "results": results}
    finally:
        await cred_mgr.close()

@router.post("/user/credentials/action")
async def credential_action(request: CredentialActionRequest, current_user = Depends(get_current_user)):
    """凭证文件操作（启用/禁用/删除）"""
    # 确保current_user不是协程对象
    if hasattr(current_user, "__await__"):
        current_user = await current_user
    cred_mgr = UserCredentialManager(current_user["username"])
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
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=404, detail="操作失败，凭证未找到或发生错误")
    finally:
        await cred_mgr.close()

@router.get("/user/credentials/{cred_name}/content")
async def get_credential_content(cred_name: str, current_user: dict = Depends(get_current_user)):
    """获取凭证文件内容（隐藏敏感信息）"""
    cred_mgr = UserCredentialManager(current_user["username"])
    await cred_mgr.initialize()
    
    try:
        all_creds = await cred_mgr.get_all_credentials_status()
        target_cred = next((c for c in all_creds if c['name'] == cred_name), None)

        if not target_cred:
            raise HTTPException(status_code=404, detail="凭证文件不存在")

        content = json.loads(target_cred['credential_data'])
        sensitive_fields = ['refresh_token', 'access_token', 'token', 'client_secret', 'private_key']
        for field in sensitive_fields:
            if field in content:
                content[field] = "***HIDDEN***"
        
        return {"success": True, "content": content}
    finally:
        await cred_mgr.close()

@router.get("/user/dashboard-data")
async def get_user_dashboard_data(current_user = Depends(get_current_user)):
    """获取用户的综合仪表盘数据，包括凭证列表、使用统计和聚合统计"""
    # 添加详细日志
    log.info(f"开始获取仪表盘数据，current_user类型: {type(current_user)}")
    log.info(f"current_user内容: {current_user}")
    
    # 确保current_user不是协程对象
    if hasattr(current_user, "__await__"):
        log.info("current_user是协程对象，等待解析")
        current_user = await current_user
        log.info(f"解析后的current_user: {current_user}")
    
    log.info(f"用户名: {current_user.get('username', '未知')}")
    cred_mgr = UserCredentialManager(current_user["username"])
    try:
        log.info("初始化凭证管理器")
        await cred_mgr.initialize()
        log.info("开始获取凭证状态")
        # get_all_credentials_status 应该返回所有需要的字段
        all_creds_data = await cred_mgr.get_all_credentials_status()
        log.info(f"获取到 {len(all_creds_data)} 个凭证")
        
        enhanced_credentials = []
        summary_total_gemini_calls = 0
        summary_total_calls = 0

        for cred in all_creds_data:
            summary_total_gemini_calls += cred.get("gemini_25_pro_calls", 0)
            summary_total_calls += cred.get("total_calls", 0)

            # 构建扁平化的数据结构，移除嵌套的 usage_stats
            # 计算下一个UTC 07:00的时间
            import datetime
            now = datetime.datetime.utcnow()
            next_reset = now.replace(hour=7, minute=0, second=0, microsecond=0)
            if now.hour >= 7:  # 如果当前时间已经过了UTC 07:00，则设置为明天的UTC 07:00
                next_reset += datetime.timedelta(days=1)
            
            # 格式化为与last_success_at一致的格式（带时区信息的ISO格式）
            next_reset_formatted = next_reset.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
            
            enhanced_credentials.append({
                "name": cred["name"],
                "project_id": cred.get("project_id"),
                "is_active": bool(cred["is_active"]),
                "created_at": cred["created_at"],
                "last_success_at": cred.get("last_success_at"),
                "next_reset_at": next_reset_formatted,  # <-- 修改：使用与last_success_at一致的格式
                "error_codes": json.loads(cred["error_codes"]) if cred.get("error_codes") else [],
                
                # --- 扁平化的统计数据 ---
                "gemini_25_pro_calls": cred.get("gemini_25_pro_calls", 0),
                "total_calls": cred.get("total_calls", 0),
                "daily_limit_gemini_25_pro": cred.get("daily_limit_gemini_25_pro", 100),
                "daily_limit_total": cred.get("daily_limit_total", 1500),
            })

        # 使用前端期望的键名构建 summary 对象
        summary = {
            "username": current_user["username"],
            "total_files": len(enhanced_credentials),
            "gemini_25_pro_calls": summary_total_gemini_calls, # <-- 修改：匹配前端键名
            "total_calls": summary_total_calls,           # <-- 修改：匹配前端键名
        }

        # 按创建时间降序排序
        enhanced_credentials.sort(key=lambda x: x["created_at"], reverse=True)

        return {
            "credentials": enhanced_credentials,
            "summary": summary
        }
    except Exception as e:
        # 添加更健壮的错误处理
        log.error(f"获取仪表盘数据时出错: {str(e)}")
        log.error(f"错误类型: {type(e)}")
        import traceback
        log.error(f"错误堆栈: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"获取仪表盘数据时出错: {str(e)}")
    finally:
        # 确保数据库连接总是被关闭
        log.info("关闭凭证管理器")
        await cred_mgr.close()

@router.post("/user/usage/update-limits")
async def update_user_limits(request: UserLimitsUpdateRequest, current_user = Depends(get_current_user)):
    """更新用户凭证文件的每日使用限制"""
    # 确保current_user不是协程对象
    if hasattr(current_user, "__await__"):
        current_user = await current_user
    cred_mgr = UserCredentialManager(current_user["username"])
    await cred_mgr.initialize()

    try:
        all_creds = await cred_mgr.get_all_credentials_status()
        target_cred = next((c for c in all_creds if c['name'] == request.name), None)

        if not target_cred:
            raise HTTPException(status_code=404, detail="该凭证文件不存在")
        
        update_data = {}
        if request.gemini_2_5_pro_limit is not None:
            update_data['daily_limit_gemini_25_pro'] = request.gemini_2_5_pro_limit
        if request.total_limit is not None:
            update_data['daily_limit_total'] = request.total_limit
        
        if not update_data:
            return {"success": True, "message": "未提供任何要更新的限制"}

        success = await user_db.update_credential(target_cred['id'], update_data)
        if success:
            return {"success": True, "message": f"已更新 {request.name} 的使用限制"}
        else:
            raise HTTPException(status_code=500, detail="更新数据库时发生错误")
    finally:
        await cred_mgr.close()
