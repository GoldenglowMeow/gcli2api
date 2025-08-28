from fastapi import APIRouter, HTTPException, Depends, Cookie, Response, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import time
from log import log
from .user_database import user_db
from .user_aware_credential_manager import UserCredentialManager
from .usage_stats import get_usage_stats as usage_stats_module, get_aggregated_stats as aggregated_stats_module, get_usage_stats_instance

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

@router.post("/register")
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

@router.post("/login")
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

@router.post("/logout")
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
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()
        
        # 检查文件总数限制
        existing_files = cred_mgr.get_user_credential_files()
        if len(existing_files) + len(files) > 10:
            raise HTTPException(
                status_code=400, 
                detail=f"凭证总数不能超过10个（当前{len(existing_files)}个，上传{len(files)}个）"
            )

        for file in files:
            # 检查文件类型
            if not file.filename.endswith('.json'):
                results.append({
                    "filename": file.filename,
                    "success": False,
                    "error": "只支持JSON格式的凭证文件"
                })
                continue
                
            # 检查文件大小限制 (2KB)
            content = await file.read()
            if len(content) > 2 * 1024:
                results.append({
                    "filename": file.filename,
                    "success": False,
                    "error": "文件大小不能超过2KB"
                })
                continue

            try:
                # 已经读取了文件内容，直接使用
                file_content = content.decode('utf-8')

                # 验证JSON格式
                import json
                creds_data = json.loads(file_content)

                # 验证必要字段
                required_fields = ['client_id', 'client_secret']
                for field in required_fields:
                    if field not in creds_data:
                        results.append({
                            "filename": file.filename,
                            "success": False,
                            "error": f"缺少必要字段: {field}"
                        })
                        continue

                # 生成唯一文件名
                import time
                timestamp = int(time.time())
                base_name = file.filename.rsplit('.', 1)[0]
                filename = f"{base_name}-{timestamp}.json"

                # 保存凭证文件
                file_path = await cred_mgr.save_user_credential(filename, creds_data)

                results.append({
                    "filename": file.filename,
                    "success": True,
                    "saved_filename": filename
                })

            except json.JSONDecodeError:
                results.append({
                    "filename": file.filename,
                    "success": False,
                    "error": "无效的JSON格式"
                })
            except Exception as e:
                results.append({
                    "filename": file.filename,
                    "success": False,
                    "error": str(e)
                })

        await cred_mgr.close()
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
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()

        # 获取用户的凭证文件列表
        filenames = cred_mgr.get_user_credential_files()

        credentials = []
        for filename in filenames:
            # 获取文件状态
            cred_state = cred_mgr._get_cred_state(filename)
            is_enabled = not cred_state.get("disabled", False)

            # 获取文件信息
            import os
            user_dir = cred_mgr._user_credentials_dir
            file_path = os.path.join(user_dir, filename)

            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                file_mtime = os.path.getmtime(file_path)

                # 尝试读取project_id
                project_id = None
                try:
                    import json
                    with open(file_path, 'r', encoding='utf-8') as f:
                        cred_data = json.load(f)
                        project_id = cred_data.get('project_id')
                except Exception:
                    pass

                credentials.append({
                    "filename": filename,
                    "original_filename": filename,
                    "project_id": project_id,
                    "is_enabled": is_enabled,
                    "created_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_mtime)),
                    "last_used": cred_state.get("last_success"),
                    "file_exists": True,
                    "file_size": file_size
                })
            else:
                credentials.append({
                    "filename": filename,
                    "original_filename": filename,
                    "project_id": None,
                    "is_enabled": is_enabled,
                    "created_at": "未知",
                    "last_used": cred_state.get("last_success"),
                    "file_exists": False,
                    "file_size": 0
                })

        # 按文件修改时间排序（最新的在前）
        credentials.sort(key=lambda x: x["created_at"] if x["created_at"] != "未知" else "", reverse=True)

        await cred_mgr.close()
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
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()

        if request.action == "enable":
            await cred_mgr.set_cred_disabled(request.filename, False)
            result = {"success": True, "message": f"凭证文件已启用"}
        elif request.action == "disable":
            await cred_mgr.set_cred_disabled(request.filename, True)
            result = {"success": True, "message": f"凭证文件已禁用"}
        elif request.action == "delete":
            success = await cred_mgr.delete_user_credential(request.filename)
            if success:
                result = {"success": True, "message": f"凭证文件已删除"}
            else:
                result = {"success": False, "error": "删除失败"}
        else:
            await cred_mgr.close()
            raise HTTPException(status_code=400, detail="无效的操作类型")

        await cred_mgr.close()

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
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()

        content = await cred_mgr.get_user_credential_content(filename)

        await cred_mgr.close()

        if not content:
            raise HTTPException(status_code=404, detail="凭证文件不存在")

        return {
            "success": True,
            "content": content
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取凭证内容失败: {e}")
        raise HTTPException(status_code=500, detail="获取凭证内容时发生错误")

# 用户统计管理接口
@router.get("/user/usage/stats")
async def get_user_usage_stats(filename: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """获取用户的使用统计信息"""
    try:
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()

        user_filenames = cred_mgr.get_user_credential_files()
        await cred_mgr.close()

        if filename:
            # 检查文件是否属于该用户
            if filename not in user_filenames:
                raise HTTPException(status_code=404, detail="该凭证文件不存在")

            from .usage_stats import get_usage_stats
            stats = await get_usage_stats(filename)
        else:
            # 获取该用户所有凭证文件的统计
            all_stats = await usage_stats_module()
            stats = {}

            # 遍历用户的所有凭证文件，查找对应的统计数据
            for user_file in user_filenames:
                # 在所有统计中查找匹配文件名（常规文件名匹配）
                if user_file in all_stats:
                    stats[user_file] = all_stats[user_file]
                else:
                    # 尝试匹配完整的用户名/文件名路径
                    user_prefix = f"{current_user['username']}/"
                    full_path_key = user_prefix + user_file
                    if full_path_key in all_stats:
                        stats[user_file] = all_stats[full_path_key]

        return {
            "success": True,
            "data": stats
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取用户使用统计失败: {e}")
        raise HTTPException(status_code=500, detail="获取使用统计时发生错误")

@router.get("/user/usage/aggregated")
async def get_user_aggregated_stats(current_user: dict = Depends(get_current_user)):
    """获取用户的聚合使用统计信息"""
    try:
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()

        user_filenames = cred_mgr.get_user_credential_files()
        await cred_mgr.close()

        # 获取该用户所有凭证文件的统计并手动聚合
        from .usage_stats import get_usage_stats
        all_stats = await get_usage_stats()
        user_prefix = f"{current_user['username']}/"
        user_stats = {cred_filename: stat for cred_filename, stat in all_stats.items()
                     if cred_filename.startswith(user_prefix)
                     if cred_filename[len(user_prefix):] in user_filenames}

        # 手动聚合用户的统计数据
        total_gemini_calls = 0
        total_calls = 0
        total_files = len(user_stats)

        for filename, stats in user_stats.items():
            total_gemini_calls += stats.get("gemini_2_5_pro_calls", 0)
            total_calls += stats.get("total_calls", 0)

        return {
            "success": True,
            "data": {
                "total_files": total_files,
                "total_gemini_2_5_pro_calls": total_gemini_calls,
                "total_all_model_calls": total_calls
            }
        }

    except Exception as e:
        log.error(f"获取用户聚合统计失败: {e}")
        raise HTTPException(status_code=500, detail="获取聚合统计时发生错误")

@router.get("/user/usage/combined")
async def get_user_combined_stats(current_user: dict = Depends(get_current_user)):
    """获取用户的综合数据，包括凭证列表、使用统计和聚合统计"""
    try:
        # 1. 获取用户凭证文件列表
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()
        user_filenames = cred_mgr.get_user_credential_files()
        
        # 构建凭证列表（避免再次初始化）
        credentials_list = []
        import os, json
        user_dir = cred_mgr._user_credentials_dir
        for filename in user_filenames:
            # 获取文件状态
            cred_state = cred_mgr._get_cred_state(filename)
            is_enabled = not cred_state.get("disabled", False)

            # 获取文件信息
            file_path = os.path.join(user_dir, filename)
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                file_mtime = os.path.getmtime(file_path)

                # 尝试读取project_id
                project_id = None
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        cred_data = json.load(f)
                        project_id = cred_data.get('project_id')
                except Exception:
                    pass

                credentials_list.append({
                    "filename": filename,
                    "original_filename": filename,
                    "project_id": project_id,
                    "is_enabled": is_enabled,
                    "created_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_mtime)),
                    "last_used": cred_state.get("last_success"),
                    "file_exists": True,
                    "file_size": file_size
                })
            else:
                credentials_list.append({
                    "filename": filename,
                    "original_filename": filename,
                    "project_id": None,
                    "is_enabled": is_enabled,
                    "created_at": "未知",
                    "last_used": cred_state.get("last_success"),
                    "file_exists": False,
                    "file_size": 0
                })

        # 按文件修改时间排序（最新的在前）
        credentials_list.sort(key=lambda x: x["created_at"] if x["created_at"] != "未知" else "", reverse=True)
        
        # 2. 获取使用统计
        from .usage_stats import get_usage_stats
        all_stats = await get_usage_stats()
        stats = {}
        
        # 遍历用户的所有凭证文件，查找对应的统计数据
        for user_file in user_filenames:
            # 在所有统计中查找匹配文件名（常规文件名匹配）
            if user_file in all_stats:
                stats[user_file] = all_stats[user_file]
            else:
                # 尝试匹配完整的用户名/文件名路径
                user_prefix = f"{current_user['username']}/"
                full_path_key = user_prefix + user_file
                if full_path_key in all_stats:
                    stats[user_file] = all_stats[full_path_key]
        
        # 3. 获取聚合统计
        # 手动聚合用户的统计数据
        total_gemini_calls = 0
        total_calls = 0
        total_files = len(stats)
        
        for filename, file_stats in stats.items():
            total_gemini_calls += file_stats.get("gemini_2_5_pro_calls", 0)
            total_calls += file_stats.get("total_calls", 0)
        
        aggregated_data = {
            "total_files": total_files,
            "total_gemini_2_5_pro_calls": total_gemini_calls,
            "total_all_model_calls": total_calls
        }
        
        await cred_mgr.close()
        
        # 返回优化后的综合数据结构
        # 将统计数据合并到凭证信息中
        enhanced_credentials = []
        for cred in credentials_list:
            filename = cred["filename"]
            cred_stats = stats.get(filename, {})
            
            enhanced_cred = {
                **cred,  # 保留原有凭证信息
                "usage_stats": {
                    "gemini_2_5_pro_calls": cred_stats.get("gemini_2_5_pro_calls", 0),
                    "total_calls": cred_stats.get("total_calls", 0),
                    "daily_limit_gemini_2_5_pro": cred_stats.get("daily_limit_gemini_2_5_pro", 0),
                    "daily_limit_total": cred_stats.get("daily_limit_total", 0),
                    "next_reset_time": cred_stats.get("next_reset_time", None)
                }
            }
            enhanced_credentials.append(enhanced_cred)
            
        return {
            "success": True,
            "credentials": enhanced_credentials,
            "summary": aggregated_data
        }
    except Exception as e:
        log.error(f"获取用户综合数据失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取用户综合数据失败")
        user_prefix = f"{current_user['username']}/"
        user_stats = {}

        # 遍历用户的所有凭证文件，查找对应的统计数据
        for user_file in user_filenames:
            # 在所有统计中查找匹配文件名（常规文件名匹配）
            if user_file in all_stats:
                user_stats[user_file] = all_stats[user_file]
            else:
                # 尝试匹配完整的用户名/文件名路径
                full_path_key = user_prefix + user_file
                if full_path_key in all_stats:
                    user_stats[user_file] = all_stats[full_path_key]

        # 3. 计算聚合统计数据
        total_gemini_calls = 0
        total_calls = 0
        total_files = len(user_stats)

        for filename, stats in user_stats.items():
            total_gemini_calls += stats.get("gemini_2_5_pro_calls", 0)
            total_calls += stats.get("total_calls", 0)

        # 4. 返回综合数据
        return {
            "success": True,
            "data": {
                "credentials": credentials_list,
                "stats": user_stats,
                "aggregated": {
                    "total_files": total_files,
                    "total_gemini_2_5_pro_calls": total_gemini_calls,
                    "total_all_model_calls": total_calls
                }
            }
        }

    except Exception as e:
        log.error(f"获取用户综合数据失败: {e}")
        raise HTTPException(status_code=500, detail="获取综合数据时发生错误")

class UserLimitsUpdateRequest(BaseModel):
    filename: str
    gemini_2_5_pro_limit: Optional[int] = None
    total_limit: Optional[int] = None

@router.post("/user/usage/update-limits")
async def update_user_limits(request: UserLimitsUpdateRequest, current_user: dict = Depends(get_current_user)):
    """更新用户凭证文件的每日使用限制"""
    try:
        cred_mgr = UserCredentialManager(current_user["username"])
        await cred_mgr.initialize()

        user_filenames = cred_mgr.get_user_credential_files()
        await cred_mgr.close()

        if request.filename not in user_filenames:
            raise HTTPException(status_code=404, detail="该凭证文件不存在")

        # 使用文件名标识凭证文件（与统计系统保持一致）
        full_filename = request.filename

        stats_instance = await get_usage_stats_instance()
        await stats_instance.update_daily_limits(
            filename=full_filename,
            gemini_2_5_pro_limit=request.gemini_2_5_pro_limit,
            total_limit=request.total_limit
        )

        return {
            "success": True,
            "message": f"已更新 {request.filename} 的使用限制"
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"更新用户限制失败: {e}")
        raise HTTPException(status_code=500, detail="更新使用限制时发生错误")