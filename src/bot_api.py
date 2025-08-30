"""
Bot API Module - Provides API endpoints for bot integration
提供给Discord Bot等机器人使用的API接口
"""
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional
import config
from log import logger
from .user_database import user_db

router = APIRouter()

# --- 请求模型 ---
class BotUserRegisterRequest(BaseModel):
    username: str
    password: str
    discord_id: Optional[str] = None
    
class BotChangePasswordRequest(BaseModel):
    username: str
    new_password: str
    
# --- 认证依赖 ---
async def verify_bot_api_key(x_bot_api_key: str = Header(None)):
    """验证Bot API Key"""
    if not x_bot_api_key:
        raise HTTPException(status_code=401, detail="缺少API密钥")
    
    valid_api_key = config.get_bot_api_key()
    if not valid_api_key:
        logger.error("Bot API Key未配置")
        raise HTTPException(status_code=500, detail="服务器未正确配置Bot API Key")
    
    if x_bot_api_key != valid_api_key:
        logger.warning(f"Bot API Key验证失败")
        raise HTTPException(status_code=401, detail="无效的API密钥")
    
    return True

# --- API端点 ---
@router.post("/bot/register", tags=["Bot API"])
async def bot_register_user(
    request: BotUserRegisterRequest, 
    _: bool = Depends(verify_bot_api_key)
):
    """Bot专用用户注册API"""
    try:
        # 检查用户名是否已存在
        existing_user = await user_db.get_user_by_username(request.username)
        if existing_user:
            return {"success": False, "message": "用户名已存在"}
        
        # 注册新用户
        result = await user_db.create_user(
            username=request.username,
            password=request.password
        )
        
        # 检查注册结果
        if not result.get("success"):
            return {"success": False, "message": result.get("error", "注册失败")}
            
        user_id = result.get("user_id")
        
        logger.info(f"Bot API成功注册用户: {request.username}")
        return {
            "success": True,
            "message": "用户注册成功",
            "user_id": user_id
        }
    except Exception as e:
        logger.error(f"Bot API注册用户失败: {str(e)}")
        return {"success": False, "message": f"注册失败: {str(e)}"}
        
@router.post("/bot/change_password", tags=["Bot API"])
async def bot_change_password(
    request: BotChangePasswordRequest,
    _: bool = Depends(verify_bot_api_key)
):
    """Bot专用修改用户密码API"""
    try:
        # 检查用户是否存在
        user = await user_db.get_user_by_username(request.username)
        if not user:
            return {"success": False, "message": "用户不存在"}
        
        # 验证新密码长度
        if len(request.new_password) < 6:
            return {"success": False, "message": "密码长度至少6位"}
        
        # 更新密码
        result = await user_db.update_user_password(user["id"], request.new_password)
        
        if not result.get("success"):
            return {"success": False, "message": result.get("error", "修改密码失败")}
        
        logger.info(f"Bot API成功修改用户密码: {request.username}")
        return {
            "success": True,
            "message": "密码修改成功"
        }
    except Exception as e:
        logger.error(f"Bot API修改密码失败: {str(e)}")
        return {"success": False, "message": f"修改密码失败: {str(e)}"}