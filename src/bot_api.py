"""
Bot API Module - Provides API endpoints for bot integration
提供给Discord Bot等机器人使用的API接口
"""
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional
import config
from log import log
from .user_database import user_db

router = APIRouter()

# --- 请求模型 ---
class BotUserRegisterRequest(BaseModel):
    username: str
    password: str
    discord_id: Optional[str] = None
    
# --- 认证依赖 ---
async def verify_bot_api_key(x_bot_api_key: str = Header(None)):
    """验证Bot API Key"""
    if not x_bot_api_key:
        raise HTTPException(status_code=401, detail="缺少API密钥")
    
    valid_api_key = config.get_bot_api_key()
    if not valid_api_key:
        log.error("Bot API Key未配置")
        raise HTTPException(status_code=500, detail="服务器未正确配置Bot API Key")
    
    if x_bot_api_key != valid_api_key:
        log.warning(f"Bot API Key验证失败")
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
        user_id = await user_db.create_user(
            username=request.username,
            password=request.password,
            discord_id=request.discord_id
        )
        
        log.info(f"Bot API成功注册用户: {request.username}")
        return {
            "success": True,
            "message": "用户注册成功",
            "user_id": user_id
        }
    except Exception as e:
        log.error(f"Bot API注册用户失败: {str(e)}")
        return {"success": False, "message": f"注册失败: {str(e)}"}