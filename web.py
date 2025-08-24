"""
Main Web Integration - Integrates all routers and modules
根据修改指导要求，负责集合上述router并开启主服务
"""
import os
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from config import get_config_value

# Import all routers
from src.openai_router import router as openai_router
from src.gemini_router import router as gemini_router
from src.web_routes import router as web_router

# Import managers and utilities
from src.credential_manager import CredentialManager
from config import get_config_value
from log import log

# 全局凭证管理器
global_credential_manager = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    global global_credential_manager
    
    log.info("启动 GCLI2API 主服务")
    
    # 初始化全局凭证管理器
    try:
        global_credential_manager = CredentialManager()
        await global_credential_manager.initialize()
        log.info("凭证管理器初始化成功")
    except Exception as e:
        log.error(f"凭证管理器初始化失败: {e}")
        global_credential_manager = None
    
    # OAuth回调服务器将在需要时按需启动
    
    yield
    
    # 清理资源
    if global_credential_manager:
        await global_credential_manager.close()
    
    try:
        from src.auth_api import stop_oauth_server
        stop_oauth_server()
        log.info("OAuth回调服务器已停止")
    except Exception as e:
        log.warning(f"停止OAuth回调服务器时出错: {e}")
    
    log.info("GCLI2API 主服务已停止")

# 创建FastAPI应用
app = FastAPI(
    title="GCLI2API",
    description="Gemini API proxy with OpenAI compatibility",
    version="2.0.0",
    lifespan=lifespan
)

# CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载路由器
# OpenAI兼容路由 - 处理OpenAI格式请求
app.include_router(
    openai_router,
    prefix="",
    tags=["OpenAI Compatible API"]
)

# Gemini原生路由 - 处理Gemini格式请求
app.include_router(
    gemini_router,
    prefix="",
    tags=["Gemini Native API"]
)

# Web路由 - 包含认证、凭证管理和控制面板功能
app.include_router(
    web_router,
    prefix="",
    tags=["Web Interface"]
)

@app.get("/")
async def root():
    """根路径 - 服务状态信息"""
    return {
        "service": "GCLI2API",
        "version": "2.0.0",
        "status": "running",
        "endpoints": {
            "openai_api": "/v1/chat/completions",
            "openai_models": "/v1/models", 
            "gemini_api": "/v1/models/{model}:generateContent",
            "gemini_streaming": "/v1/models/{model}:streamGenerateContent",
            "gemini_models": "/v1/models",
            "control_panel": "/panel",
            "auth_panel": "/auth"
        },
        "docs": "/docs",
        "credential_manager": "initialized" if global_credential_manager else "failed"
    }

def get_credential_manager():
    """获取全局凭证管理器实例"""
    return global_credential_manager

# 导出给其他模块使用
__all__ = ['app', 'get_credential_manager']

if __name__ == "__main__":
    from hypercorn.asyncio import serve
    from hypercorn.config import Config
    
    # 从环境变量或配置获取端口
    port = int(get_config_value("port", "7861", "PORT"))
    host = get_config_value("host", "0.0.0.0", "HOST")
    
    print("=" * 60)
    print("🚀 启动 GCLI2API 2.0 - 模块化架构")
    print("=" * 60)
    print(f"📍 服务地址: http://{host}:{port}")
    print(f"📖 API文档: http://{host}:{port}/docs")
    print(f"🔧 控制面板: http://{host}:{port}/panel")
    print("=" * 60)
    print("🔗 API端点:")
    print(f"   OpenAI兼容: http://{host}:{port}/v1")
    print(f"   Gemini原生: http://{host}:{port}")
    print("=" * 60)
    print("⚡ 功能特性:")
    print("   ✓ OpenAI格式兼容")
    print("   ✓ Gemini原生格式")  
    print("   ✓ 429错误自动重试")
    print("   ✓ 反截断完整输出")
    print("   ✓ 凭证自动轮换")
    print("   ✓ 实时管理面板")
    print("=" * 60)

    # 配置hypercorn
    config = Config()
    config.bind = [f"{host}:{port}"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.loglevel = "INFO"
    config.use_colors = True

    config = Config()
    config.bind = [f"{host}:{port}"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.loglevel = "INFO"

    asyncio.run(serve(app, config))