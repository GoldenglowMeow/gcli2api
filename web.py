"""
Main Web Integration - Integrates all routers and modules
根据修改指导要求，负责集合上述router并开启主服务
"""
import asyncio
import signal
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import all routers
from src.openai_router import router as openai_router
from src.gemini_router import router as gemini_router
from src.web_routes import router as web_router
from src.user_routes import router as user_router
from src.bot_api import router as bot_router

# Import utilities
from config import get_server_host, get_server_port
from log import log

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    log.info("启动 GCLI2API 主服务")

    # 初始化用户数据库
    try:
        from src.user_database import user_db
        await user_db.init_database()
        log.info("用户数据库初始化完成")
    except Exception as e:
        log.error(f"初始化用户数据库失败: {e}")

    # 自动从环境变量加载凭证（如果有的话）
    try:
        from src.auth_api import auto_load_env_credentials_on_startup
        auto_load_env_credentials_on_startup()
    except Exception as e:
        log.error(f"自动加载环境变量凭证失败: {e}")

    # OAuth回调服务器将在需要时按需启动

    yield

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

# 用户路由 - 处理用户注册、登录和凭证管理
app.include_router(
    user_router,
    prefix="",
    tags=["User Management"]
)

# Bot API路由 - 处理Bot专用API请求
app.include_router(
    bot_router,
    prefix="",
    tags=["Bot API"]
)

# 导出给其他模块使用
__all__ = ['app']

if __name__ == "__main__":
    from hypercorn.asyncio import serve
    from hypercorn.config import Config
    import platform
    
    # 从环境变量或配置获取端口和主机
    port = get_server_port()
    host = get_server_host()
    
    log.info("=" * 60)
    log.info("🚀 启动 GCLI2API")
    log.info("=" * 60)
    log.info(f"📍 服务地址: http://127.0.0.1:{port}")
    log.info(f"🔧 控制面板: http://127.0.0.1:{port}/auth")
    log.info("=" * 60)
    log.info("🔗 API端点:")
    log.info(f"   OpenAI兼容: http://127.0.0.1:{port}/v1")
    log.info(f"   Gemini原生: http://127.0.0.1:{port}")
    log.info("=" * 60)
    log.info("⚡ 功能特性:")
    log.info("   ✓ OpenAI格式兼容")
    log.info("   ✓ Gemini原生格式")
    log.info("   ✓ 429错误自动重试")
    log.info("   ✓ 反截断完整输出")
    log.info("   ✓ 凭证自动轮换")
    log.info("   ✓ 实时管理面板")
    log.info("=" * 60)

    # 配置hypercorn
    config = Config()
    config.bind = [f"{host}:{port}"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.loglevel = "INFO"
    config.use_colors = True

    # 创建一个关闭事件
    shutdown_event = asyncio.Event()
    
    # Windows系统不支持loop.add_signal_handler，使用不同的方法处理信号
    if platform.system() == "Windows":
        # Windows下使用简单的asyncio.run，并在KeyboardInterrupt中处理关闭
        try:
            asyncio.run(serve(app, config))
        except KeyboardInterrupt:
            log.info("接收到键盘中断，正在关闭服务...")
        finally:
            log.info("服务已安全关闭")
    else:
        # 非Windows系统使用事件循环和信号处理
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # 定义信号处理函数
        def signal_handler():
            log.info("接收到关闭信号，正在优雅关闭服务...")
            shutdown_event.set()
        
        # 注册信号处理（仅在非Windows系统上）
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
        
        # 启动服务器
        server = loop.create_task(serve(app, config, shutdown_trigger=shutdown_event.wait))
        
        try:
            # 运行直到收到关闭信号
            loop.run_until_complete(server)
        except KeyboardInterrupt:
            log.info("接收到键盘中断，正在关闭服务...")
        finally:
            # 确保所有任务都被正确关闭
            pending = asyncio.all_tasks(loop=loop)
            for task in pending:
                task.cancel()
            
            # 等待所有任务完成
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            
            # 关闭事件循环
            loop.close()
            log.info("服务已安全关闭")
            
            # 确保进程正常退出
            sys.exit(0)