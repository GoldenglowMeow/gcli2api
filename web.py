import os
import json
import asyncio
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask
from dotenv import load_dotenv

from log import log
from models import Model, ModelList, ChatCompletionRequest
from geminicli.client import GeminiCLIClient
from geminicli.web_routes import router as geminicli_router

load_dotenv()

# 认证配置
PASSWORD = os.getenv("PASSWORD", "pwd")

# 全局变量
geminicli_client = None

security = HTTPBearer()

def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    if token != PASSWORD:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="密码错误")
    return token

async def fake_stream_response(request_data: ChatCompletionRequest):
    """处理假流式响应"""
    async def stream_generator():
        try:
            # 发送心跳
            heartbeat = {
                "choices": [{
                    "index": 0,
                    "delta": {"role": "assistant", "content": ""},
                    "finish_reason": None
                }]
            }
            yield f"data: {json.dumps(heartbeat)}\n\n".encode()
            await asyncio.sleep(0.1)
            
            # 调用后端
            task = asyncio.create_task(geminicli_client.chat_completion(request_data))
            
            # 等待完成，期间发送心跳
            while not task.done():
                await asyncio.sleep(5)
                if not task.done():
                    yield f"data: {json.dumps(heartbeat)}\n\n".encode()
            
            # 处理结果
            result = await task
            if hasattr(result, "body"):
                body_str = result.body.decode() if isinstance(result.body, bytes) else str(result.body)
            elif isinstance(result, dict):
                body_str = json.dumps(result)
            else:
                body_str = str(result)
            
            try:
                response_data = json.loads(body_str)
                if "choices" in response_data and response_data["choices"]:
                    content = response_data["choices"][0].get("message", {}).get("content", "")
                    content_chunk = {
                        "choices": [{
                            "index": 0,
                            "delta": {"role": "assistant", "content": content},
                            "finish_reason": "stop"
                        }]
                    }
                    yield f"data: {json.dumps(content_chunk)}\n\n".encode()
                else:
                    yield f"data: {body_str}\n\n".encode()
            except json.JSONDecodeError:
                error_chunk = {
                    "choices": [{
                        "index": 0,
                        "delta": {"role": "assistant", "content": body_str},
                        "finish_reason": "stop"
                    }]
                }
                yield f"data: {json.dumps(error_chunk)}\n\n".encode()
            
            yield "data: [DONE]\n\n".encode()
        except Exception as e:
            log('error', f"假流式错误: {e}")
            yield "data: [DONE]\n\n".encode()

    response = StreamingResponse(stream_generator(), media_type="text/event-stream")
    response.background = BackgroundTask(lambda: asyncio.run(response.body_iterator.aclose()))
    return response

@asynccontextmanager
async def lifespan(app: FastAPI):
    global geminicli_client
    log('info', "启动应用")

    try:
        geminicli_client = GeminiCLIClient()
        await geminicli_client.initialize()
    except Exception as e:
        log('error', f"GeminiCLIClient 初始化失败: {e}")
        geminicli_client = None

    yield
    
    if geminicli_client:
        await geminicli_client.close()

app = FastAPI(lifespan=lifespan)
app.include_router(geminicli_router)

@lru_cache()
def get_model_list():
    models = [
        "gemini-2.5-pro-preview-06-05",
        "gemini-2.5-pro-preview-06-05-假流式",
        "gemini-2.5-pro",
        "gemini-2.5-pro-假流式",
        "gemini-2.5-pro-preview-05-06",
        "gemini-2.5-pro-preview-05-06-假流式"
    ]
    return ModelList(data=[Model(id=m) for m in models])

@app.get("/v1/models", response_model=ModelList)
async def list_models():
    response = JSONResponse(content=get_model_list().model_dump())
    return response

@app.post("/v1/chat/completions")
async def chat_completions(
    request_data: ChatCompletionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = authenticate(credentials)
    
    # 健康检查
    if (len(request_data.messages) == 1 and 
        getattr(request_data.messages[0], "role", None) == "user" and
        getattr(request_data.messages[0], "content", None) == "Hi"):
        return JSONResponse(content={
            "choices": [{"delta": {"role": "assistant", "content": "公益站正常工作中"}}]
        })
    
    # 限制max_tokens
    if getattr(request_data, "max_tokens", None) is not None and request_data.max_tokens > 65535:
        request_data.max_tokens = 65535
        
    # 覆写 top_k 为 64（无论是否提供该参数）
    setattr(request_data, "top_k", 64)

    # 过滤空消息，支持文本和图片消息
    filtered_messages = []
    for m in request_data.messages:
        content = getattr(m, "content", None)
        if content:
            # 支持字符串类型的文本消息
            if isinstance(content, str) and content.strip():
                filtered_messages.append(m)
            # 支持列表类型的多模态消息（包含图片）
            elif isinstance(content, list) and len(content) > 0:
                # 检查是否有有效的内容（文本或图片）
                has_valid_content = False
                for part in content:
                    if isinstance(part, dict):
                        # 文本部分
                        if part.get("type") == "text" and part.get("text", "").strip():
                            has_valid_content = True
                            break
                        # 图片部分
                        elif part.get("type") == "image_url" and part.get("image_url", {}).get("url"):
                            has_valid_content = True
                            break
                if has_valid_content:
                    filtered_messages.append(m)
    
    request_data.messages = filtered_messages
    
    # 处理模型
    model = request_data.model
    if model.endswith("-假流式"):
        real_model = model.replace("-假流式", "")
    else:
        real_model = model
    
    request_data.model = real_model

    # 假流式处理
    if model.endswith("-假流式") and getattr(request_data, "stream", False):
        request_data.stream = False
        return await fake_stream_response(request_data)
    
    # 调用GeminiCLI客户端
    return await geminicli_client.chat_completion(request_data)


if __name__ == "__main__":
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    print("启动配置:")
    print(f"  GeminiCLI客户端: 启用")
    print("API地址 http://127.0.0.1:7861/v1")
    print("OAuth认证管理地址  http://127.0.0.1:7861/auth")
    print("默认密码 pwd")
    print("使用PASSWORD环境变量来设置密码")

    config = Config()
    config.bind = ["0.0.0.0:7861"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.loglevel = "INFO"
    
    asyncio.run(serve(app, config))