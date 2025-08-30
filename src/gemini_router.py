"""
Gemini Router - Handles native Gemini format API requests
处理原生Gemini格式请求的路由模块
"""
import json
from contextlib import asynccontextmanager

from fastapi import APIRouter, HTTPException, Depends, Request, Path, Query, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, StreamingResponse
from typing import Optional

from .google_api_client import send_gemini_request, build_gemini_payload_from_native
from .user_aware_credential_manager import UserCredentialManager
from .user_routes import get_user_by_api_key
from config import get_config_value, get_available_models, is_fake_streaming_model, is_anti_truncation_model, get_base_model_from_feature_model, get_anti_truncation_max_attempts
from .anti_truncation import apply_anti_truncation_to_stream
from config import get_base_model_name
from log import logger

# 创建路由器
router = APIRouter()
security = HTTPBearer()

# 用户凭证管理器实例缓存
user_credential_managers = {}

@asynccontextmanager
async def get_user_credential_manager(username: str):
    """获取用户特定的凭证管理器实例（使用单例模式）"""
    # 使用UserCredentialManager的单例模式
    user_cred_mgr = await UserCredentialManager.get_instance(username)
    await user_cred_mgr.initialize()
    yield user_cred_mgr


async def cleanup_user_credential_managers():
    """清理用户凭证管理器实例缓存 - 保留但不再需要，因为使用了单例模式"""
    # 单例模式下不再需要手动清理，但保留此函数以兼容现有代码
    logger.info("使用单例模式，不需要手动清理凭证管理器实例")



async def authenticate_gemini_flexible(
    request: Request,
    x_goog_api_key: Optional[str] = Header(None, alias="x-goog-api-key"),
    key: Optional[str] = Query(None),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(lambda: None)
) -> dict:
    """简单验证：只检查是否有认证令牌"""
    
    token = None
    
    # 尝试从URL参数key获取（Google官方标准方式）
    if key:
        logger.debug(f"Using URL parameter key authentication")
        token = key
    
    # 尝试从Authorization头获取（兼容旧方式）
    if not token:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]  # 移除 "Bearer " 前缀
            logger.debug(f"Using Bearer token authentication")
    
    # 尝试从x-goog-api-key头获取（新标准方式）
    if not token and x_goog_api_key:
        logger.debug(f"Using x-goog-api-key authentication")
        token = x_goog_api_key
    
    if not token:
        logger.error(f"No authentication token found. Headers: {dict(request.headers)}, Query params: key={key}")
        raise HTTPException(
            status_code=400,
            detail="缺少认证信息。请使用'key'URL参数、'x-goog-api-key'请求头或'Authorization: Bearer <token>'提供gcli2api密钥"
        )
    
    # 完全移除用户身份识别，只返回令牌
    return {"token": token}

@router.get("/v1/v1beta/models")
@router.get("/v1/v1/models")
@router.get("/v1beta/models")
@router.get("/v1/models")
async def list_gemini_models():
    """返回Gemini格式的模型列表"""
    models = get_available_models("gemini")
    
    # 构建符合Gemini API格式的模型列表
    gemini_models = []
    for model_name in models:
        # 获取基础模型名
        base_model = get_base_model_from_feature_model(model_name)
        
        model_info = {
            "name": f"models/{model_name}",
            "baseModelId": base_model,
            "version": "001",
            "displayName": model_name,
            "description": f"Gemini {base_model} model",
            "inputTokenLimit": 1000000,
            "outputTokenLimit": 8192,
            "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
            "temperature": 1.0,
            "maxTemperature": 2.0,
            "topP": 0.95,
            "topK": 64
        }
        gemini_models.append(model_info)
    
    return JSONResponse(content={
        "models": gemini_models
    })

@router.post("/v1/v1beta/models/{model:path}:generateContent")
@router.post("/v1/v1/models/{model:path}:generateContent")
@router.post("/v1beta/models/{model:path}:generateContent")
@router.post("/v1/models/{model:path}:generateContent")
async def generate_content(
    model: str = Path(..., description="Model name"),
    request: Request = None,
    auth_info: dict = Depends(authenticate_gemini_flexible)
):
    """处理Gemini格式的内容生成请求（非流式）"""
    
    # 获取原始请求数据
    try:
        request_data = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON request: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": 400,
                    "message": f"Invalid JSON: {str(e)}",
                    "status": "INVALID_ARGUMENT"
                }
            }
        )
    
    # 验证必要字段
    if "contents" not in request_data or not request_data["contents"]:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": 400,
                    "message": "Missing required field: contents",
                    "status": "INVALID_ARGUMENT"
                }
            }
        )
    
    # 请求预处理：限制参数
    if "generationConfig" in request_data and request_data["generationConfig"]:
        generation_config = request_data["generationConfig"]
        
        # 限制max_tokens (在Gemini中叫maxOutputTokens)
        if "maxOutputTokens" in generation_config and generation_config["maxOutputTokens"] is not None:
            if generation_config["maxOutputTokens"] > 65535:
                generation_config["maxOutputTokens"] = 65535
                
        # 覆写 top_k 为 64 (在Gemini中叫topK)
        generation_config["topK"] = 64
    else:
        # 如果没有generationConfig，创建一个并设置topK
        request_data["generationConfig"] = {"topK": 64}
    
    # 处理模型名称和功能检测
    use_anti_truncation = is_anti_truncation_model(model)
    
    # 获取基础模型名
    real_model = get_base_model_from_feature_model(model)
    
    # 对于假流式模型，如果是流式端点才返回假流式响应
    # 注意：这是generateContent端点，不应该触发假流式
    
    # 对于抗截断模型的非流式请求，给出警告
    if use_anti_truncation:
        logger.info("抗截断功能仅在流式传输时有效，非流式请求将忽略此设置")
    
    # 健康检查
    if (len(request_data["contents"]) == 1 and 
        request_data["contents"][0].get("role") == "user" and
        request_data["contents"][0].get("parts", [{}])[0].get("text") == "Hi"):
        return JSONResponse(content={
            "candidates": [{
                "content": {
                    "parts": [{"text": "gcli2api工作中"}],
                    "role": "model"
                },
                "finishReason": "STOP",
                "index": 0
            }]
        })
    
    # 使用用户自己的凭证
    user = await get_user_by_api_key(auth_info["token"])
    if not user:
        # 返回符合Gemini API格式的错误响应
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": 403,
                    "message": "无效的API密钥。请确保您使用了正确的API密钥。",
                    "status": "PERMISSION_DENIED"
                }
            }
        )
    
    async with get_user_credential_manager(user["username"]) as cred_mgr:
        return await process_generate_content(request_data, model, real_model, False, use_anti_truncation, cred_mgr)

async def process_generate_content(request_data, model, real_model, use_fake_streaming, use_anti_truncation, cred_mgr):
        # 获取凭证
        creds, project_id = await cred_mgr.get_credentials()
        if not creds:
            logger.error("当前无可用凭证")
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": 403,
                        "message": "无有效的Gemini CLI凭证。请确保您已在用户面板中上传了有效的凭证。",
                        "status": "PERMISSION_DENIED"
                    }
                }
            )
        
        # 增加调用计数
        await cred_mgr.increment_call_count()
        
        # 构建Google API payload
        try:
            api_payload = build_gemini_payload_from_native(request_data, real_model)
        except Exception as e:
            logger.error(f"Gemini payload build failed: {e}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": 500,
                        "message": "Request processing failed",
                        "status": "INTERNAL"
                    }
                }
            )
        
        # 发送请求（429重试已在google_api_client中处理）
        response = await send_gemini_request(api_payload, False, creds, cred_mgr)
        
        # 处理响应
        try:
            if hasattr(response, 'body'):
                response_data = json.loads(response.body.decode() if isinstance(response.body, bytes) else response.body)
            elif hasattr(response, 'content'):
                response_data = json.loads(response.content.decode() if isinstance(response.content, bytes) else response.content)
            else:
                response_data = json.loads(str(response))
            
            return JSONResponse(content=response_data)
            
        except Exception as e:
            logger.error(f"Response processing failed: {e}")
            # 返回原始响应
            if hasattr(response, 'content'):
                return JSONResponse(content=json.loads(response.content))
            else:
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "code": 500,
                            "message": "Response processing failed",
                            "status": "INTERNAL"
                        }
                    }
                )

@router.post("/v1/v1beta/models/{model:path}:streamGenerateContent")
@router.post("/v1/v1/models/{model:path}:streamGenerateContent")
@router.post("/v1beta/models/{model:path}:streamGenerateContent")
@router.post("/v1/models/{model:path}:streamGenerateContent")
async def stream_generate_content(
    model: str = Path(..., description="Model name"),
    request: Request = None,
    auth_info: dict = Depends(authenticate_gemini_flexible)
):
    """处理Gemini格式的流式内容生成请求"""
    logger.info(f"Stream request received for model: {model}")
    logger.info(f"Request headers: {dict(request.headers)}")
    
    # 获取原始请求数据
    try:
        request_data = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON request: {e}")
        # 返回流式错误响应
        async def error_stream():
            error_chunk = {
                "error": {
                    "code": 400,
                    "message": f"Invalid JSON: {str(e)}",
                    "status": "INVALID_ARGUMENT"
                }
            }
            yield f"data: {json.dumps(error_chunk)}\n\n".encode()
            yield "data: [DONE]\n\n".encode()
        
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # 验证必要字段
    if "contents" not in request_data or not request_data["contents"]:
        # 返回流式错误响应
        async def error_stream():
            error_chunk = {
                "error": {
                    "code": 400,
                    "message": "Missing required field: contents",
                    "status": "INVALID_ARGUMENT"
                }
            }
            yield f"data: {json.dumps(error_chunk)}\n\n".encode()
            yield "data: [DONE]\n\n".encode()
        
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # 请求预处理：限制参数
    if "generationConfig" in request_data and request_data["generationConfig"]:
        generation_config = request_data["generationConfig"]
        
        # 限制max_tokens (在Gemini中叫maxOutputTokens)
        if "maxOutputTokens" in generation_config and generation_config["maxOutputTokens"] is not None:
            if generation_config["maxOutputTokens"] > 65535:
                generation_config["maxOutputTokens"] = 65535
                
        # 覆写 top_k 为 64 (在Gemini中叫topK)
        generation_config["topK"] = 64
    else:
        # 如果没有generationConfig，创建一个并设置topK
        request_data["generationConfig"] = {"topK": 64}
    
    # 处理模型名称和功能检测
    use_fake_streaming = is_fake_streaming_model(model)
    use_anti_truncation = is_anti_truncation_model(model)
    
    # 获取基础模型名
    real_model = get_base_model_from_feature_model(model)
    
    # 对于假流式模型，返回假流式响应
    if use_fake_streaming:
        return await fake_stream_response_gemini(request_data, real_model, auth_info)
    
    # 使用用户自己的凭证
    user = await get_user_by_api_key(auth_info["token"])
    if not user:
        # 返回符合Gemini API格式的错误响应
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": 403,
                    "message": "无效的API密钥。请确保您使用了正确的API密钥。",
                    "status": "PERMISSION_DENIED"
                }
            }
        )
    
    async with get_user_credential_manager(user["username"]) as cred_mgr:
        return await process_stream_generate_content(request_data, real_model, use_anti_truncation, cred_mgr)

async def process_stream_generate_content(request_data, real_model, use_anti_truncation, cred_mgr):
    # 获取凭证
    creds, project_id = await cred_mgr.get_credentials()
    if not creds:
        logger.error("当前无可用凭证")
        # 返回流式错误响应
        async def error_stream():
            error_chunk = {
                "error": {
                    "code": 403,
                    "message": "无有效的Gemini CLI凭证。请确保您已在用户面板中上传了有效的凭证。",
                    "status": "PERMISSION_DENIED"
                }
            }
            yield f"data: {json.dumps(error_chunk)}\n\n".encode()
            yield "data: [DONE]\n\n".encode()
        
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # 增加调用计数
    await cred_mgr.increment_call_count()
    
    # 构建Google API payload
    try:
        api_payload = build_gemini_payload_from_native(request_data, real_model)
    except Exception as e:
        logger.error(f"Gemini payload build failed: {e}")
        raise HTTPException(status_code=500, detail="Request processing failed")
    
    # 处理抗截断功能（仅流式传输时有效）
    if use_anti_truncation:
        logger.info("启用流式抗截断功能")
        # 使用全局配置
        max_attempts = get_anti_truncation_max_attempts()
        return await apply_anti_truncation_to_stream(
            lambda payload: send_gemini_request(payload, True, creds, cred_mgr),
            api_payload,
            max_attempts
        )
    
    # 常规流式请求（429重试已在google_api_client中处理）
    response = await send_gemini_request(api_payload, True, creds, cred_mgr)
    
    # 直接返回流式响应
    return response
    
@router.get("/v1/v1beta/models/{model:path}")
@router.get("/v1/v1/models/{model:path}")
@router.get("/v1beta/models/{model:path}")
@router.get("/v1/models/{model:path}")
async def get_model_info(
    model: str = Path(..., description="Model name"),
    auth_info: dict = Depends(authenticate_gemini_flexible)
):
    """获取特定模型的信息"""
    
    logger.info(f"Model info request for: {model}")
    
    # 验证用户权限（可选：根据需要添加模型访问控制）
    # 这里暂时允许所有认证用户访问模型信息
    
    # 获取基础模型名称
    base_model = get_base_model_name(model)
    
    # 模拟模型信息
    model_info = {
        "name": f"models/{base_model}",
        "baseModelId": base_model,
        "version": "001",
        "displayName": base_model,
        "description": f"Gemini {base_model} model",
        "inputTokenLimit": 128000,
        "outputTokenLimit": 8192,
        "supportedGenerationMethods": [
            "generateContent",
            "streamGenerateContent"
        ],
        "temperature": 1.0,
        "maxTemperature": 2.0,
        "topP": 0.95,
        "topK": 64
    }
    
    return JSONResponse(content=model_info)

async def fake_stream_response_gemini(request_data: dict, model: str, auth_info: dict):
    """处理Gemini格式的假流式响应"""
    import asyncio
    
    async def gemini_stream_generator():
        try:
            # 使用用户自己的凭证
            user = await get_user_by_api_key(auth_info["token"])
            if not user:
                error_chunk = {
                    "error": {
                        "message": "无效的API密钥。请确保您使用了正确的API密钥。",
                        "type": "authentication_error",
                        "code": 403
                    }
                }
                yield f"data: {json.dumps(error_chunk)}\n\n".encode()
                yield "data: [DONE]\n\n".encode()
                return
                
            async with get_user_credential_manager(user["username"]) as cred_mgr:
                # 获取凭证
                creds, project_id = await cred_mgr.get_credentials()
                if not creds:
                    logger.error("当前无可用凭证")
                    error_chunk = {
                        "error": {
                            "message": "无有效的Gemini CLI凭证。请确保您已在用户面板中上传了有效的凭证。",
                            "type": "PERMISSION_DENIED",
                            "code": 403
                        }
                    }
                    yield f"data: {json.dumps(error_chunk)}\n\n".encode()
                    yield "data: [DONE]\n\n".encode()
                    return
                
                # 增加调用计数
                await cred_mgr.increment_call_count()
                
                # 构建Google API payload
                try:
                    api_payload = build_gemini_payload_from_native(request_data, model)
                except Exception as e:
                    logger.error(f"Gemini payload build failed: {e}")
                    error_chunk = {
                        "error": {
                            "message": f"Request processing failed: {str(e)}",
                            "type": "api_error",
                            "code": 500
                        }
                    }
                    yield f"data: {json.dumps(error_chunk)}\n\n".encode()
                    yield "data: [DONE]\n\n".encode()
                    return
                
                # 发送心跳
                heartbeat = {
                    "candidates": [{
                        "content": {
                            "parts": [{"text": ""}],
                            "role": "model"
                        },
                        "finishReason": None,
                        "index": 0
                    }]
                }
                yield f"data: {json.dumps(heartbeat)}\n\n".encode()
                
                # 异步发送实际请求
                async def get_response():
                    return await send_gemini_request(api_payload, False, creds, cred_mgr)
                
                # 创建请求任务
                response_task = asyncio.create_task(get_response())
                
                # 每3秒发送一次心跳，直到收到响应
                while not response_task.done():
                    await asyncio.sleep(3.0)
                    if not response_task.done():
                        yield f"data: {json.dumps(heartbeat)}\n\n".encode()
                
                # 获取响应结果
                response = await response_task
                
                # 发送实际请求
                # response 已在上面获取
                
                # 处理结果
                try:
                    if hasattr(response, 'body'):
                        response_data = json.loads(response.body.decode() if isinstance(response.body, bytes) else response.body)
                    elif hasattr(response, 'content'):
                        response_data = json.loads(response.content.decode() if isinstance(response.content, bytes) else response.content)
                    else:
                        response_data = json.loads(str(response))
                    
                    logger.debug(f"Gemini fake stream response data: {response_data}")
                    
                    # 发送完整内容作为单个chunk，使用思维链分离
                    if "candidates" in response_data and response_data["candidates"]:
                        from .openai_transfer import _extract_content_and_reasoning
                        candidate = response_data["candidates"][0]
                        if "content" in candidate and "parts" in candidate["content"]:
                            parts = candidate["content"]["parts"]
                            content, reasoning_content = _extract_content_and_reasoning(parts)
                            logger.debug(f"Gemini extracted content: {content}")
                            logger.debug(f"Gemini extracted reasoning: {reasoning_content[:100] if reasoning_content else 'None'}...")
                            
                            # 如果没有正常内容但有思维内容
                            if not content and reasoning_content:
                                logger.warning(f"Gemini fake stream contains only thinking content: {reasoning_content[:100]}...")
                                content = "[模型正在思考中，请稍后再试或重新提问]"
                            
                            if content:
                                # 构建包含分离内容的响应
                                parts_response = [{"text": content}]
                                if reasoning_content:
                                    parts_response.append({"text": reasoning_content, "thought": True})
                                
                                content_chunk = {
                                    "candidates": [{
                                        "content": {
                                            "parts": parts_response,
                                            "role": "model"
                                        },
                                        "finishReason": candidate.get("finishReason", "STOP"),
                                        "index": 0
                                    }]
                                }
                                yield f"data: {json.dumps(content_chunk)}\n\n".encode()
                            else:
                                logger.warning(f"No content found in Gemini candidate: {candidate}")
                                # 提供默认回复
                                error_chunk = {
                                    "candidates": [{
                                        "content": {
                                            "parts": [{"text": "[响应为空，请重新尝试]"}],
                                            "role": "model"
                                        },
                                        "finishReason": "STOP",
                                        "index": 0
                                    }]
                                }
                                yield f"data: {json.dumps(error_chunk)}\n\n".encode()
                        else:
                            logger.warning(f"No content/parts found in Gemini candidate: {candidate}")
                            # 返回原始响应
                            yield f"data: {json.dumps(response_data)}\n\n".encode()
                    else:
                        logger.warning(f"No candidates found in Gemini response: {response_data}")
                        yield f"data: {json.dumps(response_data)}\n\n".encode()
                    
                except Exception as e:
                    logger.error(f"Response parsing failed: {e}")
                    error_chunk = {
                        "candidates": [{
                            "content": {
                                "parts": [{"text": f"Response parsing error: {str(e)}"}],
                                "role": "model"
                            },
                            "finishReason": "ERROR",
                            "index": 0
                        }]
                    }
                    yield f"data: {json.dumps(error_chunk)}\n\n".encode()
                
                yield "data: [DONE]\n\n".encode()
                
        except Exception as e:
            logger.error(f"Fake streaming error: {e}")
            error_chunk = {
                "error": {
                    "message": f"Fake streaming error: {str(e)}",
                    "type": "api_error", 
                    "code": 500
                }
            }
            yield f"data: {json.dumps(error_chunk)}\n\n".encode()
            yield "data: [DONE]\n\n".encode()

    return StreamingResponse(gemini_stream_generator(), media_type="text/event-stream")
