"""
Gemini Router - Handles native Gemini format API requests
处理原生Gemini格式请求的路由模块
"""
import json
from contextlib import asynccontextmanager

from fastapi import APIRouter, HTTPException, Depends, Request, Path, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, StreamingResponse

from .google_api_client import send_gemini_request, build_gemini_payload_from_native
from .credential_manager import CredentialManager
from .retry_429 import retry_429_wrapper
from config import get_config_value, get_available_models, is_fake_streaming_model, is_anti_truncation_model, get_base_model_from_feature_model, get_anti_truncation_max_attempts
from .anti_truncation import apply_anti_truncation_to_stream
from config import get_base_model_name
from log import log

# 创建路由器
router = APIRouter()
security = HTTPBearer()

# 全局凭证管理器实例
credential_manager = None

@asynccontextmanager
async def get_credential_manager():
    """获取全局凭证管理器实例"""
    global credential_manager
    if not credential_manager:
        credential_manager = CredentialManager()
        await credential_manager.initialize()
    yield credential_manager

def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """验证用户密码"""
    password = get_config_value("password", "pwd", "PASSWORD")
    token = credentials.credentials
    if token != password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="密码错误")
    return token

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

@router.post("/v1beta/models/{model}:generateContent")
@router.post("/v1/models/{model}:generateContent")
async def generate_content(
    model: str = Path(..., description="Model name"),
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """处理Gemini格式的内容生成请求（非流式）"""
    token = authenticate(credentials)
    
    # 获取原始请求数据
    try:
        request_data = await request.json()
    except Exception as e:
        log.error(f"Failed to parse JSON request: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    
    # 验证必要字段
    if "contents" not in request_data or not request_data["contents"]:
        raise HTTPException(status_code=400, detail="Missing required field: contents")
    
    # 处理模型名称和功能检测
    use_anti_truncation = is_anti_truncation_model(model)
    
    # 获取基础模型名
    real_model = get_base_model_from_feature_model(model)
    
    # 对于假流式模型，如果是流式端点才返回假流式响应
    # 注意：这是generateContent端点，不应该触发假流式
    
    # 对于抗截断模型的非流式请求，给出警告
    if use_anti_truncation:
        log.warning("抗截断功能仅在流式传输时有效，非流式请求将忽略此设置")
    
    # 健康检查
    if (len(request_data["contents"]) == 1 and 
        request_data["contents"][0].get("role") == "user" and
        request_data["contents"][0].get("parts", [{}])[0].get("text") == "Hi"):
        return JSONResponse(content={
            "candidates": [{
                "content": {
                    "parts": [{"text": "公益站正常工作中"}],
                    "role": "model"
                },
                "finishReason": "STOP",
                "index": 0
            }]
        })
    
    # 获取凭证管理器
    async with get_credential_manager() as cred_mgr:
        # 获取凭证
        creds, project_id = await cred_mgr.get_credentials_and_project()
        if not creds:
            log.error("No credentials available")
            raise HTTPException(status_code=500, detail="No credentials available")
        
        # 增加调用计数
        await cred_mgr.increment_call_count()
        
        # 构建Google API payload
        try:
            api_payload = build_gemini_payload_from_native(request_data, real_model)
        except Exception as e:
            log.error(f"Gemini payload build failed: {e}")
            raise HTTPException(status_code=500, detail="Request processing failed")
        
        # 发送请求（包含429重试）
        response = await retry_429_wrapper(
            lambda: send_gemini_request(api_payload, False, creds, cred_mgr),
            cred_mgr
        )
        
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
            log.error(f"Response processing failed: {e}")
            # 返回原始响应
            if hasattr(response, 'content'):
                return JSONResponse(content=json.loads(response.content))
            else:
                raise HTTPException(status_code=500, detail="Response processing failed")

@router.post("/v1beta/models/{model}:streamGenerateContent")
@router.post("/v1/models/{model}:streamGenerateContent")
async def stream_generate_content(
    model: str = Path(..., description="Model name"),
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """处理Gemini格式的流式内容生成请求"""
    token = authenticate(credentials)
    
    # 获取原始请求数据
    try:
        request_data = await request.json()
    except Exception as e:
        log.error(f"Failed to parse JSON request: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    
    # 验证必要字段
    if "contents" not in request_data or not request_data["contents"]:
        raise HTTPException(status_code=400, detail="Missing required field: contents")
    
    # 处理模型名称和功能检测
    use_fake_streaming = is_fake_streaming_model(model)
    use_anti_truncation = is_anti_truncation_model(model)
    
    # 获取基础模型名
    real_model = get_base_model_from_feature_model(model)
    
    # 对于假流式模型，返回假流式响应
    if use_fake_streaming:
        return await fake_stream_response_gemini(request_data, real_model)
    
    # 获取凭证管理器
    async with get_credential_manager() as cred_mgr:
        # 获取凭证
        creds, project_id = await cred_mgr.get_credentials_and_project()
        if not creds:
            log.error("No credentials available")
            raise HTTPException(status_code=500, detail="No credentials available")
        
        # 增加调用计数
        await cred_mgr.increment_call_count()
        
        # 构建Google API payload
        try:
            api_payload = build_gemini_payload_from_native(request_data, real_model)
        except Exception as e:
            log.error(f"Gemini payload build failed: {e}")
            raise HTTPException(status_code=500, detail="Request processing failed")
        
        # 处理抗截断功能（仅流式传输时有效）
        if use_anti_truncation:
            log.info("启用流式抗截断功能")
            # 使用流式抗截断处理器
            max_attempts = get_anti_truncation_max_attempts()
            return await apply_anti_truncation_to_stream(
                lambda payload: retry_429_wrapper(
                    lambda: send_gemini_request(payload, True, creds, cred_mgr),
                    cred_mgr
                ),
                api_payload,
                max_attempts
            )
        
        # 常规流式请求
        response = await retry_429_wrapper(
            lambda: send_gemini_request(api_payload, True, creds, cred_mgr),
            cred_mgr
        )
        
        # 直接返回流式响应
        return response

@router.get("/v1beta/models/{model}")
@router.get("/v1/models/{model}")
async def get_model_info(
    model: str = Path(..., description="Model name"),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """获取特定模型的信息"""
    token = authenticate(credentials)
    
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

@router.post("/v1beta/models/{model}:countTokens")
@router.post("/v1/models/{model}:countTokens")
async def count_tokens(
    model: str = Path(..., description="Model name"),
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """计算令牌数量（模拟实现）"""
    token = authenticate(credentials)
    
    try:
        request_data = await request.json()
    except Exception as e:
        log.error(f"Failed to parse JSON request: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    
    # 简单的令牌计数估算
    total_tokens = 0
    
    if "contents" in request_data:
        for content in request_data["contents"]:
            if "parts" in content:
                for part in content["parts"]:
                    if "text" in part:
                        # 简单估算：4个字符≈1个令牌
                        total_tokens += len(part["text"]) // 4
    
    return JSONResponse(content={
        "totalTokens": max(total_tokens, 1)  # 至少返回1个令牌
    })

@router.post("/v1beta/models/{model}:batchEmbedContents")
@router.post("/v1/models/{model}:batchEmbedContents")
async def batch_embed_contents(
    model: str = Path(..., description="Model name"),
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """批量嵌入内容（模拟实现）"""
    token = authenticate(credentials)
    
    try:
        request_data = await request.json()
    except Exception as e:
        log.error(f"Failed to parse JSON request: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    
    # 模拟嵌入响应
    embeddings = []
    
    if "requests" in request_data:
        for i, req in enumerate(request_data["requests"]):
            # 模拟768维嵌入向量
            import random
            embedding_values = [random.random() * 2 - 1 for _ in range(768)]
            
            embeddings.append({
                "embedding": {
                    "values": embedding_values
                }
            })
    
    return JSONResponse(content={
        "embeddings": embeddings
    })

async def fake_stream_response_gemini(request_data: dict, model: str):
    """处理Gemini格式的假流式响应"""
    async def gemini_stream_generator():
        try:
            # 获取凭证管理器
            async with get_credential_manager() as cred_mgr:
                # 获取凭证
                creds, project_id = await cred_mgr.get_credentials_and_project()
                if not creds:
                    log.error("No credentials available")
                    error_chunk = {
                        "error": {
                            "message": "No credentials available",
                            "type": "authentication_error",
                            "code": 500
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
                    log.error(f"Gemini payload build failed: {e}")
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
                
                # 发送实际请求
                response = await retry_429_wrapper(
                    lambda: send_gemini_request(api_payload, False, creds, cred_mgr),
                    cred_mgr
                )
                
                # 处理结果
                try:
                    if hasattr(response, 'body'):
                        response_data = json.loads(response.body.decode() if isinstance(response.body, bytes) else response.body)
                    elif hasattr(response, 'content'):
                        response_data = json.loads(response.content.decode() if isinstance(response.content, bytes) else response.content)
                    else:
                        response_data = json.loads(str(response))
                    
                    log.debug(f"Gemini fake stream response data: {response_data}")
                    
                    # 发送完整内容作为单个chunk
                    if "candidates" in response_data and response_data["candidates"]:
                        candidate = response_data["candidates"][0]
                        if "content" in candidate and "parts" in candidate["content"]:
                            content = candidate["content"]["parts"][0].get("text", "")
                            log.debug(f"Gemini extracted content: {content}")
                            
                            if content:
                                content_chunk = {
                                    "candidates": [{
                                        "content": {
                                            "parts": [{"text": content}],
                                            "role": "model"
                                        },
                                        "finishReason": candidate.get("finishReason", "STOP"),
                                        "index": 0
                                    }]
                                }
                                yield f"data: {json.dumps(content_chunk)}\n\n".encode()
                            else:
                                log.warning(f"No content found in Gemini candidate: {candidate}")
                                yield f"data: {json.dumps(response_data)}\n\n".encode()
                        else:
                            log.warning(f"No content/parts found in Gemini candidate: {candidate}")
                            # 返回原始响应
                            yield f"data: {json.dumps(response_data)}\n\n".encode()
                    else:
                        log.warning(f"No candidates found in Gemini response: {response_data}")
                        yield f"data: {json.dumps(response_data)}\n\n".encode()
                    
                except Exception as e:
                    log.error(f"Response parsing failed: {e}")
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
            log.error(f"Fake streaming error: {e}")
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