"""
Google API Client - Handles all communication with Google's Gemini API.
This module is used by both OpenAI compatibility layer and native Gemini endpoints.
"""
import json
import httpx
from fastapi import Response
from fastapi.responses import StreamingResponse

from .credential_manager import CredentialManager
from .utils import get_user_agent
from .config import (
    CODE_ASSIST_ENDPOINT,
    DEFAULT_SAFETY_SETTINGS,
    get_base_model_name,
    get_thinking_budget,
    should_include_thoughts
)
import asyncio

from log import log

def _create_error_response(message: str, status_code: int = 500) -> Response:
    """Create standardized error response."""
    return Response(
        content=json.dumps({
            "error": {
                "message": message,
                "type": "api_error",
                "code": status_code
            }
        }),
        status_code=status_code,
        media_type="application/json"
    )

async def _handle_quota_exhausted(credential_manager: CredentialManager, status_code: int, current_file: str = None):
    """Handle quota exhausted error by rotating credentials."""
    if status_code == 429 and credential_manager:
        log.warning("Google API returned status 429 - quota exhausted, switching credentials")
        if current_file:
            await credential_manager.record_error(current_file, status_code)
        await credential_manager.rotate_to_next_credential()

async def _prepare_request_headers_and_payload(payload: dict, creds, credential_manager: CredentialManager):
    """Prepare request headers and final payload."""
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }

    # 获取项目ID (使用线程安全的方法)
    try:
        proj_id = credential_manager.get_user_project_id(creds)
    except Exception as e:
        raise Exception(f"Failed to get user project ID: {str(e)}")
    
    # 上线用户
    try:
        await credential_manager.onboard_user(creds, proj_id)
    except Exception as e:
        raise Exception(f"Failed to onboard user: {str(e)}")

    final_payload = {
        "model": payload.get("model"),
        "project": proj_id,
        "request": payload.get("request", {})
    }
    
    return headers, final_payload

async def send_gemini_request(payload: dict, is_streaming: bool = False, creds = None, credential_manager: CredentialManager = None) -> Response:
    """
    Send a request to Google's Gemini API.
    
    Args:
        payload: The request payload in Gemini format
        is_streaming: Whether this is a streaming request
        creds: Credentials object (legacy compatibility)
        credential_manager: CredentialManager instance for high-performance operations
        
    Returns:
        FastAPI Response object
    """
    try:
        headers, final_payload = await _prepare_request_headers_and_payload(payload, creds, credential_manager)
    except Exception as e:
        return _create_error_response(str(e), 500)

    # 确定API端点
    action = "streamGenerateContent" if is_streaming else "generateContent"
    target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
    if is_streaming:
        target_url += "?alt=sse"

    final_post_data = json.dumps(final_payload)

    try:
        if is_streaming:
            # 流式请求：在生成器里打开 AsyncClient 和 client.stream，确保整个流式周期中 client 不被关闭
            async def event_stream():
                async with httpx.AsyncClient(timeout=None) as client:
                    async with client.stream(
                        "POST", target_url, content=final_post_data, headers=headers
                    ) as resp:
                        sse_resp = await _handle_streaming_response(resp, credential_manager)
                        async for chunk in sse_resp.body_iterator:
                            yield chunk
            return StreamingResponse(event_stream(), media_type="text/event-stream")

        # 非流式请求保持原逻辑
        async with httpx.AsyncClient(timeout=None) as client:
            resp = await client.post(
                target_url, content=final_post_data, headers=headers
            )
            return await _handle_non_streaming_response(resp, credential_manager)
    except Exception as e:
        log.error(f"Request to Google API failed: {str(e)}")
        return _create_error_response(f"Request failed: {str(e)}")


async def _handle_streaming_response(resp: httpx.Response, credential_manager: CredentialManager = None) -> StreamingResponse:
    """Handle streaming response from Google API."""
    
    # 检查HTTP错误
    if resp.status_code != 200:
        log.error(f"Google API returned status {resp.status_code}")
        
        # 记录错误并检查是否是 429 错误（配额用完），立即切换凭据
        current_file = credential_manager.get_current_file_path() if credential_manager else None
        if current_file and credential_manager:
            await credential_manager.record_error(current_file, resp.status_code)
        await _handle_quota_exhausted(credential_manager, resp.status_code, current_file)
        
        # 返回错误流
        async def error_generator():
            error_response = {
                "error": {
                    "message": f"API error: {resp.status_code}",
                    "type": "api_error",
                    "code": resp.status_code
                }
            }
            yield f'data: {json.dumps(error_response)}\n\n'.encode('utf-8')
        
        return StreamingResponse(
            error_generator(),
            media_type="text/event-stream",
            status_code=resp.status_code
        )
    
    async def stream_generator():
        success_recorded = False
        try:
            async for chunk in resp.aiter_lines():
                if not chunk or not chunk.startswith('data: '):
                    continue
                    
                # 记录第一次成功响应
                if not success_recorded:
                    current_file = credential_manager.get_current_file_path() if credential_manager else None
                    if current_file and credential_manager:
                        await credential_manager.record_success(current_file, "chat_content")
                    success_recorded = True
                
                payload = chunk[len('data: '):]
                try:
                    obj = json.loads(payload)
                    if "response" in obj:
                        data = obj["response"]
                        yield f"data: {json.dumps(data, separators=(',',':'))}\n\n".encode()
                        await asyncio.sleep(0)
                    else:
                        yield f"data: {json.dumps(obj, separators=(',',':'))}\n\n".encode()
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            log.error(f"Streaming error: {e}")
            err = {"error": {"message": str(e), "type": "api_error", "code": 500}}
            yield f"data: {json.dumps(err)}\n\n".encode()

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream"
    )


async def _handle_non_streaming_response(resp: httpx.Response, credential_manager: CredentialManager = None) -> Response:
    """Handle non-streaming response from Google API."""
    if resp.status_code == 200:
        try:
            # 记录成功响应
            current_file = credential_manager.get_current_file_path() if credential_manager else None
            if current_file and credential_manager:
                await credential_manager.record_success(current_file, "chat_content")
            
            raw = await resp.aread()
            google_api_response = raw.decode('utf-8')
            if google_api_response.startswith('data: '):
                google_api_response = google_api_response[len('data: '):]
            google_api_response = json.loads(google_api_response)
            standard_gemini_response = google_api_response.get("response")
            return Response(
                content=json.dumps(standard_gemini_response),
                status_code=200,
                media_type="application/json; charset=utf-8"
            )
        except Exception as e:
            log.error(f"Failed to parse Google API response: {str(e)}")
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type=resp.headers.get("Content-Type")
            )
    else:
        log.error(f"Google API returned status {resp.status_code}")
        
        # 记录错误并检查是否是 429 错误（配额用完），立即切换凭据
        current_file = credential_manager.get_current_file_path() if credential_manager else None
        if current_file and credential_manager:
            await credential_manager.record_error(current_file, resp.status_code)
        await _handle_quota_exhausted(credential_manager, resp.status_code, current_file)
        
        return _create_error_response(f"API error: {resp.status_code}", resp.status_code)


def build_gemini_payload_from_openai(openai_payload: dict) -> dict:
    """
    Build a Gemini API payload from an OpenAI-transformed request.
    """
    model = openai_payload.get("model")
    safety_settings = openai_payload.get("safetySettings", DEFAULT_SAFETY_SETTINGS)
    
    request_data = {
        "contents": openai_payload.get("contents"),
        "systemInstruction": openai_payload.get("systemInstruction"),
        "cachedContent": openai_payload.get("cachedContent"),
        "tools": openai_payload.get("tools"),
        "toolConfig": openai_payload.get("toolConfig"),
        "safetySettings": safety_settings,
        "generationConfig": openai_payload.get("generationConfig", {}),
    }
    
    # 移除None值
    request_data = {k: v for k, v in request_data.items() if v is not None}
    
    return {
        "model": model,
        "request": request_data
    }


def build_gemini_payload_from_native(native_request: dict, model_from_path: str) -> dict:
    """
    Build a Gemini API payload from a native Gemini request.
    """
    native_request["safetySettings"] = DEFAULT_SAFETY_SETTINGS
    
    if "generationConfig" not in native_request:
        native_request["generationConfig"] = {}
    
    if "thinkingConfig" not in native_request["generationConfig"]:
        native_request["generationConfig"]["thinkingConfig"] = {}
    
    # 配置thinking
    thinking_budget = get_thinking_budget(model_from_path)
    include_thoughts = should_include_thoughts(model_from_path)
    
    native_request["generationConfig"]["thinkingConfig"]["includeThoughts"] = include_thoughts
    native_request["generationConfig"]["thinkingConfig"]["thinkingBudget"] = thinking_budget
    
    return {
        "model": get_base_model_name(model_from_path),
        "request": native_request
    }