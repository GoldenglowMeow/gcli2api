"""
Google API Client - Handles all communication with Google's Gemini API.
This module is used by both OpenAI compatibility layer and native Gemini endpoints.
"""
import json
import httpx
from fastapi import Response
from fastapi.responses import StreamingResponse
from .user_aware_credential_manager import UserCredentialManager
from .utils import get_user_agent
from config import (
    CODE_ASSIST_ENDPOINT,
    DEFAULT_SAFETY_SETTINGS,
    get_base_model_name,
    get_thinking_budget,
    should_include_thoughts,
    is_search_model,
    get_proxy_config,
    get_auto_ban_enabled,
    get_auto_ban_error_codes,
    get_retry_429_max_retries,
    get_retry_429_enabled,
    get_retry_429_interval
)
import asyncio
from log import log

# 移除对 usage_stats 的导入
# from .usage_stats import record_successful_call

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

async def _handle_api_error(credential_manager: UserCredentialManager, status_code: int, response_content: str = ""):
    """Handle API errors by rotating credentials when needed. Error recording should be done before calling this function."""
    if status_code == 429 and credential_manager:
        if response_content:
            log.error(f"Google API returned status 429 - quota exhausted. Response details: {response_content[:500]}")
        else:
            log.error("Google API returned status 429 - quota exhausted, switching credentials")
        # 注意：在新的逻辑中，429错误会触发 _force_rotate_credential，这里保留 rotate_to_next_credential 作为通用后备
        await credential_manager._force_rotate_credential()
    elif get_auto_ban_enabled() and status_code in get_auto_ban_error_codes() and credential_manager:
        if response_content:
            log.error(f"Google API returned status {status_code} - auto ban triggered. Response details: {response_content[:500]}")
        else:
            log.warning(f"Google API returned status {status_code} - auto ban triggered, rotating credentials")
        await credential_manager._force_rotate_credential()

async def _prepare_request_headers_and_payload(payload: dict, creds, credential_manager: UserCredentialManager):
    """Prepare request headers and final payload."""
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }
    # 获取项目ID (此方法在新的凭证管理器中已不存在，但逻辑保留在 get_credentials 中)
    # project_id 在 get_credentials 返回时已经获得
    _ , project_id = await credential_manager.get_credentials()
    if not project_id:
        raise Exception("Failed to get user project ID from credential manager.")
    
    # 上线用户
    try:
        await credential_manager.onboard_user(creds, project_id)
    except Exception as e:
        raise Exception(f"Failed to onboard user: {str(e)}")
    
    final_payload = {
        "model": payload.get("model"),
        "project": project_id,
        "request": payload.get("request", {})
    }
    return headers, final_payload

async def send_gemini_request(payload: dict, is_streaming: bool = False, creds = None, credential_manager: UserCredentialManager = None) -> Response:
    """
    Send a request to Google's Gemini API.
    Args:
        payload: The request payload in Gemini format
        is_streaming: Whether this is a streaming request
        creds: Credentials object (legacy compatibility, now primarily managed by credential_manager)
        credential_manager: CredentialManager instance for high-performance operations
    Returns:
        FastAPI Response object
    """
    if not credential_manager:
        return _create_error_response("Credential manager is not available.", 500)

    # 获取429重试配置
    max_retries = get_retry_429_max_retries()
    retry_429_enabled = get_retry_429_enabled()
    retry_interval = get_retry_429_interval()
    
    # 确定API端点
    action = "streamGenerateContent" if is_streaming else "generateContent"
    target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
    if is_streaming:
        target_url += "?alt=sse"
    
    try:
        # 首次获取凭证
        current_creds, _ = await credential_manager.get_credentials()
        if not current_creds:
            return _create_error_response("No valid credentials available.", 500)
        
        headers, final_payload = await _prepare_request_headers_and_payload(payload, current_creds, credential_manager)
    except Exception as e:
        return _create_error_response(str(e), 500)

    final_post_data = json.dumps(final_payload)
    proxy = get_proxy_config()

    for attempt in range(max_retries + 1):
        try:
            if is_streaming:
                # 流式请求处理
                client_kwargs = {"timeout": None}
                if proxy:
                    client_kwargs["proxy"] = proxy
                
                client = httpx.AsyncClient(**client_kwargs)
                try:
                    stream_ctx = client.stream("POST", target_url, content=final_post_data, headers=headers)
                    resp = await stream_ctx.__aenter__()

                    if resp.status_code == 429:
                        response_content = ""
                        try:
                            response_content = await resp.aread()
                            if isinstance(response_content, bytes):
                                response_content = response_content.decode('utf-8', errors='ignore')
                        except Exception: pass
                        
                        await credential_manager.record_error(resp.status_code, response_content)
                        await stream_ctx.__aexit__(None, None, None)
                        await client.aclose()

                        if retry_429_enabled and attempt < max_retries:
                            log.warning(f"[RETRY] 429 error encountered, retrying ({attempt + 1}/{max_retries})")
                            await credential_manager._force_rotate_credential()
                            new_creds, _ = await credential_manager.get_credentials()
                            if not new_creds:
                                return _create_error_response("Failed to rotate to a new valid credential.", 500)
                            headers, final_payload = await _prepare_request_headers_and_payload(payload, new_creds, credential_manager)
                            final_post_data = json.dumps(final_payload)
                            await asyncio.sleep(retry_interval)
                            continue
                        else:
                            async def error_stream():
                                yield f'data: {json.dumps({"error": {"message": "429 rate limit exceeded, max retries reached", "type": "api_error", "code": 429}})}\n\n'
                            return StreamingResponse(error_stream(), media_type="text/event-stream", status_code=429)
                    else:
                        return _handle_streaming_response_managed(resp, stream_ctx, client, credential_manager, payload.get("model", ""))
                except Exception as e:
                    try: await client.aclose()
                    except: pass
                    raise e
            else:
                # 非流式请求处理
                client_kwargs = {"timeout": None}
                if proxy:
                    client_kwargs["proxy"] = proxy
                async with httpx.AsyncClient(**client_kwargs) as client:
                    resp = await client.post(target_url, content=final_post_data, headers=headers)
                    
                    if resp.status_code == 429:
                        response_content = ""
                        try:
                            response_content = resp.content.decode('utf-8', errors='ignore')
                        except Exception: pass
                        
                        await credential_manager.record_error(resp.status_code, response_content)

                        if retry_429_enabled and attempt < max_retries:
                            log.warning(f"[RETRY] 429 error encountered, retrying ({attempt + 1}/{max_retries})")
                            await credential_manager._force_rotate_credential()
                            new_creds, _ = await credential_manager.get_credentials()
                            if not new_creds:
                                return _create_error_response("Failed to rotate to a new valid credential.", 500)
                            headers, final_payload = await _prepare_request_headers_and_payload(payload, new_creds, credential_manager)
                            final_post_data = json.dumps(final_payload)
                            await asyncio.sleep(retry_interval)
                            continue
                        else:
                            log.error(f"[RETRY] Max retries exceeded for 429 error")
                            return _create_error_response("429 rate limit exceeded, max retries reached", 429)
                    else:
                        return await _handle_non_streaming_response(resp, credential_manager, payload.get("model", ""))
        except Exception as e:
            if attempt < max_retries:
                log.warning(f"[RETRY] Request failed with exception, retrying ({attempt + 1}/{max_retries}): {str(e)}")
                await asyncio.sleep(retry_interval)
                continue
            else:
                log.error(f"Request to Google API failed: {str(e)}")
                return _create_error_response(f"Request failed: {str(e)}")
    
    return _create_error_response("Max retries exceeded", 429)

def _handle_streaming_response_managed(resp: httpx.Response, stream_ctx, client: httpx.AsyncClient, credential_manager: UserCredentialManager, model_name: str) -> StreamingResponse:
    """Handle streaming response with complete resource lifecycle management."""
    async def cleanup_and_error_stream(status_code, content):
        try: await stream_ctx.__aexit__(None, None, None)
        except: pass
        try: await client.aclose()
        except: pass
        
        log.error(f"Google API returned status {status_code} (STREAMING). Details: {content[:500]}")
        
        if credential_manager:
            await credential_manager.record_error(status_code, content)
            await _handle_api_error(credential_manager, status_code, content)
        
        error_response = {"error": {"message": f"API error: {status_code}", "type": "api_error", "code": status_code}}
        yield f'data: {json.dumps(error_response)}\n\n'.encode('utf-8')

    if resp.status_code != 200:
        response_content = ""
        try:
            response_content = resp.content.decode('utf-8', 'ignore')
        except: pass
        return StreamingResponse(cleanup_and_error_stream(resp.status_code, response_content), media_type="text/event-stream", status_code=resp.status_code)

    async def managed_stream_generator():
        success_recorded = False
        try:
            async for chunk in resp.aiter_lines():
                if not chunk or not chunk.startswith('data: '):
                    continue
                
                if not success_recorded and credential_manager:
                    # 修改：调用 credential_manager.record_success，它现在包含统计逻辑
                    await credential_manager.record_success(model_name)
                    success_recorded = True
                
                payload = chunk[len('data: '):]
                try:
                    obj = json.loads(payload)
                    yield f"data: {json.dumps(obj.get('response', obj), separators=(',',':'))}\n\n".encode()
                    await asyncio.sleep(0)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            log.error(f"Streaming error: {e}")
            yield f'data: {json.dumps({"error": {"message": str(e), "type": "api_error", "code": 500}})}\n\n'.encode()
        finally:
            try: await stream_ctx.__aexit__(None, None, None)
            except Exception as e: log.debug(f"Error closing stream context: {e}")
            try: await client.aclose()
            except Exception as e: log.debug(f"Error closing client: {e}")

    return StreamingResponse(managed_stream_generator(), media_type="text/event-stream")

async def _handle_non_streaming_response(resp: httpx.Response, credential_manager: UserCredentialManager, model_name: str) -> Response:
    """Handle non-streaming response from Google API."""
    if resp.status_code == 200:
        if credential_manager:
            # 修改：调用 credential_manager.record_success，它现在包含统计逻辑
            await credential_manager.record_success(model_name)
        
        try:
            raw = await resp.aread()
            google_api_response = json.loads(raw.decode('utf-8').lstrip('data: '))
            return Response(
                content=json.dumps(google_api_response.get("response")),
                status_code=200,
                media_type="application/json; charset=utf-8"
            )
        except Exception as e:
            log.error(f"Failed to parse Google API response: {str(e)}")
            return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))
    else:
        response_content = ""
        try:
            response_content = resp.content.decode('utf-8', 'ignore')
        except Exception: pass

        log.error(f"Google API returned status {resp.status_code} (NON-STREAMING). Details: {response_content[:500]}")

        if credential_manager:
            await credential_manager.record_error(resp.status_code, response_content)
            await _handle_api_error(credential_manager, resp.status_code, response_content)
            
        return _create_error_response(f"API error: {resp.status_code}", resp.status_code)

def build_gemini_payload_from_openai(openai_payload: dict) -> dict:
    """Build a Gemini API payload from an OpenAI-transformed request."""
    request_data = {
        "contents": openai_payload.get("contents"),
        "safetySettings": openai_payload.get("safetySettings", DEFAULT_SAFETY_SETTINGS),
        "generationConfig": openai_payload.get("generationConfig", {}),
    }
    system_instruction = openai_payload.get("system_instruction")
    if system_instruction:
        request_data["systemInstruction"] = {"parts": [{"text": system_instruction}]} if isinstance(system_instruction, str) else system_instruction
    
    for field in ["cachedContent", "tools", "toolConfig"]:
        if (value := openai_payload.get(field)) is not None:
            request_data[field] = value
            
    return {"model": openai_payload.get("model"), "request": {k: v for k, v in request_data.items() if v is not None}}

def build_gemini_payload_from_native(native_request: dict, model_from_path: str) -> dict:
    """Build a Gemini API payload from a native Gemini request."""
    native_request["safetySettings"] = DEFAULT_SAFETY_SETTINGS
    gen_config = native_request.setdefault("generationConfig", {})
    thinking_config = gen_config.setdefault("thinkingConfig", {})
    thinking_config["includeThoughts"] = should_include_thoughts(model_from_path)
    thinking_config["thinkingBudget"] = get_thinking_budget(model_from_path)
    
    if is_search_model(model_from_path):
        tools = native_request.setdefault("tools", [])
        if not any("googleSearch" in tool for tool in tools):
            tools.append({"googleSearch": {}})
            
    return {"model": get_base_model_name(model_from_path), "request": native_request}
