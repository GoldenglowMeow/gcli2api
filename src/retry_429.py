"""
429 Retry Module - Handles automatic retry for non-quota 429 errors
根据修改指导要求，负责429错误的自动重试逻辑
"""
import asyncio
from typing import Callable, Any, Optional
from fastapi.responses import StreamingResponse

from config import get_retry_429_max_retries, get_retry_429_enabled, get_retry_429_interval
from .credential_manager import CredentialManager
from log import log

async def retry_429_wrapper(
    request_func: Callable,
    credential_manager: CredentialManager,
    max_retries: Optional[int] = None,
    retry_interval: Optional[float] = None
) -> Any:
    """
    429重试包装器
    
    Args:
        request_func: 要执行的请求函数
        credential_manager: 凭证管理器
        max_retries: 最大重试次数（可选，默认从配置读取）
        retry_interval: 重试间隔（可选，默认从配置读取）
        
    Returns:
        请求响应结果
    """
    if max_retries is None:
        max_retries = get_retry_429_max_retries()
    if retry_interval is None:
        retry_interval = get_retry_429_interval()
    
    retry_429_enabled = get_retry_429_enabled()
    retry_count = 0
    
    while retry_count <= max_retries:
        try:
            # 执行请求
            response = await request_func()
            
            # 检查是否是429错误
            if hasattr(response, 'status_code') and response.status_code == 429:
                if retry_429_enabled and retry_count < max_retries:
                    retry_count += 1
                    log.warning(f"[RETRY_429] Got 429 error, retrying ({retry_count}/{max_retries})")
                    
                    # 增加调用计数触发凭证轮换
                    await credential_manager.increment_call_count()
                    
                    # 等待重试间隔
                    await asyncio.sleep(retry_interval)
                    continue
                else:
                    # 重试次数用完或重试被禁用
                    if retry_count >= max_retries:
                        log.error(f"[RETRY_429] Max retries ({max_retries}) exceeded for 429 error")
                    else:
                        log.warning("[RETRY_429] 429 error encountered, but retry is disabled")
                    return response
            else:
                # 非429错误或成功响应，直接返回
                return response
                
        except Exception as e:
            # 如果是网络错误或其他异常，也进行重试
            if retry_429_enabled and retry_count < max_retries:
                retry_count += 1
                log.warning(f"[RETRY_429] Request failed with exception, retrying ({retry_count}/{max_retries}): {str(e)}")
                
                # 等待重试间隔
                await asyncio.sleep(retry_interval)
                continue
            else:
                # 重试次数用完，抛出异常
                log.error(f"[RETRY_429] Max retries exceeded for exception: {str(e)}")
                raise e
    
    # 如果循环结束还没有成功响应，返回错误
    log.error("[RETRY_429] Unexpected end of retry loop")
    raise Exception("Max retries exceeded without successful response")

class StreamingRetry429Wrapper:
    """流式响应429重试包装器"""
    
    def __init__(self, 
                 request_func: Callable,
                 credential_manager: CredentialManager,
                 max_retries: Optional[int] = None,
                 retry_interval: Optional[float] = None):
        self.request_func = request_func
        self.credential_manager = credential_manager
        self.max_retries = max_retries or get_retry_429_max_retries()
        self.retry_interval = retry_interval or get_retry_429_interval()
        self.retry_429_enabled = get_retry_429_enabled()
    
    async def execute(self) -> StreamingResponse:
        """执行带重试的流式请求"""
        retry_count = 0
        
        while retry_count <= self.max_retries:
            try:
                # 执行流式请求
                response = await self.request_func()
                
                # 对于流式响应，我们需要检查第一个chunk来确定是否是429错误
                if isinstance(response, StreamingResponse):
                    # 包装流式响应以处理429错误
                    return StreamingResponse(
                        self._handle_streaming_429(response, retry_count),
                        media_type=response.media_type,
                        status_code=response.status_code,
                        headers=response.headers
                    )
                else:
                    # 非流式响应，按普通重试处理
                    if hasattr(response, 'status_code') and response.status_code == 429:
                        if self.retry_429_enabled and retry_count < self.max_retries:
                            retry_count += 1
                            log.warning(f"[STREAMING_RETRY_429] Got 429 error, retrying ({retry_count}/{self.max_retries})")
                            
                            # 增加调用计数触发凭证轮换
                            await self.credential_manager.increment_call_count()
                            
                            # 等待重试间隔
                            await asyncio.sleep(self.retry_interval)
                            continue
                    
                    return response
                    
            except Exception as e:
                if self.retry_429_enabled and retry_count < self.max_retries:
                    retry_count += 1
                    log.warning(f"[STREAMING_RETRY_429] Request failed with exception, retrying ({retry_count}/{self.max_retries}): {str(e)}")
                    
                    # 等待重试间隔
                    await asyncio.sleep(self.retry_interval)
                    continue
                else:
                    log.error(f"[STREAMING_RETRY_429] Max retries exceeded for exception: {str(e)}")
                    raise e
        
        raise Exception("Max retries exceeded without successful response")
    
    async def _handle_streaming_429(self, response: StreamingResponse, initial_retry_count: int):
        """处理流式响应中的429错误"""
        retry_count = initial_retry_count
        
        try:
            async for chunk in response.body_iterator:
                # 检查chunk是否包含429错误信息
                if self._is_429_error_chunk(chunk):
                    if self.retry_429_enabled and retry_count < self.max_retries:
                        retry_count += 1
                        log.warning(f"[STREAMING_RETRY_429] Detected 429 in stream, retrying ({retry_count}/{self.max_retries})")
                        
                        # 增加调用计数触发凭证轮换
                        await self.credential_manager.increment_call_count()
                        
                        # 等待重试间隔
                        await asyncio.sleep(self.retry_interval)
                        
                        # 重新执行请求
                        new_response = await self.request_func()
                        if isinstance(new_response, StreamingResponse):
                            async for new_chunk in new_response.body_iterator:
                                yield new_chunk
                        return
                    else:
                        # 重试次数用完，返回错误chunk
                        log.error(f"[STREAMING_RETRY_429] Max retries exceeded for 429 error in stream")
                        yield chunk
                        return
                else:
                    # 正常chunk，直接返回
                    yield chunk
                    
        except Exception as e:
            log.error(f"[STREAMING_RETRY_429] Error handling streaming 429: {str(e)}")
            import json
            error_chunk = {
                "error": {
                    "message": f"Streaming retry error: {str(e)}",
                    "type": "api_error",
                    "code": 500
                }
            }
            yield f"data: {json.dumps(error_chunk)}\n\n".encode()
    
    def _is_429_error_chunk(self, chunk: bytes) -> bool:
        """检查chunk是否包含429错误"""
        try:
            if chunk.startswith(b'data: '):
                payload = chunk[len(b'data: '):]
                if payload.strip() == b'[DONE]':
                    return False
                
                import json
                data = json.loads(payload.decode())
                
                # 检查是否有错误码429
                if isinstance(data, dict):
                    error = data.get('error', {})
                    if error.get('code') == 429:
                        return True
                    
                    # 检查Gemini格式的错误
                    if 'status' in error and error.get('status') == 'RESOURCE_EXHAUSTED':
                        return True
                
                return False
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
            return False

async def streaming_retry_429_wrapper(
    request_func: Callable,
    credential_manager: CredentialManager,
    max_retries: Optional[int] = None,
    retry_interval: Optional[float] = None
) -> StreamingResponse:
    """
    流式429重试包装器的便捷函数
    
    Args:
        request_func: 要执行的流式请求函数
        credential_manager: 凭证管理器
        max_retries: 最大重试次数
        retry_interval: 重试间隔
        
    Returns:
        StreamingResponse对象
    """
    wrapper = StreamingRetry429Wrapper(
        request_func, 
        credential_manager, 
        max_retries, 
        retry_interval
    )
    return await wrapper.execute()