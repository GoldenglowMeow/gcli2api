"""
Anti-Truncation Module - Ensures complete streaming output
根据修改指导要求，保持一个流式请求内完整输出的反截断模块
"""
import json
from typing import Dict, Any, AsyncGenerator
from fastapi.responses import StreamingResponse

from log import log

# 反截断配置
DONE_MARKER = "[done]"
MAX_CONTINUATION_ATTEMPTS = 3
CONTINUATION_PROMPT = "\n\n请继续输出剩余内容，在结束时输出[done]标记。"

def apply_anti_truncation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    对请求payload应用反截断处理
    在systemInstruction中添加提醒，要求模型在结束时输出[done]标记
    
    Args:
        payload: 原始请求payload
        
    Returns:
        添加了反截断指令的payload
    """
    modified_payload = payload.copy()
    request_data = modified_payload.get("request", {})
    
    # 获取或创建systemInstruction
    system_instruction = request_data.get("systemInstruction", {})
    if not system_instruction:
        system_instruction = {"parts": []}
    elif "parts" not in system_instruction:
        system_instruction["parts"] = []
    
    # 添加反截断指令
    anti_truncation_instruction = {
        "text": f"重要提醒：当你完成回答时，请在输出的最后添加标记 {DONE_MARKER} 以表示回答完整结束。这非常重要，请务必记住。"
    }
    
    # 检查是否已经包含反截断指令
    has_done_instruction = any(
        part.get("text", "").find(DONE_MARKER) != -1 
        for part in system_instruction["parts"] 
        if isinstance(part, dict)
    )
    
    if not has_done_instruction:
        system_instruction["parts"].append(anti_truncation_instruction)
        request_data["systemInstruction"] = system_instruction
        modified_payload["request"] = request_data
        
        log.debug("Applied anti-truncation instruction to request")
    
    return modified_payload

class AntiTruncationStreamProcessor:
    """反截断流式处理器"""
    
    def __init__(self, 
                 original_request_func,
                 payload: Dict[str, Any],
                 max_attempts: int = MAX_CONTINUATION_ATTEMPTS):
        self.original_request_func = original_request_func
        self.base_payload = payload.copy()
        self.max_attempts = max_attempts
        self.collected_content = ""
        self.current_attempt = 0
        
    async def process_stream(self) -> AsyncGenerator[bytes, None]:
        """处理流式响应，检测并处理截断"""
        
        while self.current_attempt < self.max_attempts:
            self.current_attempt += 1
            
            # 构建当前请求payload
            current_payload = self._build_current_payload()
            
            log.debug(f"Anti-truncation attempt {self.current_attempt}/{self.max_attempts}")
            
            # 发送请求
            try:
                response = await self.original_request_func(current_payload)
                
                if not isinstance(response, StreamingResponse):
                    # 非流式响应，直接处理
                    yield await self._handle_non_streaming_response(response)
                    return
                
                # 处理流式响应
                chunk_content = ""
                found_done_marker = False
                
                async for chunk in response.body_iterator:
                    if not chunk or not chunk.startswith(b'data: '):
                        yield chunk
                        continue
                    
                    # 解析chunk内容
                    payload_data = chunk[len(b'data: '):]
                    
                    if payload_data.strip() == b'[DONE]':
                        # 检查是否找到了done标记
                        if found_done_marker:
                            log.info("Anti-truncation: Found [done] marker, output complete")
                            yield chunk
                            return
                        else:
                            log.warning("Anti-truncation: Stream ended without [done] marker")
                            # 不发送[DONE]，准备继续
                            break
                    
                    try:
                        data = json.loads(payload_data.decode())
                        content = self._extract_content_from_chunk(data)
                        
                        if content:
                            chunk_content += content
                            
                            # 检查是否包含done标记
                            if DONE_MARKER.lower() in content.lower():
                                found_done_marker = True
                                log.info("Anti-truncation: Found [done] marker in chunk")
                        
                        yield chunk
                        
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        yield chunk
                        continue
                
                # 更新收集的内容
                self.collected_content += chunk_content
                
                # 如果找到了done标记，结束
                if found_done_marker:
                    yield b'data: [DONE]\n\n'
                    return
                
                # 如果没找到done标记且不是最后一次尝试，准备续传
                if self.current_attempt < self.max_attempts:
                    log.info(f"Anti-truncation: No [done] marker found, preparing continuation (attempt {self.current_attempt + 1})")
                    # 在下一次循环中会继续
                    continue
                else:
                    # 最后一次尝试，直接结束
                    log.warning("Anti-truncation: Max attempts reached, ending stream")
                    yield b'data: [DONE]\n\n'
                    return
                
            except Exception as e:
                log.error(f"Anti-truncation error in attempt {self.current_attempt}: {str(e)}")
                if self.current_attempt >= self.max_attempts:
                    # 发送错误chunk
                    error_chunk = {
                        "error": {
                            "message": f"Anti-truncation failed: {str(e)}",
                            "type": "api_error",
                            "code": 500
                        }
                    }
                    yield f"data: {json.dumps(error_chunk)}\n\n".encode()
                    yield b'data: [DONE]\n\n'
                    return
                # 否则继续下一次尝试
                
        # 如果所有尝试都失败了
        log.error("Anti-truncation: All attempts failed")
        yield b'data: [DONE]\n\n'
    
    def _build_current_payload(self) -> Dict[str, Any]:
        """构建当前请求的payload"""
        if self.current_attempt == 1:
            # 第一次请求，使用原始payload（已经包含反截断指令）
            return self.base_payload
        
        # 后续请求，添加续传指令
        continuation_payload = self.base_payload.copy()
        request_data = continuation_payload.get("request", {})
        
        # 获取原始对话内容
        contents = request_data.get("contents", [])
        new_contents = contents.copy()
        
        # 如果有收集到的内容，添加到对话中
        if self.collected_content:
            # 添加模型的回复
            new_contents.append({
                "role": "model",
                "parts": [{"text": self.collected_content}]
            })
        
        # 添加继续指令
        continuation_message = {
            "role": "user",
            "parts": [{"text": CONTINUATION_PROMPT}]
        }
        new_contents.append(continuation_message)
        
        request_data["contents"] = new_contents
        continuation_payload["request"] = request_data
        
        return continuation_payload
    
    def _extract_content_from_chunk(self, data: Dict[str, Any]) -> str:
        """从chunk数据中提取文本内容"""
        content = ""
        
        # 处理Gemini格式
        if "candidates" in data:
            for candidate in data["candidates"]:
                if "content" in candidate:
                    parts = candidate["content"].get("parts", [])
                    for part in parts:
                        if "text" in part:
                            content += part["text"]
        
        # 处理OpenAI格式
        elif "choices" in data:
            for choice in data["choices"]:
                if "delta" in choice and "content" in choice["delta"]:
                    content += choice["delta"]["content"]
                elif "message" in choice and "content" in choice["message"]:
                    content += choice["message"]["content"]
        
        return content
    
    async def _handle_non_streaming_response(self, response) -> bytes:
        """处理非流式响应"""
        try:
            if hasattr(response, 'body'):
                content = response.body.decode() if isinstance(response.body, bytes) else response.body
            elif hasattr(response, 'content'):
                content = response.content.decode() if isinstance(response.content, bytes) else response.content
            else:
                content = str(response)
            
            response_data = json.loads(content)
            
            # 检查是否包含done标记
            text_content = self._extract_content_from_response(response_data)
            
            if DONE_MARKER.lower() not in text_content.lower() and self.current_attempt < self.max_attempts:
                log.info("Anti-truncation: Non-streaming response needs continuation")
                self.collected_content += text_content
                # 递归处理续传
                return await self._handle_non_streaming_response(
                    await self.original_request_func(self._build_current_payload())
                )
            
            return content.encode()
            
        except Exception as e:
            log.error(f"Anti-truncation non-streaming error: {str(e)}")
            return json.dumps({
                "error": {
                    "message": f"Anti-truncation failed: {str(e)}",
                    "type": "api_error",
                    "code": 500
                }
            }).encode()
    
    def _extract_content_from_response(self, data: Dict[str, Any]) -> str:
        """从响应数据中提取文本内容"""
        content = ""
        
        # 处理Gemini格式
        if "candidates" in data:
            for candidate in data["candidates"]:
                if "content" in candidate:
                    parts = candidate["content"].get("parts", [])
                    for part in parts:
                        if "text" in part:
                            content += part["text"]
        
        # 处理OpenAI格式
        elif "choices" in data:
            for choice in data["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    content += choice["message"]["content"]
        
        return content

async def apply_anti_truncation_to_stream(
    request_func,
    payload: Dict[str, Any],
    max_attempts: int = MAX_CONTINUATION_ATTEMPTS
) -> StreamingResponse:
    """
    对流式请求应用反截断处理
    
    Args:
        request_func: 原始请求函数
        payload: 请求payload
        max_attempts: 最大续传尝试次数
        
    Returns:
        处理后的StreamingResponse
    """
    
    # 首先对payload应用反截断指令
    anti_truncation_payload = apply_anti_truncation(payload)
    
    # 创建反截断处理器
    processor = AntiTruncationStreamProcessor(
        lambda p: request_func(p),
        anti_truncation_payload,
        max_attempts
    )
    
    # 返回包装后的流式响应
    return StreamingResponse(
        processor.process_stream(),
        media_type="text/event-stream"
    )

def is_anti_truncation_enabled(request_data: Dict[str, Any]) -> bool:
    """
    检查请求是否启用了反截断功能
    
    Args:
        request_data: 请求数据
        
    Returns:
        是否启用反截断
    """
    return request_data.get("enable_anti_truncation", False)