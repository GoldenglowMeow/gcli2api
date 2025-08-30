"""
Anti-Truncation Module - Ensures complete streaming output
根据修改指导要求，保持一个流式请求内完整输出的反截断模块
"""
import json
from typing import Dict, Any, AsyncGenerator
from fastapi.responses import StreamingResponse

from log import logger

# 反截断配置
DONE_MARKER = "[done]"
MAX_CONTINUATION_ATTEMPTS = 3
CONTINUATION_PROMPT = """请从刚才被截断的地方继续输出剩余的所有内容。

重要提醒：
1. 不要重复前面已经输出的内容
2. 直接继续输出，无需任何前言或解释
3. 当你完整完成所有内容输出后，必须在最后一行单独输出：[done]
4. [done]标记表示你的回答已经完全结束，这是必需的结束标记

现在请继续输出："""

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
        "text": f"""严格执行以下输出结束规则：

1. 当你完成完整回答时，必须在输出的最后单独一行输出：{DONE_MARKER}
2. {DONE_MARKER} 标记表示你的回答已经完全结束，这是必需的结束标记
3. 只有输出了 {DONE_MARKER} 标记，系统才认为你的回答是完整的
4. 如果你的回答被截断，系统会要求你继续输出剩余内容
5. 无论回答长短，都必须以 {DONE_MARKER} 标记结束

示例格式：
```
你的回答内容...
更多回答内容...
{DONE_MARKER}
```

注意：{DONE_MARKER} 必须单独占一行，前面不要有任何其他字符。

这个规则对于确保输出完整性极其重要，请严格遵守。"""
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
        
        logger.debug("Applied anti-truncation instruction to request")
    
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
            
            logger.debug(f"Anti-truncation attempt {self.current_attempt}/{self.max_attempts}")
            
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
                    if not chunk:
                        yield chunk
                        continue
                    
                    # 处理不同数据类型的startswith问题
                    if isinstance(chunk, bytes):
                        if not chunk.startswith(b'data: '):
                            yield chunk
                            continue
                        payload_data = chunk[len(b'data: '):]
                    else:
                        chunk_str = str(chunk)
                        if not chunk_str.startswith('data: '):
                            yield chunk
                            continue
                        payload_data = chunk_str[len('data: '):].encode()
                    
                    # 解析chunk内容
                    
                    if payload_data.strip() == b'[DONE]':
                        # 检查是否找到了done标记
                        if found_done_marker:
                            logger.info("Anti-truncation: Found [done] marker, output complete")
                            yield chunk
                            return
                        else:
                            logger.warning("Anti-truncation: Stream ended without [done] marker")
                            # 不发送[DONE]，准备继续
                            break
                    
                    try:
                        data = json.loads(payload_data.decode())
                        content = self._extract_content_from_chunk(data)
                        
                        if content:
                            chunk_content += content
                            
                            # 检查是否包含done标记
                            if self._check_done_marker_in_chunk_content(content):
                                found_done_marker = True
                                logger.info("Anti-truncation: Found [done] marker in chunk")
                        
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
                
                # 最后再检查一次累积的内容（防止done标记跨chunk出现）
                if self._check_done_marker_in_text(self.collected_content):
                    logger.info("Anti-truncation: Found [done] marker in accumulated content")
                    yield b'data: [DONE]\n\n'
                    return
                
                # 如果没找到done标记且不是最后一次尝试，准备续传
                if self.current_attempt < self.max_attempts:
                    logger.info(f"Anti-truncation: No [done] marker found in output (length: {len(self.collected_content)}), preparing continuation (attempt {self.current_attempt + 1})")
                    logger.debug(f"Anti-truncation: Current collected content ends with: {'...' + self.collected_content[-100:] if len(self.collected_content) > 100 else self.collected_content}")
                    # 在下一次循环中会继续
                    continue
                else:
                    # 最后一次尝试，直接结束
                    logger.warning("Anti-truncation: Max attempts reached, ending stream")
                    yield b'data: [DONE]\n\n'
                    return
                
            except Exception as e:
                logger.error(f"Anti-truncation error in attempt {self.current_attempt}: {str(e)}")
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
        logger.error("Anti-truncation: All attempts failed")
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
        
        # 构建具体的续写指令，包含前面的内容摘要
        content_summary = ""
        if len(self.collected_content) > 200:
            content_summary = f"\n\n前面你已经输出了约 {len(self.collected_content)} 个字符的内容，结尾是：\n\"...{self.collected_content[-100:]}\""
        elif self.collected_content:
            content_summary = f"\n\n前面你已经输出的内容是：\n\"{self.collected_content}\""
        
        detailed_continuation_prompt = f"""{CONTINUATION_PROMPT}{content_summary}"""
        
        # 添加继续指令
        continuation_message = {
            "role": "user", 
            "parts": [{"text": detailed_continuation_prompt}]
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
            has_done_marker = self._check_done_marker_in_text(text_content)
            
            if not has_done_marker and self.current_attempt < self.max_attempts:
                logger.info("Anti-truncation: Non-streaming response needs continuation")
                self.collected_content += text_content
                
                # 构建续传payload
                continuation_payload = self._build_current_payload()
                
                # 使用同一个请求函数处理续传，但不使用递归以避免栈溢出
                # 同时避免频繁凭证轮换，使用循环替代递归
                max_continuation_loops = self.max_attempts - self.current_attempt
                current_loop = 0
                
                while current_loop < max_continuation_loops:
                    current_loop += 1
                    continuation_response = await self.original_request_func(continuation_payload)
                    
                    if hasattr(continuation_response, 'body'):
                        cont_content = continuation_response.body.decode() if isinstance(continuation_response.body, bytes) else continuation_response.body
                    elif hasattr(continuation_response, 'content'):
                        cont_content = continuation_response.content.decode() if isinstance(continuation_response.content, bytes) else continuation_response.content
                    else:
                        cont_content = str(continuation_response)
                    
                    try:
                        cont_data = json.loads(cont_content)
                        cont_text = self._extract_content_from_response(cont_data)
                        self.collected_content += cont_text
                        
                        # 检查是否包含done标记
                        if self._check_done_marker_in_text(cont_text):
                            logger.info(f"Anti-truncation: Found [done] marker in continuation attempt {current_loop}")
                            # 找到done标记，合并响应并返回
                            return self._merge_response_with_collected_content(response_data, self.collected_content).encode()
                        
                        # 更新续传payload以包含新收集的内容
                        continuation_payload = self._build_current_payload()
                    except Exception as e:
                        logger.error(f"Anti-truncation continuation error: {str(e)}")
                        break
                
                # 如果所有尝试都没有找到done标记，返回合并的内容
                logger.warning(f"Anti-truncation: No [done] marker found after {current_loop} continuation attempts")
                return self._merge_response_with_collected_content(response_data, self.collected_content).encode()
            
            return content.encode()
            
        except Exception as e:
            logger.error(f"Anti-truncation non-streaming error: {str(e)}")
            return json.dumps({
                "error": {
                    "message": f"Anti-truncation failed: {str(e)}",
                    "type": "api_error",
                    "code": 500
                }
            }).encode()
            
    def _merge_response_with_collected_content(self, original_response: Dict[str, Any], collected_content: str) -> str:
        """将收集到的内容合并到原始响应中"""
        response_copy = original_response.copy()
        
        # 处理Gemini格式
        if "candidates" in response_copy and response_copy["candidates"]:
            for candidate in response_copy["candidates"]:
                if "content" in candidate:
                    parts = candidate["content"].get("parts", [])
                    # 替换或添加文本部分
                    text_part_found = False
                    for part in parts:
                        if "text" in part:
                            part["text"] = collected_content
                            text_part_found = True
                            break
                    
                    if not text_part_found and parts:
                        parts.append({"text": collected_content})
                    elif not parts:
                        candidate["content"]["parts"] = [{"text": collected_content}]
        
        # 处理OpenAI格式
        elif "choices" in response_copy and response_copy["choices"]:
            for choice in response_copy["choices"]:
                if "message" in choice:
                    choice["message"]["content"] = collected_content
        
        return json.dumps(response_copy)
    
    def _check_done_marker_in_text(self, text: str) -> bool:
        """检查文本中是否包含done标记（严格检测）"""
        if not text:
            return False
        
        # 支持的done标记变体
        done_variants = [
            "[done]",
            "[DONE]", 
            "[Done]",
            "【done】",
            "【DONE】",
            "[完成]",
            "[结束]"
        ]
        
        # 分行检查，每行去掉空白后检查
        lines = text.strip().split('\n')
        for line in lines:
            line_clean = line.strip()
            # 检查整行是否就是done标记的任何变体
            for variant in done_variants:
                if line_clean == variant or line_clean.endswith(variant):
                    return True
        
        return False
    
    def _check_done_marker_in_chunk_content(self, content: str) -> bool:
        """检查单个chunk内容中是否包含done标记"""
        return self._check_done_marker_in_text(content)
    
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