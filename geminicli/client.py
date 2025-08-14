"""
OpenAI API Routes - Handles OpenAI-compatible endpoints.
This module provides OpenAI-compatible endpoints that transform requests/responses
and delegate to the Google API client.
"""
import json
import uuid
import asyncio
from fastapi import Response
from fastapi.responses import StreamingResponse

from .models import OpenAIChatCompletionRequest
from .openai_transformers import (
    openai_request_to_gemini,
    gemini_response_to_openai,
    gemini_stream_chunk_to_openai
)
from .google_api_client import send_gemini_request, build_gemini_payload_from_openai
from .credential_manager import CredentialManager

from log import log

class GeminiCLIClient:
    def __init__(self):
        self.creds = None
        self.project_id = None
        # 使用高性能凭证管理器
        self.credential_manager = CredentialManager(calls_per_rotation=100)  # Switch every 100 calls

    async def initialize(self):
        """
        Load or acquire credentials and onboard the user.
        """
        log.info("Initializing GeminiCli...")
        
        try:
            # 初始化凭证管理器
            await self.credential_manager.initialize()
            
            # 获取初始凭证
            self.creds, self.project_id = await self.credential_manager.get_credentials_and_project()
            if not self.creds:
                log.warning("No credentials available on startup - service will return errors until credentials are added via OAuth")
                # 不抛出异常，允许服务启动
                return
            
            if self.project_id:
                await self.credential_manager.onboard_user(self.creds, self.project_id)
                log.info(f"Onboarded with project ID: {self.project_id}")
            
            log.info("GeminiCli initialized successfully.")
        except Exception as e:
            log.error(f"Initialization error: {e}")
            # 改为警告而不是抛出异常，允许服务启动
            log.warning("Service started without credentials - OAuth authentication required")

    def _create_error_response(self, message: str, error_type: str = "api_error", status_code: int = 500):
        """Create standardized error response."""
        return Response(
            content=json.dumps({
                "error": {
                    "message": message,
                    "type": error_type,
                    "code": status_code
                }
            }),
            status_code=status_code,
            media_type="application/json"
        )

    async def _prepare_request(self, request: OpenAIChatCompletionRequest):
        """Prepare credentials and convert request to Gemini format."""
        # 增加调用计数用于凭证轮换
        await self.credential_manager.increment_call_count()
        
        # 使用缓存的凭证，按调用次数轮换
        log.debug("Getting credentials for chat completion")
        self.creds, self.project_id = await self.credential_manager.get_credentials_and_project()
        if not self.creds:
            raise RuntimeError("No credentials available - please configure OAuth credentials via /auth endpoint")
        
        if self.project_id:
            # onboarding - 只在需要时执行
            await self.credential_manager.onboard_user(self.creds, self.project_id)
            log.debug(f"Using project ID: {self.project_id}")
        
        # 转换请求
        gemini_req = openai_request_to_gemini(request)
        payload = build_gemini_payload_from_openai(gemini_req)
        log.debug(f"Prepared Gemini payload: {payload}")
        return payload

    async def chat_completion(self, request: OpenAIChatCompletionRequest):
        """
        Handle a chat completion request, supports streaming and non-streaming.
        每次聊天都会轮换凭证
        """
        try:
            payload = await self._prepare_request(request)
        except Exception as e:
            log.error(f"Request preparation failed: {e}")
            return self._create_error_response(str(e), "invalid_request_error", 400)

        if request.stream:
            async def _streamer():
                try:
                    # ← 透传 creds 和 credential_manager
                    resp = await send_gemini_request(payload, is_streaming=True, creds=self.creds, credential_manager=self.credential_manager)
                    if isinstance(resp, StreamingResponse):
                        resp_id = "chatcmpl-" + str(uuid.uuid4())
                        async for chunk in resp.body_iterator:
                            text = chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk
                            if not text.startswith("data: "):
                                continue
                            body = json.loads(text[6:])
                            if "error" in body:
                                yield f"data: {json.dumps({'error': body['error']})}\n\n"
                                yield "data: [DONE]\n\n"
                                return
                            out = gemini_stream_chunk_to_openai(body, request.model, resp_id)
                            yield f"data: {json.dumps(out)}\n\n"
                            await asyncio.sleep(0)
                        yield "data: [DONE]\n\n"
                    else:
                        code = getattr(resp, "status_code", 500)
                        msg = f"Streaming request failed (status: {code})"
                        yield f"data: {json.dumps({'error': {'message': msg, 'type': 'api_error', 'code': code}})}\n\n"
                        yield "data: [DONE]\n\n"
                except Exception as ex:
                    log.error(f"Streaming exception: {ex}")
                    yield f"data: {json.dumps({'error': {'message': str(ex), 'type': 'api_error', 'code': 500}})}\n\n"
                    yield "data: [DONE]\n\n"

            return StreamingResponse(_streamer(), media_type="text/event-stream")

        # non-streaming
        resp = await send_gemini_request(payload, is_streaming=False, creds=self.creds, credential_manager=self.credential_manager)
        try:
            if isinstance(resp, Response) and resp.status_code != 200:
                body = resp.body.decode('utf-8') if isinstance(resp.body, bytes) else resp.body
                data = json.loads(body) if body else {}
                err = data.get("error", {"message": f"API error {resp.status_code}", "code": resp.status_code})
                return Response(
                    content=json.dumps({"error": err}),
                    status_code=resp.status_code,
                    media_type="application/json"
                )
            gemini_resp = json.loads(resp.body)
            return gemini_response_to_openai(gemini_resp, request.model)
        except Exception as e:
            log.error(f"chat_completion failed: {e}")
            return self._create_error_response(str(e))

    async def close(self):
        """
        Clean up any resources, if necessary.
        """
        log.info("Closing GeminiCli resources.")
        await self.credential_manager.close()