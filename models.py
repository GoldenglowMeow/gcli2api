import time
import uuid
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal, Union

class Model(BaseModel):
    id: str
    object: str = "model"
    created: int = Field(default_factory=lambda: int(time.time()))

class ModelList(BaseModel):
    object: str = "list"
    data: List[Model]

class ChatMessage(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    role: Literal["system", "user", "assistant"]
    content: Union[str, List[Dict[str, Any]]]
    userId: Optional[str] = None # Added for user messages
    createdAt: Optional[str] = None # Added for timestamping
    traceId: Optional[str] = None # Added for assistant messages

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 1.0
    max_tokens: Optional[int] = None
    top_p: Optional[float] = 1.0
    top_k: Optional[int] = None
    stream: Optional[bool] = False
    stop: Optional[List[str]] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    seed: Optional[int] = None
    logprobs: Optional[int] = None
    response_logprobs: Optional[bool] = None
    n: Optional[int] = None
    response_format: Optional[Dict[str, Any]] = None

# Gemini format models
class GeminiPart(BaseModel):
    text: Optional[str] = None
    inlineData: Optional[Dict[str, str]] = None  # {mimeType: str, data: str}

class GeminiContent(BaseModel):
    role: Literal["user", "model"]
    parts: List[GeminiPart]

class GeminiGenerationConfig(BaseModel):
    temperature: Optional[float] = None
    topP: Optional[float] = None
    topK: Optional[int] = None
    maxOutputTokens: Optional[int] = None
    stopSequences: Optional[List[str]] = None
    frequencyPenalty: Optional[float] = None
    presencePenalty: Optional[float] = None
    candidateCount: Optional[int] = None
    seed: Optional[int] = None

class GeminiRequest(BaseModel):
    model: Optional[str] = None
    contents: List[GeminiContent]
    systemInstruction: Optional[Union[str, Dict[str, Any]]] = None
    generationConfig: Optional[GeminiGenerationConfig] = None
    stream: Optional[bool] = False

# Union type for accepting both formats
UniversalChatRequest = Union[ChatCompletionRequest, GeminiRequest, Dict[str, Any]]