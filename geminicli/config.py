"""
Configuration constants for the Geminicli2api proxy server.
Centralizes all configuration to avoid duplication across modules.
"""
import os

# API Endpoints
CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"

# Client Configuration
CLI_VERSION = "0.1.5"  # Match current gemini-cli version

# 凭证目录
CREDENTIALS_DIR = "geminicli/creds"

# 自动封禁配置
AUTO_BAN_ENABLED = os.getenv("AUTO_BAN", "true").lower() in ("true", "1", "yes", "on")

# 需要自动封禁的错误码
AUTO_BAN_ERROR_CODES = [400, 403]

# 启动时打印配置（用于调试）
print(f"[DEBUG] AUTO_BAN environment variable: {os.getenv('AUTO_BAN', 'not set')}")
print(f"[DEBUG] AUTO_BAN_ENABLED: {AUTO_BAN_ENABLED}")
print(f"[DEBUG] AUTO_BAN_ERROR_CODES: {AUTO_BAN_ERROR_CODES}")

# Default Safety Settings for Google API
DEFAULT_SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
]

# Helper function to get base model name from any variant
def get_base_model_name(model_name):
    """Convert variant model name to base model name."""
    # Remove all possible suffixes in order
    suffixes = ["-maxthinking", "-nothinking"]
    for suffix in suffixes:
        if model_name.endswith(suffix):
            return model_name[:-len(suffix)]
    return model_name

# Helper function to check if model uses no thinking
def is_nothinking_model(model_name):
    """Check if model name indicates thinking should be disabled."""
    return "-nothinking" in model_name

# Helper function to check if model uses max thinking
def is_maxthinking_model(model_name):
    """Check if model name indicates maximum thinking budget should be used."""
    return "-maxthinking" in model_name

# Helper function to get thinking budget for a model
def get_thinking_budget(model_name):
    """Get the appropriate thinking budget for a model based on its name and variant."""
    
    if is_nothinking_model(model_name):
        return 128  # Limited thinking for pro
    elif is_maxthinking_model(model_name):
        return 32768
    else:
        # Default thinking budget for regular models
        return -1  # Default for all models

# Helper function to check if thinking should be included in output
def should_include_thoughts(model_name):
    """Check if thoughts should be included in the response."""
    if is_nothinking_model(model_name):
        # For nothinking mode, still include thoughts if it's a pro model
        base_model = get_base_model_name(model_name)
        return "gemini-2.5-pro" in base_model
    else:
        # For all other modes, include thoughts
        return True