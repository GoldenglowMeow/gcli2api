"""
Configuration constants for the Geminicli2api proxy server.
Centralizes all configuration to avoid duplication across modules.
"""
import os
import httpx
import toml
from typing import Any, Optional

# API Endpoints
CODE_ASSIST_ENDPOINT = os.getenv("CODE_ASSIST_ENDPOINT", "https://cloudcode-pa.googleapis.com")

# Client Configuration
CLI_VERSION = "0.1.5"  # Match current gemini-cli version

# 凭证目录
CREDENTIALS_DIR = "geminicli/creds"

# 自动封禁配置
AUTO_BAN_ENABLED = os.getenv("AUTO_BAN", "false").lower() in ("true", "1", "yes", "on")

# 需要自动封禁的错误码
AUTO_BAN_ERROR_CODES = [400, 403, 401]

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

# Dynamic Configuration System
_config_cache = {}
_config_cache_time = 0

def _load_toml_config() -> dict:
    """Load configuration from dedicated config.toml file."""
    global _config_cache, _config_cache_time
    
    try:
        config_file = os.path.join(CREDENTIALS_DIR, "config.toml")
        
        # Check if file exists and get modification time
        if not os.path.exists(config_file):
            return {}
        
        file_time = os.path.getmtime(config_file)
        
        # Return cached config if file hasn't changed
        if file_time <= _config_cache_time and _config_cache:
            return _config_cache
        
        # Load fresh config
        with open(config_file, "r", encoding="utf-8") as f:
            toml_data = toml.load(f)
        
        _config_cache = toml_data
        _config_cache_time = file_time
        
        return toml_data
    
    except Exception:
        return {}

def get_config_value(key: str, default: Any = None, env_var: Optional[str] = None) -> Any:
    """Get configuration value with priority: ENV > TOML > default."""
    # Check environment variable first
    if env_var and os.getenv(env_var):
        return os.getenv(env_var)
    
    # Check TOML configuration
    toml_config = _load_toml_config()
    if key in toml_config:
        return toml_config[key]
    
    # Return default
    return default

def save_config_to_toml(config_data: dict) -> None:
    """Save configuration to config.toml file."""
    try:
        config_file = os.path.join(CREDENTIALS_DIR, "config.toml")
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, "w", encoding="utf-8") as f:
            toml.dump(config_data, f)
        
        # Force cache refresh
        global _config_cache, _config_cache_time
        _config_cache = config_data
        _config_cache_time = os.path.getmtime(config_file)
        
    except Exception as e:
        raise Exception(f"Failed to save config: {e}")

def reload_config_cache() -> None:
    """Force reload configuration cache."""
    global _config_cache, _config_cache_time
    _config_cache = {}
    _config_cache_time = 0

# Proxy Configuration
def get_proxy_config():
    """Get proxy configuration from PROXY environment variable or TOML config."""
    proxy_url = get_config_value("proxy", env_var="PROXY")
    if not proxy_url:
        return None
    
    # httpx supports http, https, socks5 proxies
    # Format: http://proxy:port, https://proxy:port, socks5://proxy:port
    return proxy_url

# Dynamic configuration getters
def get_calls_per_rotation() -> int:
    """Get calls per rotation setting."""
    return int(get_config_value("calls_per_rotation", 10))

def get_http_timeout() -> float:
    """Get HTTP timeout setting."""
    return float(get_config_value("http_timeout", 30.0))

def get_max_connections() -> int:
    """Get max connections setting."""
    return int(get_config_value("max_connections", 100))

def get_auto_ban_enabled() -> bool:
    """Get auto ban enabled setting."""
    env_value = os.getenv("AUTO_BAN")
    if env_value:
        return env_value.lower() in ("true", "1", "yes", "on")
    
    return bool(get_config_value("auto_ban_enabled", AUTO_BAN_ENABLED))

def get_auto_ban_error_codes() -> list:
    """Get auto ban error codes."""
    toml_codes = get_config_value("auto_ban_error_codes")
    if toml_codes and isinstance(toml_codes, list):
        return toml_codes
    return AUTO_BAN_ERROR_CODES