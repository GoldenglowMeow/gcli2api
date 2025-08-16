"""
High-performance credential manager with call-based rotation and caching.
Rotates credentials based on API call count rather than time for better quota distribution.
"""
import os
import json
import asyncio
import glob
import aiofiles
import toml
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple, Dict, Any
import httpx

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from .config import (
    CREDENTIALS_DIR, CODE_ASSIST_ENDPOINT, AUTO_BAN_ENABLED, AUTO_BAN_ERROR_CODES, 
    get_proxy_config, get_calls_per_rotation, get_http_timeout, get_max_connections,
    get_auto_ban_enabled, get_auto_ban_error_codes
)
from .utils import get_user_agent, get_client_metadata
from log import log
import re

class CredentialManager:
    """High-performance credential manager with call-based rotation and caching."""

    def __init__(self, calls_per_rotation: int = None):  # Use dynamic config by default
        self._lock = asyncio.Lock()
        self._current_credential_index = 0
        self._credential_files: List[str] = []
        
        # Call-based rotation instead of time-based
        self._cached_credentials: Optional[Credentials] = None
        self._cached_project_id: Optional[str] = None
        self._call_count = 0
        self._calls_per_rotation = calls_per_rotation or get_calls_per_rotation()
        
        # Onboarding state
        self._onboarding_complete = False
        self._onboarding_checked = False
        
        # HTTP client reuse
        self._http_client: Optional[httpx.AsyncClient] = None
        
        # TOML状态文件路径
        self._state_file = os.path.join(CREDENTIALS_DIR, "creds_state.toml")
        self._creds_state: Dict[str, Any] = {}
        
        # 当前使用的凭证文件路径
        self._current_file_path: Optional[str] = None
        
        self._initialized = False

    async def initialize(self):
        """Initialize the credential manager."""
        async with self._lock:
            if self._initialized:
                return
            
            # 加载状态文件
            await self._load_state()
            
            await self._discover_credential_files()
            
            # Initialize HTTP client with connection pooling and proxy support
            proxy = get_proxy_config()
            client_kwargs = {
                "timeout": get_http_timeout(),
                "limits": httpx.Limits(max_keepalive_connections=20, max_connections=get_max_connections())
            }
            if proxy:
                client_kwargs["proxy"] = proxy
            self._http_client = httpx.AsyncClient(**client_kwargs)
            
            self._initialized = True

    async def close(self):
        """Clean up resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def _load_state(self):
        """从TOML文件加载状态"""
        try:
            if os.path.exists(self._state_file):
                async with aiofiles.open(self._state_file, "r", encoding="utf-8") as f:
                    content = await f.read()
                self._creds_state = toml.loads(content)
            else:
                self._creds_state = {}
            
            # 清理过期的CD状态（UTC时间08:00刷新）
            await self._cleanup_expired_cd_status()
        except Exception as e:
            log.warning(f"Failed to load state file: {e}")
            self._creds_state = {}

    async def _save_state(self):
        """保存状态到TOML文件"""
        try:
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            async with aiofiles.open(self._state_file, "w", encoding="utf-8") as f:
                await f.write(toml.dumps(self._creds_state))
        except Exception as e:
            log.error(f"Failed to save state file: {e}")

    async def _cleanup_expired_cd_status(self):
        """清理过期的CD状态"""
        now = datetime.now(timezone.utc)
        today_8am = now.replace(hour=8, minute=0, second=0, microsecond=0)
        
        # 如果现在是08:00之后，清理昨天的CD状态
        if now >= today_8am:
            cutoff_time = today_8am
        else:
            # 如果现在是08:00之前，清理前天的CD状态
            cutoff_time = today_8am - timedelta(days=1)
        
        for filename in list(self._creds_state.keys()):
            cred_state = self._creds_state[filename]
            if "cd_until" in cred_state:
                cd_until = datetime.fromisoformat(cred_state["cd_until"])
                if cd_until <= cutoff_time:
                    cred_state.pop("cd_until", None)
                    log.info(f"Cleared expired CD status for {filename}")

    def _is_quota_exhausted_error(self, response_content: str) -> bool:
        """检查响应内容是否为配额耗尽错误（更精确的判断）"""
        if not response_content:
            return False
        
        try:
            # 尝试解析JSON响应
            response_data = json.loads(response_content)
            
            # 检查是否有error字段
            if "error" not in response_data:
                return False
            
            error = response_data["error"]
            
            # 检查错误码是否为429
            if error.get("code") != 429:
                return False
            
            # 检查状态是否为RESOURCE_EXHAUSTED
            if error.get("status") != "RESOURCE_EXHAUSTED":
                return False
            
            # 检查错误消息中是否包含特定的配额相关关键词
            message = error.get("message", "")
            
            # 检查是否包含关键的配额指标
            quota_patterns = [
                r"Quota exceeded for quota metric.*StreamGenerateContent Requests",
                r"limit.*StreamGenerateContent Requests per day per user per tier",
                r"project_number:\d+",  # 包含项目编号的错误
                r"consumer.*project_number"
            ]
            
            for pattern in quota_patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    log.debug(f"Found quota exhaustion pattern: {pattern} in message: {message[:100]}...")
                    return True
            
            log.debug(f"429 error but no quota exhaustion patterns found in message: {message[:100]}...")
            return False
            
        except json.JSONDecodeError:
            # 如果不是JSON，回退到关键词检查（保持向后兼容）
            log.debug("Response is not valid JSON, falling back to keyword check")
            return "1500" in response_content
        except Exception as e:
            log.warning(f"Error parsing response for quota check: {e}")
            return False
    
    def _get_cred_state(self, filename: str) -> Dict[str, Any]:
        """获取指定凭证文件的状态"""
        # 标准化路径以确保一致性
        normalized_filename = os.path.abspath(filename)
        
        # 先检查是否已存在（可能用不同的路径格式）
        existing_state = None
        existing_key = None
        for key, state in self._creds_state.items():
            if os.path.abspath(key) == normalized_filename:
                existing_state = state
                existing_key = key
                break
        
        if existing_state is not None:
            # 如果找到了现有状态但路径格式不同，更新键名
            if existing_key != normalized_filename:
                self._creds_state[normalized_filename] = existing_state
                del self._creds_state[existing_key]
                log.debug(f"Updated state key from {existing_key} to {normalized_filename}")
            return existing_state
        
        # 只有真正没有找到时才创建新状态
        if normalized_filename not in self._creds_state:
            log.debug(f"Creating new state for {normalized_filename}")
            self._creds_state[normalized_filename] = {
                "error_codes": [],
                "disabled": False,
                "last_success": None
            }
        return self._creds_state[normalized_filename]

    async def record_error(self, filename: str, status_code: int, response_content: str = ""):
        """记录API错误码"""
        async with self._lock:
            normalized_filename = os.path.abspath(filename)
            cred_state = self._get_cred_state(normalized_filename)
            
            # 记录错误码
            if "error_codes" not in cred_state:
                cred_state["error_codes"] = []
            if status_code not in cred_state["error_codes"]:
                cred_state["error_codes"].append(status_code)
            
            # 改进的CD机制：精确判断是否为配额耗尽错误
            if status_code == 429 and self._is_quota_exhausted_error(response_content):
                # 设置CD状态直到下一个UTC 08:00
                now = datetime.now(timezone.utc)
                today_8am = now.replace(hour=8, minute=0, second=0, microsecond=0)
                next_8am = today_8am if now < today_8am else today_8am + timedelta(days=1)
                cred_state["cd_until"] = next_8am.isoformat()
                log.warning(f"[CD_SET] Set CD status for {normalized_filename} until {next_8am} (429 + quota exhausted)")
                
                # 记录更详细的错误信息
                try:
                    error_data = json.loads(response_content)
                    error_message = error_data.get("error", {}).get("message", "")
                    log.info(f"Quota exhausted for {os.path.basename(normalized_filename)}: {error_message[:200]}...")
                except:
                    log.info(f"Quota exhausted for {os.path.basename(normalized_filename)} (legacy format)")
            elif status_code == 429:
                log.info(f"Got 429 error for {os.path.basename(normalized_filename)} but not a quota exhaustion error, no CD set")
                # 记录非配额耗尽的429错误内容供调试
                log.debug(f"429 error response content: {response_content[:300]}...")
            
            # 自动封禁功能
            auto_ban_enabled = get_auto_ban_enabled()
            auto_ban_error_codes = get_auto_ban_error_codes()
            log.debug(f"AUTO_BAN check: enabled={auto_ban_enabled}, status_code={status_code}, error_codes={auto_ban_error_codes}")
            if auto_ban_enabled and status_code in auto_ban_error_codes:
                if not cred_state.get("disabled", False):
                    cred_state["disabled"] = True
                    log.warning(f"AUTO_BAN: Disabled credential {os.path.basename(normalized_filename)} due to error {status_code}")
                else:
                    log.debug(f"Credential {os.path.basename(normalized_filename)} already disabled, error {status_code} recorded")
            elif auto_ban_enabled:
                log.debug(f"AUTO_BAN enabled but status_code {status_code} not in ban list {auto_ban_error_codes}")
            else:
                log.debug(f"AUTO_BAN disabled, status_code {status_code} recorded but no auto ban")
            
            await self._save_state()

    async def record_success(self, filename: str, api_type: str = "other"):
        """记录成功的API调用"""
        async with self._lock:
            normalized_filename = os.path.abspath(filename)
            cred_state = self._get_cred_state(normalized_filename)
            
            # 只有聊天内容生成API成功才清除错误码，其他API不清除
            if api_type == "chat_content":
                cred_state["error_codes"] = []
                log.debug(f"Cleared error codes for {normalized_filename} due to successful chat content generation")
            
            cred_state["last_success"] = datetime.now(timezone.utc).isoformat()
            
            await self._save_state()

    def is_cred_in_cd(self, filename: str) -> bool:
        """检查凭证是否处于CD状态"""
        cred_state = self._get_cred_state(filename)
        if "cd_until" not in cred_state:
            return False
        
        cd_until = datetime.fromisoformat(cred_state["cd_until"])
        is_in_cd = datetime.now(timezone.utc) < cd_until
        
        # 调试日志
        if is_in_cd:
            log.debug(f"[CD_CHECK] {os.path.basename(filename)} is in CD until {cd_until}")
        
        return is_in_cd

    def is_cred_disabled(self, filename: str) -> bool:
        """检查凭证是否被禁用"""
        cred_state = self._get_cred_state(filename)
        return cred_state.get("disabled", False)

    async def set_cred_disabled(self, filename: str, disabled: bool):
        """设置凭证的禁用状态"""
        async with self._lock:
            normalized_filename = os.path.abspath(filename)
            log.info(f"Setting disabled={disabled} for file: {normalized_filename}")
            cred_state = self._get_cred_state(normalized_filename)
            cred_state["disabled"] = disabled
            log.info(f"Updated state for {normalized_filename}: {cred_state}")
            await self._save_state()
            log.info(f"State saved successfully")

    def get_creds_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有凭证的状态信息"""
        status = {}
        # 获取所有文件，包括禁用和CD状态的
        credentials_dir = CREDENTIALS_DIR
        patterns = [os.path.join(credentials_dir, "*.json")]
        all_files = []
        for pattern in patterns:
            all_files.extend(glob.glob(pattern))
        all_files = sorted(list(set(all_files)))
        
        for filename in all_files:
            # 标准化路径以确保一致性
            normalized_filename = os.path.abspath(filename)
            cred_state = self._get_cred_state(normalized_filename)
            file_status = {
                "error_codes": cred_state.get("error_codes", []),
                "disabled": cred_state.get("disabled", False),
                "in_cd": self.is_cred_in_cd(normalized_filename),
                "last_success": cred_state.get("last_success")
            }
            status[normalized_filename] = file_status
            
            # 调试：记录特定文件的状态
            basename = os.path.basename(filename)
            if "atomic-affinity" in basename:
                log.info(f"Status for {basename}: disabled={file_status['disabled']} (normalized: {normalized_filename})")
                
        return status

    def get_current_file_path(self) -> Optional[str]:
        """获取当前使用的凭证文件路径"""
        return self._current_file_path

    async def _discover_credential_files(self):
        """Discover all credential files with hot reload support."""
        old_files = set(self._credential_files)
        all_files = []
        
        credentials_dir = CREDENTIALS_DIR
        patterns = [os.path.join(credentials_dir, "*.json")]
        
        for pattern in patterns:
            all_files.extend(glob.glob(pattern))
        
        all_files = sorted(list(set(all_files)))
        
        # 过滤掉被禁用和CD状态的文件
        self._credential_files = []
        for filename in all_files:
            is_disabled = self.is_cred_disabled(filename)
            is_in_cd = self.is_cred_in_cd(filename)
            
            if not is_disabled and not is_in_cd:
                self._credential_files.append(filename)
            else:
                # 记录被过滤的文件信息供调试
                status_info = []
                if is_disabled:
                    status_info.append("disabled")
                if is_in_cd:
                    status_info.append("in_cd")
                log.debug(f"Filtered out {os.path.basename(filename)}: {', '.join(status_info)}")
        
        new_files = set(self._credential_files)
        
        # 检测文件变化
        if old_files != new_files:
            added_files = new_files - old_files
            removed_files = old_files - new_files
            
            if added_files:
                log.info(f"发现新的可用凭证文件: {list(added_files)}")
                # 清除缓存以便使用新文件
                self._cached_credentials = None
                self._cached_project_id = None
            
            if removed_files:
                log.info(f"凭证文件已移除或不可用: {list(removed_files)}")
                # 如果当前使用的文件被移除，切换到下一个文件
                if self._credential_files and self._current_credential_index >= len(self._credential_files):
                    self._current_credential_index = 0
                    self._cached_credentials = None
                    self._cached_project_id = None
        
        # 同步状态文件，清理不存在的文件状态
        await self._sync_state_with_files(all_files)
        
        if not self._credential_files:
            log.warning("No available credential files found")
        else:
            available_files = [os.path.basename(f) for f in self._credential_files]
            log.info(f"Found {len(self._credential_files)} available credential files: {available_files}")

    async def _sync_state_with_files(self, current_files: List[str]):
        """同步状态文件与实际文件"""
        # 标准化当前文件列表
        normalized_current_files = [os.path.abspath(f) for f in current_files]
        
        # 移除不存在文件的状态
        files_to_remove = []
        for filename in list(self._creds_state.keys()):
            if filename not in normalized_current_files:
                files_to_remove.append(filename)
        
        if files_to_remove:
            for filename in files_to_remove:
                del self._creds_state[filename]
            await self._save_state()
            log.info(f"Removed state for deleted files: {files_to_remove}")

    def _is_cache_valid(self) -> bool:
        """Check if cached credentials are still valid based on call count and token expiration."""
        if not self._cached_credentials:
            return False
        
        # 如果没有凭证文件，缓存无效
        if not self._credential_files:
            return False
        
        # Check if we've reached the rotation threshold (use dynamic config)
        current_calls_per_rotation = get_calls_per_rotation()
        if self._call_count >= current_calls_per_rotation:
            return False
        
        # Check token expiration (with 60 second buffer)
        if self._cached_credentials.expired:
            return False
        
        return True

    async def _rotate_credential_if_needed(self):
        """Rotate to next credential if call limit reached."""
        current_calls_per_rotation = get_calls_per_rotation()
        if self._call_count >= current_calls_per_rotation:
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
            self._call_count = 0  # Reset call counter
            log.info(f"Rotated to credential index {self._current_credential_index}")

    async def _load_credential_with_fallback(self, current_file: str) -> Tuple[Optional[Credentials], Optional[str]]:
        """Load credentials with fallback to next file on failure."""
        creds, project_id = await self._load_credentials_from_file(current_file)
        if not creds:
            # Try next file on failure
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
            if self._current_credential_index < len(self._credential_files):
                current_file = self._credential_files[self._current_credential_index]
                creds, project_id = await self._load_credentials_from_file(current_file)
        return creds, project_id

    async def get_credentials(self) -> Tuple[Optional[Credentials], Optional[str]]:
        """Get credentials with call-based rotation, caching and hot reload for performance."""
        async with self._lock:
            # 修改文件检查策略：
            # 1. 启动时读取一次creds文件
            # 2. 当无任何creds时，每次使用chat都读取一次creds目录积极发现新文件
            # 3. 当有creds文件时，每次轮换的时候读取一次
            current_calls_per_rotation = get_calls_per_rotation()
            should_check_files = (
                not self._credential_files or  # 无文件时每次都检查
                self._call_count >= current_calls_per_rotation  # 轮换时检查
            )
            
            if should_check_files:
                await self._discover_credential_files()
            
            # Return cached credentials if valid and files exist
            if self._is_cache_valid() and self._credential_files:
                log.debug(f"Using cached credentials (call count: {self._call_count}/{current_calls_per_rotation})")
                return self._cached_credentials, self._cached_project_id
            
            # Cache miss or rotation needed - load fresh credentials
            if self._call_count >= current_calls_per_rotation:
                log.info(f"Rotating credentials after {self._call_count} calls")
            else:
                log.info("Cache miss - loading fresh credentials")
            
            # Rotate to next credential if we've reached the call limit
            await self._rotate_credential_if_needed()
            
            if not self._credential_files:
                log.error("No available credential files")
                return None, None
            
            current_file = self._credential_files[self._current_credential_index]
            
            # Load credentials from file with fallback
            creds, project_id = await self._load_credential_with_fallback(current_file)
            
            if creds:
                # Update cache
                self._cached_credentials = creds
                self._cached_project_id = project_id
                self._current_file_path = current_file
                log.info(f"Cached credentials from {current_file}")
            
            return creds, project_id

    async def _load_credentials_from_file(self, file_path: str) -> Tuple[Optional[Credentials], Optional[str]]:
        """Load credentials from file (optimized)."""
        try:
            async with aiofiles.open(file_path, "r") as f:
                content = await f.read()
            creds_data = json.loads(content)
            
            if "refresh_token" not in creds_data or not creds_data["refresh_token"]:
                log.warning(f"No refresh token in {file_path}")
                return None, None
            
            # Handle different credential formats
            if "access_token" in creds_data and "token" not in creds_data:
                creds_data["token"] = creds_data["access_token"]
            if "scope" in creds_data and "scopes" not in creds_data:
                creds_data["scopes"] = creds_data["scope"].split()
            
            # Handle expiry time format
            if "expiry" in creds_data and isinstance(creds_data["expiry"], str):
                try:
                    exp = creds_data["expiry"]
                    if "+00:00" in exp:
                        parsed = datetime.fromisoformat(exp)
                    elif exp.endswith("Z"):
                        parsed = datetime.fromisoformat(exp.replace('Z', '+00:00'))
                    else:
                        parsed = datetime.fromisoformat(exp)
                    ts = parsed.timestamp()
                    creds_data["expiry"] = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception as e:
                    log.warning(f"Could not parse expiry in {file_path}: {e}")
                    del creds_data["expiry"]
            
            creds = Credentials.from_authorized_user_info(creds_data, creds_data.get("scopes"))
            project_id = creds_data.get("project_id")
            setattr(creds, "project_id", project_id)
            
            # Refresh if needed (but only once per cache cycle)
            if creds.expired and creds.refresh_token:
                try:
                    log.debug(f"Refreshing credentials from {file_path}")
                    creds.refresh(GoogleAuthRequest())
                except Exception as e:
                    log.warning(f"Failed to refresh credentials from {file_path}: {e}")
            
            return creds, project_id
        except Exception as e:
            log.error(f"Failed to load credentials from {file_path}: {e}")
            return None, None

    async def increment_call_count(self):
        """Increment the call count for tracking rotation."""
        async with self._lock:
            self._call_count += 1
            current_calls_per_rotation = get_calls_per_rotation()
            log.debug(f"Call count incremented to {self._call_count}/{current_calls_per_rotation}")

    async def rotate_to_next_credential(self):
        """Manually rotate to next credential (for error recovery)."""
        async with self._lock:
            # Invalidate cache
            self._cached_credentials = None
            self._cached_project_id = None
            self._call_count = 0  # Reset call count
            
            # 重新发现可用凭证文件（过滤掉CD和禁用的文件）
            await self._discover_credential_files()
            
            # 如果没有可用凭证，早期返回
            if not self._credential_files:
                log.error("No available credentials to rotate to")
                return
            
            # Move to next credential
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
            log.info(f"Rotated to credential index {self._current_credential_index}, total available: {len(self._credential_files)}")
            
            # 记录当前使用的文件名称供调试
            if self._credential_files:
                current_file = self._credential_files[self._current_credential_index]
                log.info(f"Now using credential: {os.path.basename(current_file)}")

    def get_user_project_id(self, creds: Credentials) -> str:
        """Get user project ID from credentials."""
        project_id = getattr(creds, "project_id", None)
        if project_id:
            return project_id

        raise Exception(
            "Unable to determine Google Cloud project ID. "
            "Ensure credential file contains project_id."
        )

    async def onboard_user(self, creds: Credentials, project_id: str):
        """Optimized user onboarding with caching."""
        # Skip if already onboarded for this session
        if self._onboarding_complete:
            return
        
        async with self._lock:
            # Double-check after acquiring lock
            if self._onboarding_complete:
                return
            
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(GoogleAuthRequest())
                except Exception as e:
                    raise Exception(f"Failed to refresh credentials during onboarding: {str(e)}")
            
            headers = {
                "Authorization": f"Bearer {creds.token}",
                "Content-Type": "application/json",
                "User-Agent": get_user_agent(),
            }
            
            load_assist_payload = {
                "cloudaicompanionProject": project_id,
                "metadata": get_client_metadata(project_id),
            }
            
            try:
                # Use reusable HTTP client
                resp = await self._http_client.post(
                    f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist",
                    json=load_assist_payload,
                    headers=headers,
                )
                resp.raise_for_status()
                load_data = resp.json()
                
                # Determine tier
                tier = None
                if load_data.get("currentTier"):
                    tier = load_data["currentTier"]
                else:
                    for allowed_tier in load_data.get("allowedTiers", []):
                        if allowed_tier.get("isDefault"):
                            tier = allowed_tier
                            break
                    
                    if not tier:
                        tier = {
                            "name": "",
                            "description": "",
                            "id": "legacy-tier",
                            "userDefinedCloudaicompanionProject": True,
                        }

                if tier.get("userDefinedCloudaicompanionProject") and not project_id:
                    raise ValueError("This account requires setting the GOOGLE_CLOUD_PROJECT env var.")

                if load_data.get("currentTier"):
                    self._onboarding_complete = True
                    return

                # Onboard user
                onboard_req_payload = {
                    "tierId": tier.get("id"),
                    "cloudaicompanionProject": project_id,
                    "metadata": get_client_metadata(project_id),
                }

                while True:
                    onboard_resp = await self._http_client.post(
                        f"{CODE_ASSIST_ENDPOINT}/v1internal:onboardUser",
                        json=onboard_req_payload,
                        headers=headers,
                    )
                    onboard_resp.raise_for_status()
                    lro_data = onboard_resp.json()

                    if lro_data.get("done"):
                        self._onboarding_complete = True
                        break
                    
                    await asyncio.sleep(5)

            except httpx.HTTPStatusError as e:
                error_text = e.response.text if hasattr(e, 'response') else str(e)
                raise Exception(f"User onboarding failed. Please check your Google Cloud project permissions and try again. Error: {error_text}")
            except Exception as e:
                raise Exception(f"User onboarding failed due to an unexpected error: {str(e)}")

    async def get_credentials_and_project(self) -> Tuple[Optional[Credentials], Optional[str]]:
        """Get both credentials and project ID in one optimized call."""
        if not self._initialized:
            await self.initialize()
        
        # 如果当前没有文件，强制检查一次
        if not self._credential_files:
            log.info("No credentials found, forcing file discovery")
            async with self._lock:
                await self._discover_credential_files()
        
        return await self.get_credentials()
    
    async def test_auto_ban(self, filename: str, status_code: int = 403, response_content: str = ""):
        """测试自动封禁功能（仅用于调试）"""
        log.info(f"[TEST] Testing auto ban for file {filename} with status code {status_code}")
        log.info(f"[TEST] AUTO_BAN_ENABLED: {AUTO_BAN_ENABLED}")
        log.info(f"[TEST] AUTO_BAN_ERROR_CODES: {AUTO_BAN_ERROR_CODES}")
        await self.record_error(filename, status_code, response_content)
        
        # 检查状态
        cred_state = self._get_cred_state(filename)
        log.info(f"[TEST] After test, credential state: {cred_state}")
    
    async def test_cd_mechanism(self, filename: str, response_content: str = None):
        """测试CD机制（仅用于调试）"""
        if response_content is None:
            # 使用真实的配额耗尽错误格式
            response_content = '''{
  "error": {
    "code": 429,
    "message": "Quota exceeded for quota metric 'StreamGenerateContent Requests' and limit 'StreamGenerateContent Requests per day per user per tier' of service 'cloudcode-pa.googleapis.com' for consumer 'project_number:681255809395'.",
    "status": "RESOURCE_EXHAUSTED"
  }
}'''
        
        log.info(f"[TEST] Testing CD mechanism for file {filename}")
        log.info(f"[TEST] Response content: {response_content}")
        log.info(f"[TEST] Is quota exhausted: {self._is_quota_exhausted_error(response_content)}")
        await self.record_error(filename, 429, response_content)
        
        # 检查状态
        cred_state = self._get_cred_state(filename)
        log.info(f"[TEST] After CD test, credential state: {cred_state}")
        log.info(f"[TEST] CD until: {cred_state.get('cd_until', 'Not set')}")