"""用户凭证管理器，基于文件系统的多用户凭证管理"""
import os
import json
import asyncio
import glob
import aiofiles
import toml
import base64
import time
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
import httpx

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from config import (
    CREDENTIALS_DIR, CODE_ASSIST_ENDPOINT,
    get_proxy_config, get_calls_per_rotation, get_http_timeout, get_max_connections,
    get_auto_ban_enabled,
    get_auto_ban_error_codes
)
from .utils import get_user_agent, get_client_metadata
from log import log

class UserCredentialManager:
    """基于文件系统的用户凭证管理器，支持用户隔离"""

    def __init__(self, username: str = None, calls_per_rotation: int = None):
        """初始化用户凭证管理器

        Args:
            username: 用户名，如果为None则使用全局凭证目录
            calls_per_rotation: 每次轮换的调用次数
        """
        self._lock = asyncio.Lock()
        self.username = username
        self._user_credentials_dir = self._get_user_credentials_dir()
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
        if username:
            self._state_file = os.path.join(self._user_credentials_dir, "creds_state.toml")
        else:
            self._state_file = os.path.join(CREDENTIALS_DIR, "creds_state.toml")
        self._creds_state: Dict[str, Any] = {}

        # 当前使用的凭证文件路径
        self._current_file_path: Optional[str] = None

        # 最后一次文件扫描时间
        self._last_file_scan_time = 0

        self._initialized = False
        self._current_credential_index = 0
    
    def _get_user_credentials_dir(self) -> str:
        """获取用户凭证目录路径"""
        if self.username:
            return os.path.join(CREDENTIALS_DIR, self.username)
        return CREDENTIALS_DIR
    
    async def _discover_credential_files(self):
        """发现用户特定的凭证文件"""
        old_files = set(self._credential_files)
        all_files = []
        
        # 如果是用户模式，只扫描用户目录
        if self.username:
            user_dir = self._user_credentials_dir
            log.debug(f"用户 {self.username} 的凭证目录: {user_dir}")
            if os.path.exists(user_dir):
                patterns = [os.path.join(user_dir, "*.json")]
                for pattern in patterns:
                    discovered_files = glob.glob(pattern)
                    # 确保所有路径都是绝对路径
                    normalized_files = [os.path.abspath(f) for f in discovered_files]
                    all_files.extend(normalized_files)
                log.info(f"用户 {self.username} 发现 {len(all_files)} 个凭证文件: {[os.path.basename(f) for f in all_files]}")
            else:
                log.warning(f"用户凭证目录不存在: {user_dir}")
        else:
            # 管理员模式，使用原有逻辑（包括环境变量凭证）
            # 检查环境变量凭证
            env_creds_loaded = False
            for i in range(1, 11):
                env_var_name = f"GOOGLE_CREDENTIALS_{i}" if i > 1 else "GOOGLE_CREDENTIALS"
                env_creds = os.getenv(env_var_name)
                
                if env_creds:
                    try:
                        # 尝试解码base64
                        try:
                            decoded = base64.b64decode(env_creds)
                            env_creds = decoded.decode('utf-8')
                            log.debug(f"Decoded base64 credential from {env_var_name}")
                        except:
                            pass
                        
                        # 解析JSON凭证
                        cred_data = json.loads(env_creds)
                        
                        # 自动添加type字段
                        if 'type' not in cred_data and all(key in cred_data for key in ['client_id', 'refresh_token']):
                            cred_data['type'] = 'authorized_user'
                            log.debug(f"Auto-added 'type' field to credential from {env_var_name}")
                        
                        if all(key in cred_data for key in ['type', 'client_id', 'refresh_token']):
                            # 保存到临时文件以兼容现有代码
                            temp_file = os.path.join(CREDENTIALS_DIR, f"env_credential_{i}.json")
                            os.makedirs(CREDENTIALS_DIR, exist_ok=True)
                            with open(temp_file, 'w') as f:
                                json.dump(cred_data, f)
                            all_files.append(temp_file)
                            log.info(f"Loaded credential from environment variable: {env_var_name}")
                            env_creds_loaded = True
                        else:
                            log.warning(f"Invalid credential format in {env_var_name}")
                    except json.JSONDecodeError as e:
                        log.warning(f"Failed to parse JSON from {env_var_name}: {e}")
                    except Exception as e:
                        log.warning(f"Error loading credential from {env_var_name}: {e}")
            
            # 如果没有环境变量凭证，从目录发现
            if not env_creds_loaded:
                credentials_dir = CREDENTIALS_DIR
                patterns = [os.path.join(credentials_dir, "*.json")]
                
                for pattern in patterns:
                    discovered_files = glob.glob(pattern)
                    # 跳过env_credential文件
                    for file in discovered_files:
                        if not os.path.basename(file).startswith("env_credential_"):
                            # 确保使用绝对路径
                            abs_file = os.path.abspath(file)
                            all_files.append(abs_file)
        
        all_files = sorted(list(set(all_files)))
        
        # 过滤掉被禁用的文件
        self._credential_files = []
        disabled_count = 0
        for filename in all_files:
            is_disabled = self.is_cred_disabled(filename)
            
            if not is_disabled:
                # 确保使用绝对路径
                abs_filename = os.path.abspath(filename)
                self._credential_files.append(abs_filename)
                log.debug(f"凭证文件可用: {os.path.basename(filename)}")
            else:
                disabled_count += 1
                log.debug(f"Filtered out {os.path.basename(filename)}: disabled")
        
        if disabled_count > 0:
            log.info(f"过滤掉 {disabled_count} 个被禁用的凭证文件")
        
        new_files = set(self._credential_files)
        
        # 检测文件变化
        if old_files != new_files:
            added_files = new_files - old_files
            removed_files = old_files - new_files
            
            if added_files:
                log.info(f"发现新的可用凭证文件: {list(added_files)}")
                self._cached_credentials = None
                self._cached_project_id = None
            
            if removed_files:
                log.info(f"凭证文件已移除或不可用: {list(removed_files)}")
                if self._credential_files and self._current_credential_index >= len(self._credential_files):
                    self._current_credential_index = 0
                    self._cached_credentials = None
                    self._cached_project_id = None
        
        # 同步状态文件
        await self._sync_state_with_files(all_files)
        
        if not self._credential_files:
            if self.username:
                log.warning(f"用户 {self.username} 没有找到可用的凭证文件")
            else:
                log.warning("没有找到可用的凭证文件")
        else:
            available_files = [os.path.basename(f) for f in self._credential_files]
            if self.username:
                log.info(f"用户 {self.username} 找到 {len(self._credential_files)} 个可用凭证文件: {available_files}")
            else:
                log.info(f"找到 {len(self._credential_files)} 个可用凭证文件: {available_files}")
    
    def _get_cred_state(self, filename: str) -> Dict[str, Any]:
        """获取指定凭证文件的状态，支持用户隔离"""
        # 对于用户模式，使用相对于用户目录的路径作为键
        if self.username:
            # 标准化为相对于用户目录的路径
            if filename.startswith(self._user_credentials_dir):
                relative_filename = os.path.relpath(filename, self._user_credentials_dir)
            else:
                relative_filename = os.path.basename(filename)
            log.debug(f"用户 {self.username} 获取凭证状态: {relative_filename}")
        else:
            # 管理员模式，使用文件名作为键
            relative_filename = os.path.basename(filename)
            log.debug(f"管理员模式获取凭证状态: {relative_filename}")

        # 检查是否已存在
        if relative_filename in self._creds_state:
            state = self._creds_state[relative_filename]
            log.debug(f"凭证状态已存在: {relative_filename}, disabled: {state.get('disabled', False)}, errors: {len(state.get('error_codes', []))}")
            return state

        # 创建新状态
        log.debug(f"为凭证文件创建新状态: {relative_filename} (用户: {self.username})")
        self._creds_state[relative_filename] = {
            "error_codes": [],
            "disabled": False,
            "last_success": None,
            "user_email": None
        }
        return self._creds_state[relative_filename]

    def is_cred_disabled(self, filename: str) -> bool:
        """检查凭证文件是否被禁用"""
        cred_state = self._get_cred_state(filename)
        return cred_state.get("disabled", False)

    async def set_cred_disabled(self, filename: str, disabled: bool) -> None:
        """设置凭证文件的禁用状态"""
        cred_state = self._get_cred_state(filename)
        cred_state["disabled"] = disabled
        await self._save_state()

        # 如果文件被禁用，从可用文件列表中移除；如果被启用，强制刷新文件列表
        if disabled and self._credential_files:
            # 移除已禁用的文件
            abs_filename = os.path.abspath(filename)
            if abs_filename in self._credential_files:
                self._credential_files.remove(abs_filename)
                log.info(f"从可用文件列表中移除了被禁用的文件: {os.path.basename(filename)}")
        else:
            # 强制刷新以包含新启用的文件
            await self.force_refresh_credential_files()
    
    async def _discover_credential_files_unlocked(self):
        """用户感知的无锁文件发现操作"""
        log.debug(f"用户 {self.username} 开始无锁文件发现操作")
        
        # 临时存储发现的文件
        temp_files = []
        
        try:
            if self.username:
                # 用户模式：只扫描用户特定目录
                user_dir = self._user_credentials_dir
                log.debug(f"用户模式扫描目录: {user_dir}")
                
                if os.path.exists(user_dir):
                    import glob
                    json_pattern = os.path.join(user_dir, "*.json")
                    all_json_files = glob.glob(json_pattern)
                    log.debug(f"用户 {self.username} 在目录中找到 {len(all_json_files)} 个JSON文件")
                    
                    file_creds_found = 0
                    disabled_file_creds = 0
                    
                    for filepath in all_json_files:
                        filename = os.path.basename(filepath)
                        # 检查禁用状态
                        if not self.is_cred_disabled(filepath):
                            temp_files.append(os.path.abspath(filepath))
                            file_creds_found += 1
                            log.debug(f"用户 {self.username} 添加可用文件凭证: {filename}")
                        else:
                            disabled_file_creds += 1
                            log.debug(f"用户 {self.username} 文件凭证被禁用: {filename}")
                    
                    log.info(f"用户 {self.username} 文件系统凭证检查完成，找到 {file_creds_found} 个可用凭证，{disabled_file_creds} 个被禁用")
                else:
                    log.warning(f"用户 {self.username} 凭证目录不存在: {user_dir}")
            else:
                # 管理员模式：直接返回，不扫描文件
                log.debug("管理员模式，不进行文件扫描")
                return
            
            log.info(f"用户 {self.username} 总计发现 {len(temp_files)} 个可用凭证文件")
            
            # 在锁内快速更新文件列表
            async with self._lock:
                old_files = set(self._credential_files)
                new_files = set(temp_files)
                
                if old_files != new_files:
                    log.info(f"用户 {self.username} 凭证文件列表发生变化")
                    
                    # 检查新增的文件
                    added_files = new_files - old_files
                    if added_files:
                        log.info(f"用户 {self.username} 发现新的可用凭证文件: {list(added_files)}")
                    
                    # 检查移除的文件
                    removed_files = old_files - new_files
                    if removed_files:
                        log.info(f"用户 {self.username} 移除不可用凭证文件: {list(removed_files)}")
                    
                    # 更新文件列表
                    self._credential_files = temp_files
                    
                    # 同步状态文件
                    await self._sync_state_with_files(temp_files)
                    
                    # 如果当前索引超出范围，重置为0
                    if self._credential_files and self._current_credential_index >= len(self._credential_files):
                        self._current_credential_index = 0
                        log.info(f"用户 {self.username} 重置凭证索引为 0")
                else:
                    log.debug(f"用户 {self.username} 凭证文件列表无变化")
        
        except Exception as e:
            log.error(f"用户 {self.username} 文件发现过程中出错: {e}")
    
    def get_creds_status(self) -> Dict[str, Dict[str, Any]]:
        """获取用户特定的凭证状态信息"""
        status = {}
        
        # 获取用户特定的文件
        if self.username:
            user_dir = self._user_credentials_dir
            if os.path.exists(user_dir):
                patterns = [os.path.join(user_dir, "*.json")]
                all_files = []
                for pattern in patterns:
                    all_files.extend(glob.glob(pattern))
                all_files = sorted(list(set(all_files)))
        else:
            # 管理员模式，获取所有文件
            credentials_dir = CREDENTIALS_DIR
            patterns = [os.path.join(credentials_dir, "*.json")]
            all_files = []
            for pattern in patterns:
                all_files.extend(glob.glob(pattern))
            all_files = sorted(list(set(all_files)))
        
        for filename in all_files:
            absolute_filename = os.path.abspath(filename)
            cred_state = self._get_cred_state(filename)
            file_status = {
                "error_codes": cred_state.get("error_codes", []),
                "disabled": cred_state.get("disabled", False),
                "last_success": cred_state.get("last_success"),
                "user_email": cred_state.get("user_email")
            }
            status[absolute_filename] = file_status
        
        return status
    
    async def save_user_credential(self, filename: str, credential_data: dict) -> str:
        """保存用户凭证文件
        
        Args:
            filename: 文件名（不包含路径）
            credential_data: 凭证数据
            
        Returns:
            保存的文件完整路径
        """
        if not self.username:
            raise ValueError("Cannot save user credential without username")
        
        # 确保用户目录存在
        os.makedirs(self._user_credentials_dir, exist_ok=True)
        
        # 构建完整文件路径
        file_path = os.path.join(self._user_credentials_dir, filename)
        
        # 保存文件
        async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(credential_data, indent=2))
        
        log.info(f"Saved credential file for user {self.username}: {filename}")
        
        # 强制刷新凭证文件列表
        await self.force_refresh_credential_files()
        
        return file_path
    
    async def delete_user_credential(self, filename: str) -> bool:
        """删除用户凭证文件
        
        Args:
            filename: 文件名（不包含路径）
            
        Returns:
            是否成功删除
        """
        if not self.username:
            raise ValueError("Cannot delete user credential without username")
        
        file_path = os.path.join(self._user_credentials_dir, filename)
        
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                log.info(f"Deleted credential file for user {self.username}: {filename}")
                
                # 从状态中移除
                async with self._lock:
                    relative_filename = os.path.basename(filename)
                    if relative_filename in self._creds_state:
                        del self._creds_state[relative_filename]
                        await self._save_state()
                
                # 强制刷新凭证文件列表
                await self.force_refresh_credential_files()
                
                return True
            else:
                log.warning(f"Credential file not found for user {self.username}: {filename}")
                return False
        except Exception as e:
            log.error(f"Failed to delete credential file for user {self.username}: {filename}, error: {e}")
            return False
    
    def get_user_credential_files(self) -> List[str]:
        """获取用户的凭证文件列表（带缓存优化）

        Returns:
            文件名列表（不包含路径）
        """
        if not self.username:
            return []

        user_dir = self._user_credentials_dir
        if not os.path.exists(user_dir):
            return []

        # 简单的文件列表缓存，避免每次都扫描目录
        current_time = time.time()
        if (hasattr(self, '_files_cache') and
            hasattr(self, '_files_cache_time') and
            current_time - self._files_cache_time < 30):  # 30秒缓存
            return self._files_cache

        files = []
        for filename in os.listdir(user_dir):
            if filename.endswith('.json'):
                files.append(filename)

        # 更新缓存
        self._files_cache = sorted(files)
        self._files_cache_time = current_time

        return self._files_cache
    
    async def get_user_credential_content(self, filename: str) -> Optional[dict]:
        """获取用户凭证文件内容（隐藏敏感信息）
        
        Args:
            filename: 文件名（不包含路径）
            
        Returns:
            凭证内容（敏感信息已隐藏）
        """
        if not self.username:
            return None
        
        file_path = os.path.join(self._user_credentials_dir, filename)
        
        try:
            if not os.path.exists(file_path):
                return None
            
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            credential_data = json.loads(content)
            
            # 隐藏敏感信息
            safe_data = credential_data.copy()
            sensitive_fields = ['refresh_token', 'access_token', 'token', 'client_secret']
            
            for field in sensitive_fields:
                if field in safe_data:
                    safe_data[field] = "***HIDDEN***"
            
            return safe_data
            
        except Exception as e:
            log.error(f"Failed to read credential file for user {self.username}: {filename}, error: {e}")
            return None

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

    async def _sync_state_with_files(self, current_files: List[str]):
        """同步状态文件与实际文件"""
        # 标准化当前文件列表为相对路径
        normalized_current_files = [self._normalize_to_relative_path(f) for f in current_files]

        # 移除不存在文件的状态
        files_to_remove = []
        for filename in list(self._creds_state.keys()):
            # 将状态文件中的键标准化为相对路径进行比较
            normalized_state_key = self._normalize_to_relative_path(filename) if not filename.startswith('<ENV_') else filename
            if normalized_state_key not in normalized_current_files:
                files_to_remove.append(filename)

        if files_to_remove:
            for filename in files_to_remove:
                del self._creds_state[filename]
            await self._save_state()
            log.info(f"Removed state for deleted files: {files_to_remove}")

    def _normalize_to_relative_path(self, filepath: str) -> str:
        """将文件路径标准化为相对于base_dir的相对路径"""
        base_dir = self._user_credentials_dir

        # 如果已经是相对路径且在当前目录内，直接返回
        if not os.path.isabs(filepath):
            # 检查相对路径是否安全（不包含..等）
            if ".." not in filepath and filepath.endswith('.json'):
                return os.path.basename(filepath)  # 只保留文件名

        # 绝对路径转相对路径
        abs_filepath = os.path.abspath(filepath)
        abs_base_dir = os.path.abspath(base_dir)

        try:
            # 如果文件在base_dir内，返回相对路径（只要文件名）
            if abs_filepath.startswith(abs_base_dir):
                return os.path.basename(abs_filepath)
        except Exception:
            pass

        # 其他情况也只返回文件名
        return os.path.basename(filepath)

    def _is_cache_valid(self) -> bool:
        """Check if cached credentials are still valid based on call count and token expiration."""
        if not self._cached_credentials:
            return False

        # 如果没有凭证文件，缓存无效
        if not self._credential_files:
            return False

        # Check if we've reached the rotation threshold
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

    async def _force_rotate_credential(self):
        """Force rotate to next credential immediately (used for 429 errors)."""
        if len(self._credential_files) <= 1:
            log.warning("Only one credential available, cannot rotate")
            return

        old_index = self._current_credential_index
        self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
        self._call_count = 0  # Reset call counter

        # 清理缓存状态以确保使用新凭证
        self._cached_credentials = None
        self._cached_project_id = None
        self._current_file_path = None

        log.info(f"Force rotated from credential index {old_index} to {self._current_credential_index} due to 429 error")

    async def _load_credential_with_fallback(self, current_file: str) -> Tuple[Optional[Credentials], Optional[str]]:
        """Load credentials with fallback to next file on failure."""
        log.debug(f"尝试加载凭证文件: {os.path.basename(current_file)}")
        creds, project_id = await self._load_credentials_from_file(current_file)

        if not creds:
            log.warning(f"凭证文件加载失败，尝试下一个文件: {os.path.basename(current_file)}")
            # Try next file on failure
            original_index = self._current_credential_index
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)

            if self._current_credential_index < len(self._credential_files) and self._current_credential_index != original_index:
                current_file = self._credential_files[self._current_credential_index]
                log.info(f"切换到下一个凭证文件: {os.path.basename(current_file)} (索引: {self._current_credential_index})")
                creds, project_id = await self._load_credentials_from_file(current_file)

                if creds:
                    log.info(f"备用凭证文件加载成功: {os.path.basename(current_file)}")
                else:
                    log.error(f"备用凭证文件也加载失败: {os.path.basename(current_file)}")
            else:
                log.error("没有更多可用的凭证文件进行回退")
        else:
            log.debug(f"凭证文件加载成功: {os.path.basename(current_file)}")

        return creds, project_id

    async def get_credentials(self) -> Tuple[Optional[Credentials], Optional[str]]:
        """Get credentials with call-based rotation, caching and hot reload for performance."""
        log.debug("开始获取凭证")

        # 第一阶段：快速检查缓存（减少锁持有时间）
        async with self._lock:
            current_calls_per_rotation = get_calls_per_rotation()
            log.debug(f"当前轮换配置: {current_calls_per_rotation} 次调用后轮换")

            # 检查是否可以使用缓存，并验证当前文件是否仍然可用
            if self._is_cache_valid() and self._credential_files:
                # 额外检查：确保当前使用的文件没有被禁用
                current_file_still_valid = (
                    self._current_file_path and
                    not self.is_cred_disabled(self._current_file_path) and
                    self._current_file_path in self._credential_files
                )

                if current_file_still_valid:
                    log.debug(f"使用缓存的凭证 (调用计数: {self._call_count}/{current_calls_per_rotation})")
                    return self._cached_credentials, self._cached_project_id
                else:
                    log.info(f"当前凭证文件 {self._current_file_path} 不再有效，清除缓存")
                    self._cached_credentials = None
                    self._cached_project_id = None

            # 检查是否需要重新发现文件
            current_time = time.time()
            should_check_files = (
                not self._credential_files or  # 无文件时每次都检查
                self._call_count >= current_calls_per_rotation or  # 轮换时检查
                not self._cached_credentials or  # 无缓存凭证时也检查（确保新文件能被及时发现）
                current_time - self._last_file_scan_time > 30  # 每30秒至少扫描一次文件
            )
            log.debug(f"是否需要检查文件: {should_check_files}")

        # 第二阶段：如果需要，在锁外进行文件发现（避免阻塞其他操作）
        if should_check_files:
            log.debug("开始文件发现过程")
            # 文件发现操作不需要锁，因为它主要是读操作
            await self._discover_credential_files_unlocked()
            # 更新扫描时间
            async with self._lock:
                self._last_file_scan_time = current_time

        # 第三阶段：获取凭证（持有锁但时间较短）
        async with self._lock:
            current_calls_per_rotation = get_calls_per_rotation()  # 重新获取配置

            # 再次检查缓存（可能在文件发现过程中被其他操作更新）
            if self._is_cache_valid() and self._credential_files:
                # 验证当前文件是否仍然可用
                current_file_still_valid = (
                    self._current_file_path and
                    not self.is_cred_disabled(self._current_file_path) and
                    self._current_file_path in self._credential_files
                )

                if current_file_still_valid:
                    log.debug(f"文件发现后使用缓存的凭证")
                    return self._cached_credentials, self._cached_project_id
                else:
                    log.info(f"文件发现后当前凭证文件 {self._current_file_path} 不再有效，强制重新加载")

            # 需要加载新凭证
            if self._call_count >= current_calls_per_rotation:
                log.info(f"在 {self._call_count} 次调用后轮换凭证")
            else:
                log.info("缓存未命中 - 加载新凭证")

            # 轮换凭证
            await self._rotate_credential_if_needed()

            if not self._credential_files:
                log.error("没有可用的凭证文件")
                return None, None

            log.debug(f"当前有 {len(self._credential_files)} 个可用凭证文件")
            current_file = self._credential_files[self._current_credential_index]
            log.info(f"尝试加载凭证文件: {os.path.basename(current_file)} (索引: {self._current_credential_index})")

            # 记录当前使用的文件路径
            self._current_file_path = current_file

        # 第四阶段：在锁外加载凭证文件（避免I/O阻塞其他操作）
        creds, project_id = await self._load_credential_with_fallback(current_file)

        # 第五阶段：更新缓存（短时间持有锁）
        async with self._lock:
            if creds:
                log.info(f"凭证加载成功，project_id: {project_id}")
                self._cached_credentials = creds
                self._cached_project_id = project_id
                self._cache_timestamp = time.time()
                log.debug(f"已加载并缓存来自 {os.path.basename(current_file)} 的凭证")
            else:
                log.error(f"从 {current_file} 加载凭证失败")

            return creds, project_id

    async def _load_credentials_from_file(self, file_path: str) -> Tuple[Optional[Credentials], Optional[str]]:
        """Load credentials from file (optimized)."""
        log.debug(f"开始加载凭证文件: {file_path}")
        try:
            async with aiofiles.open(file_path, "r") as f:
                content = await f.read()
            log.debug(f"成功读取凭证文件内容，长度: {len(content)} 字符")

            creds_data = json.loads(content)
            log.debug(f"成功解析JSON，包含字段: {list(creds_data.keys())}")

            if "refresh_token" not in creds_data or not creds_data["refresh_token"]:
                log.warning(f"凭证文件 {file_path} 缺少refresh_token或为空")
                return None, None

            # Auto-add 'type' field if missing but has required OAuth fields
            if 'type' not in creds_data and all(key in creds_data for key in ['client_id', 'refresh_token']):
                creds_data['type'] = 'authorized_user'
                log.debug(f"Auto-added 'type' field to credential from file {file_path}")

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

            log.debug(f"创建Google Credentials对象，scopes: {creds_data.get('scopes')}")
            creds = Credentials.from_authorized_user_info(creds_data, creds_data.get("scopes"))
            project_id = creds_data.get("project_id")
            setattr(creds, "project_id", project_id)
            log.debug(f"凭证对象创建成功，project_id: {project_id}")

            # 检查凭证是否过期
            log.debug(f"检查凭证过期状态: expired={creds.expired}, expiry={getattr(creds, 'expiry', 'None')}")

            # Refresh if needed (but only once per cache cycle)
            if creds.expired and creds.refresh_token:
                try:
                    log.info(f"凭证已过期，开始刷新: {file_path}")
                    creds.refresh(GoogleAuthRequest())
                    log.info(f"凭证刷新成功: {file_path}")
                except Exception as e:
                    log.error(f"凭证刷新失败 {file_path}: {e}")
                    return None, None
            elif creds.expired:
                log.warning(f"凭证已过期但无refresh_token: {file_path}")
                return None, None
            else:
                log.debug(f"凭证未过期，直接使用: {file_path}")

            log.info(f"凭证加载成功: {file_path}")
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

            # 重新发现可用凭证文件（过滤掉禁用的文件）
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

    async def force_refresh_credential_files(self):
        """强制刷新凭证文件列表，用于检测新添加的凭证文件"""
        if not self._initialized:
            await self.initialize()

        log.info("Forcing credential files refresh")
        async with self._lock:
            # 清除缓存，强制重新加载
            self._cached_credentials = None
            self._cached_project_id = None
            self._cache_timestamp = 0

            # 重新发现凭证文件
            await self._discover_credential_files()

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

    def get_current_file_path(self) -> Optional[str]:
        """获取当前使用的凭证文件路径。

        Returns:
            当前使用的凭证文件绝对路径，如果没有则返回None
        """
        return self._current_file_path

    async def record_error(self, filename: str, status_code: int, response_content: str = "") -> None:
        """记录API调用错误并更新凭证状态。

        Args:
            filename: 凭证文件名（绝对路径）
            status_code: HTTP状态码
            response_content: 响应内容（用于错误分析）
        """
        try:
            # 更新最后一次成功记录
            cred_state = self._get_cred_state(filename)
            cred_state["last_success"] = None  # 清除成功记录

            # 处理429错误（配额超限）
            if status_code == 429:
                # 对于429错误，可能需要特殊处理
                log.warning(f"429 error recorded for credential: {os.path.basename(filename)}")

            # 处理其他错误
            elif status_code >= 400:
                # 记录错误码
                error_codes = cred_state.get("error_codes", [])
                if status_code not in error_codes:
                    error_codes.append(status_code)
                    cred_state["error_codes"] = error_codes[:50]  # 限制错误码历史记录数量

                log.debug(f"Error {status_code} recorded for credential: {os.path.basename(filename)}")

            # 保存凭证状态
            await self._save_state()

            log.debug(f"Error recorded for credential {os.path.basename(filename)}: status_code={status_code}")

        except Exception as e:
            log.warning(f"Failed to record error for credential {os.path.basename(filename)}: {e}")

    async def record_success(self, filename: str, content_type: str = "chat_content") -> None:
        """记录API调用成功并更新凭证状态。

        Args:
            filename: 凭证文件名（绝对路径）
            content_type: 内容类型（默认为chat_content）
        """
        try:
            # 更新最后一次成功记录
            cred_state = self._get_cred_state(filename)
            cred_state["last_success"] = datetime.now(timezone.utc).isoformat()

            # 清除错误码（在成功调用后）
            cred_state["error_codes"] = []

            # 保存凭证状态
            await self._save_state()

            log.debug(f"Success recorded for credential {os.path.basename(filename)}: content_type={content_type}")

        except Exception as e:
            log.warning(f"Failed to record success for credential {os.path.basename(filename)}: {e}")