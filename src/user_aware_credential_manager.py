"""用户感知的凭证管理器，支持用户隔离的凭证管理"""
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
from .credential_manager import CredentialManager, _normalize_to_relative_path


class UserAwareCredentialManager(CredentialManager):
    """用户感知的凭证管理器，支持用户隔离的凭证管理"""
    
    def __init__(self, username: str = None, calls_per_rotation: int = None):
        """初始化用户感知的凭证管理器
        
        Args:
            username: 用户名，如果为None则使用全局凭证目录
            calls_per_rotation: 每次轮换的调用次数
        """
        super().__init__(calls_per_rotation)
        self.username = username
        self._user_credentials_dir = self._get_user_credentials_dir()
        
        # 用户特定的状态文件
        if username:
            self._state_file = os.path.join(self._user_credentials_dir, "creds_state.toml")
        else:
            self._state_file = os.path.join(CREDENTIALS_DIR, "creds_state.toml")
    
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
            # 管理员模式，使用原有逻辑
            relative_filename = _normalize_to_relative_path(filename)
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
                # 管理员模式：使用父类的逻辑
                log.debug("管理员模式，调用父类文件发现逻辑")
                await super()._discover_credential_files_unlocked()
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
        """获取用户的凭证文件列表
        
        Returns:
            文件名列表（不包含路径）
        """
        if not self.username:
            return []
        
        user_dir = self._user_credentials_dir
        if not os.path.exists(user_dir):
            return []
        
        files = []
        for filename in os.listdir(user_dir):
            if filename.endswith('.json'):
                files.append(filename)
        
        return sorted(files)
    
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