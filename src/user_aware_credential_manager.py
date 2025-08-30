"""用户凭证管理器，基于SQLite数据库的多用户凭证管理"""
import os
import json
import asyncio
import time
import sqlite3
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any

import httpx
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from config import (
    CODE_ASSIST_ENDPOINT,
    get_proxy_config, get_calls_per_rotation, get_http_timeout, get_max_connections,
    get_base_model_name, get_base_model_from_feature_model
)
# 核心修改：从数据库模块导入 user_db 实例
from .user_database import user_db
from .utils import get_user_agent, get_client_metadata
from log import logger

class UserCredentialManager:
    """基于SQLite数据库的用户凭证管理器，支持用户隔离，使用单例模式确保每个用户只有一个实例"""
    
    # 类级别的实例字典，用于存储每个用户名对应的实例
    _instances = {}
    # 类级别的锁，用于保护实例字典的并发访问
    _instances_lock = asyncio.Lock()
    # 记录每个实例的最后访问时间
    _last_access_times = {}
    # 清理任务
    _cleanup_task = None
    # 实例超时时间（秒），1小时不使用则清理
    _INSTANCE_TIMEOUT = 3600
    
    @classmethod
    async def get_instance(cls, username: str, calls_per_rotation: int = None) -> 'UserCredentialManager':
        """
        获取用户的凭证管理器实例，如果不存在则创建
        Args:
            username: 用户名
            calls_per_rotation: 每次轮换的调用次数
        Returns:
            UserCredentialManager: 用户的凭证管理器实例
        """
        # 启动清理任务（如果尚未启动）
        if cls._cleanup_task is None or cls._cleanup_task.done():
            cls._cleanup_task = asyncio.create_task(cls._cleanup_inactive_instances())
            
        if not username:
            raise ValueError("UserCredentialManager必须使用用户名进行初始化。")
            
        async with cls._instances_lock:
            if username not in cls._instances:
                logger.info(f"为用户 '{username}' 创建新的凭证管理器实例")
                instance = cls._create_instance(username, calls_per_rotation)
                cls._instances[username] = instance
            
            # 更新最后访问时间
            cls._last_access_times[username] = time.time()
            return cls._instances[username]
    
    @classmethod
    def _create_instance(cls, username: str, calls_per_rotation: int = None) -> 'UserCredentialManager':
        """创建新实例但不初始化（初始化将在第一次使用时异步进行）"""
        return cls(username, calls_per_rotation, _private_init=True)
        
    @classmethod
    async def _cleanup_inactive_instances(cls):
        """定期清理长时间不活跃的实例"""
        try:
            while True:
                await asyncio.sleep(300)  # 每5分钟检查一次
                current_time = time.time()
                usernames_to_remove = []
                
                async with cls._instances_lock:
                    for username, last_access_time in cls._last_access_times.items():
                        if current_time - last_access_time > cls._INSTANCE_TIMEOUT:
                            usernames_to_remove.append(username)
                    
                    for username in usernames_to_remove:
                        if username in cls._instances:
                            logger.info(f"清理长时间不活跃的凭证管理器实例: {username}")
                            try:
                                await cls._instances[username].close()
                            except Exception as e:
                                logger.warning(f"关闭用户 {username} 的凭证管理器时出错: {e}")
                            del cls._instances[username]
                            del cls._last_access_times[username]
        except asyncio.CancelledError:
            logger.info("凭证管理器清理任务被取消")
        except Exception as e:
            logger.error(f"凭证管理器清理任务出错: {e}")
            # 重新启动清理任务
            cls._cleanup_task = asyncio.create_task(cls._cleanup_inactive_instances())
    
    def __init__(self, username: str, calls_per_rotation: int = None, _private_init: bool = False):
        """
        初始化用户凭证管理器
        Args:
            username: 用户名
            calls_per_rotation: 每次轮换的调用次数
            _private_init: 私有参数，防止直接实例化，应该使用get_instance方法
        """
        if not _private_init:
            logger.warning(f"警告：直接实例化UserCredentialManager已弃用，请使用UserCredentialManager.get_instance()方法")
            
        self._lock = asyncio.Lock()
        self.username = username
        self.user_id: Optional[int] = None

        # 凭证缓存 (从数据库加载)
        self._credentials_cache: List[Dict[str, Any]] = []
        self._current_credential_index = 0
        self._last_cache_refresh_time = 0

        # 当前使用的凭证对象和其数据库记录
        self._cached_credentials_obj: Optional[Credentials] = None
        self._current_credential_record: Optional[Dict[str, Any]] = None

        # 基于调用的轮换机制
        self._call_count = 0
        self._calls_per_rotation = calls_per_rotation or get_calls_per_rotation()

        # Onboarding状态
        self._onboarding_complete = False

        # HTTP客户端
        self._http_client: Optional[httpx.AsyncClient] = None
        self._initialized = False
        
        # 新增一个集合来跟踪正在刷新的凭证ID，防止竞态条件
        self._refreshing_in_progress = set()

    async def initialize(self):
        """初始化凭证管理器"""
        async with self._lock:
            if self._initialized:
                return

            # 获取用户ID
            user_data = await user_db.get_user_by_username(self.username)
            if not user_data:
                raise ValueError(f"无法初始化凭证管理器：用户 '{self.username}' 不存在。")
            # 添加日志记录user_data的内容
            logger.info(f"获取到用户数据: {user_data}")
            # 尝试从不同的键获取user_id
            if 'user_id' in user_data:
                self.user_id = user_data['user_id']
            elif 'id' in user_data:
                self.user_id = user_data['id']
            else:
                logger.error(f"用户数据中没有user_id或id字段: {user_data}")
                raise ValueError(f"无法获取用户ID: 数据结构不符合预期")

            # 从数据库加载凭证到缓存
            await self._load_credentials_from_db()

            # 初始化HTTP客户端
            proxy = get_proxy_config()
            client_kwargs = {
                "timeout": get_http_timeout(),
                "limits": httpx.Limits(max_keepalive_connections=20, max_connections=get_max_connections())
            }
            if proxy:
                client_kwargs["proxy"] = proxy
            self._http_client = httpx.AsyncClient(**client_kwargs)
            
            self._initialized = True
            logger.info(f"用户 '{self.username}' 的凭证管理器初始化完成。")

    async def close(self):
        """清理资源"""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def _load_credentials_from_db(self):
        """从数据库加载激活的凭证到内部缓存。必须在锁内调用。"""
        logger.debug(f"用户 '{self.username}': 从数据库刷新凭证缓存...")
        if not self.user_id:
            logger.error(f"用户 '{self.username}' 的 user_id 未设置，无法加载凭证。")
            return

        self._credentials_cache = await user_db.get_active_credentials_for_rotation(self.user_id)
        self._last_cache_refresh_time = time.time()

        if not self._credentials_cache:
            logger.warning(f"用户 '{self.username}' 没有找到可用的凭证。")
            self._current_credential_index = 0
            self._cached_credentials_obj = None
            self._current_credential_record = None
        else:
            # 如果索引超出范围，重置
            if self._current_credential_index >= len(self._credentials_cache):
                self._current_credential_index = 0
            logger.info(f"用户 '{self.username}': 加载了 {len(self._credentials_cache)} 个可用凭证。")
        
        # 清除缓存的凭证对象，强制重新加载
        self._cached_credentials_obj = None

    def _is_cache_valid(self) -> bool:
        """检查缓存的凭证对象是否仍然有效"""
        if not self._cached_credentials_obj:
            return False
        
        if self._call_count >= self._calls_per_rotation:
            return False
        
        # 避免频繁检查过期状态，如果最近刷新过则认为有效
        if hasattr(self, '_last_refresh_time') and time.time() - self._last_refresh_time < 1800:
            return True
        
        if self._cached_credentials_obj.expired:
            return False
        
        if self._current_credential_record and not self._current_credential_record.get('is_active', False):
            return False
            
        return True

    async def get_credentials(self) -> Tuple[Optional[Credentials], Optional[str]]:
        """获取当前凭证，如果过期则刷新（最终修复版）"""
        if not self._initialized:
            await self.initialize()
        
        # 记录已尝试过的凭证ID，确保每个凭证只尝试一次
        tried_credential_ids = set()
        
        # 继续尝试直到所有凭证都尝试过或成功获取凭证
        while True:
            cred_record = None
            is_already_refreshing = False
            
            # --- 阶段1: 在锁内做快速决策 ---
            async with self._lock:
                if self._is_cache_valid():
                    self._call_count += 1
                    logger.debug(f"使用缓存的凭证 (调用计数: {self._call_count}/{self._calls_per_rotation})")
                    return self._cached_credentials_obj, self._current_credential_record.get('project_id')
                
                # 准备轮换或刷新
                if not self._credentials_cache or time.time() - self._last_cache_refresh_time > 600:
                    await self._load_credentials_from_db()

                if not self._credentials_cache:
                    logger.error(f"用户 '{self.username}' 没有可用的凭证。")
                    return None, None

                # 检查是否已尝试过所有凭证
                if len(tried_credential_ids) >= len(self._credentials_cache):
                    logger.error(f"已尝试所有 {len(self._credentials_cache)} 个凭证，均无法使用。")
                    return None, None

                if self._call_count >= self._calls_per_rotation:
                    self._current_credential_index = (self._current_credential_index + 1) % len(self._credentials_cache)
                    self._call_count = 0
                    self._cached_credentials_obj = None
                    logger.info(f"轮换到凭证索引 {self._current_credential_index}")
                
                # 获取当前凭证，如果已尝试过则继续轮换
                initial_index = self._current_credential_index
                while True:
                    cred_record = self._credentials_cache[self._current_credential_index]
                    cred_id = cred_record['id']
                    
                    # 如果这个凭证已经尝试过，轮换到下一个
                    if cred_id in tried_credential_ids:
                        self._current_credential_index = (self._current_credential_index + 1) % len(self._credentials_cache)
                        # 如果已经循环回到起始索引，说明所有凭证都尝试过了
                        if self._current_credential_index == initial_index:
                            logger.error(f"已尝试所有 {len(self._credentials_cache)} 个凭证，均无法使用。")
                            return None, None
                        continue
                    else:
                        # 找到一个未尝试过的凭证
                        break
                
                self._current_credential_record = cred_record
                cred_id = cred_record['id']
                tried_credential_ids.add(cred_id)  # 标记为已尝试
                
                # 关键修复：正确判断是否已有任务在刷新
                if cred_id in self._refreshing_in_progress:
                    is_already_refreshing = True
                    logger.debug(f"凭证 '{cred_record['name']}' (ID: {cred_id}) 正在刷新，本任务将等待。")
                else:
                    self._refreshing_in_progress.add(cred_id)
                    logger.info(f"决定刷新凭证: {cred_record['name']} (ID: {cred_id}, 索引: {self._current_credential_index})")
            
            # --- 锁已释放 ---
            # --- 阶段2: 根据决策执行操作 ---
            if is_already_refreshing:
                await asyncio.sleep(1)  # 等待1秒让其他任务完成刷新
                continue  # 进入下一次循环重试
            
            # --- 如果我们是负责刷新的任务，则执行网络操作 ---
            try:
                creds_data = json.loads(cred_record['credential_data'])
                creds = self._create_credentials_obj(creds_data)
                
                if creds.expired and creds.refresh_token:
                    logger.info(f"凭证 '{cred_record['name']}' 正在执行网络刷新...")
                    request = GoogleAuthRequest()
                    await asyncio.to_thread(creds.refresh, request)
                    logger.info(f"凭证 '{cred_record['name']}' 刷新成功。")
                    
                    # 更新数据库
                    cred_info = {
                        'token': creds.token,
                        'refresh_token': creds.refresh_token,
                        'expiry': creds.expiry.isoformat() if creds.expiry else None,
                        'token_uri': creds.token_uri,
                        'client_id': creds.client_id,
                        'client_secret': creds.client_secret,
                        'scopes': creds.scopes
                    }
                    await user_db.update_credential(cred_id, {'credential_data': json.dumps(cred_info)})
                
                project_id = cred_record.get('project_id') or creds_data.get('project_id')
                
                # --- 阶段3: 在锁内更新共享状态 ---
                async with self._lock:
                    self._cached_credentials_obj = creds
                    self._call_count = 0
                    self._last_refresh_time = time.time()
                    await user_db.update_credential(cred_id, {'last_used_at': datetime.now(timezone.utc).isoformat()})
                    return creds, project_id
                    
            except Exception as e:
                logger.error(f"加载或刷新凭证 '{cred_record['name']}' (ID: {cred_id}) 失败: {e}")
                await self.record_error(500, f"Credential load/refresh failed: {e}")
                
                # 强制轮换到下一个凭证
                await self._force_rotate_credential()
                
                # 继续循环尝试下一个凭证
            finally:
                # 关键修复：使用finally确保无论成功、失败或异常，都清理刷新标记
                async with self._lock:
                    self._refreshing_in_progress.discard(cred_id)
        
        # 理论上不会执行到这里，因为循环中会处理所有情况
        logger.error("尝试获取凭证失败，所有凭证均无法使用。")
        return None, None

    def _create_credentials_obj(self, creds_data: Dict[str, Any]) -> Credentials:
        """从字典创建 google.oauth2.credentials.Credentials 对象"""
        if 'type' not in creds_data and all(key in creds_data for key in ['client_id', 'refresh_token']):
            creds_data['type'] = 'authorized_user'
        if "access_token" in creds_data and "token" not in creds_data:
            creds_data["token"] = creds_data["access_token"]
        if "scope" in creds_data and "scopes" not in creds_data:
            creds_data["scopes"] = creds_data["scope"].split()
        
        # 处理过期时间格式问题，移除 +00:00 时区信息
        if "expiry" in creds_data and isinstance(creds_data["expiry"], str):
            # 移除 +00:00 时区信息
            expiry = creds_data["expiry"]
            if "+00:00" in expiry:
                creds_data["expiry"] = expiry.replace("+00:00", "")
        
        try:
            return Credentials.from_authorized_user_info(creds_data, creds_data.get("scopes"))
        except ValueError as e:
            # 如果仍然出现日期解析错误，尝试更强的修复
            if "expiry" in creds_data and "unconverted data remains" in str(e):
                logger.warning(f"凭证日期格式错误: {e}，尝试修复...")
                # 完全移除过期时间，让库自动处理
                creds_data.pop("expiry", None)
                return Credentials.from_authorized_user_info(creds_data, creds_data.get("scopes"))
            raise

    async def _force_rotate_credential(self):
        """强制轮换到下一个凭证，通常在发生严重错误后调用"""
        async with self._lock:
            if not self._credentials_cache or len(self._credentials_cache) <= 1:
                logger.info("只有一个或没有可用凭证，无法强制轮换。")
                return
            
            old_index = self._current_credential_index
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credentials_cache)
            self._call_count = 0
            
            # 不再清除缓存的凭证对象，避免重复刷新
            # 只有在需要时才会重新加载凭证
            # self._cached_credentials_obj = None
            
            logger.info(f"强制从凭证索引 {old_index} 轮换到 {self._current_credential_index}")

    async def force_refresh_credential_cache(self):
        """外部调用，强制从数据库刷新凭证缓存"""
        async with self._lock:
            await self._load_credentials_from_db()

    async def increment_call_count(self):
        """增加调用计数器"""
        async with self._lock:
            self._call_count += 1
            logger.debug(f"调用计数增加到 {self._call_count}/{self._calls_per_rotation}")

    def _is_gemini_2_5_pro(self, model_name: str) -> bool:
        """检查模型是否为 gemini-2.5-pro 变体"""
        if not model_name:
            return False
        base_with_suffix = get_base_model_from_feature_model(model_name)
        pure_base_model = get_base_model_name(base_with_suffix)
        return pure_base_model == "gemini-2.5-pro"

    async def record_success(self, model_name: str):
        """记录一次成功的API调用"""
        cred_record = self._current_credential_record
        if not cred_record:
            logger.warning("无法记录成功，因为没有当前凭证记录。")
            return
        
        cred_id = cred_record['id']
        is_gemini_2_5 = self._is_gemini_2_5_pro(model_name)
        
        update_data = {
            'last_success_at': datetime.now(timezone.utc).isoformat(),
            'error_codes': None,
            'total_calls': cred_record.get('total_calls', 0) + 1,
            'gemini_25_pro_calls': cred_record.get('gemini_25_pro_calls', 0) + (1 if is_gemini_2_5 else 0)
        }
        
        if await user_db.update_credential(cred_id, update_data):
            # 更新内存中的缓存记录
            async with self._lock:
                if self._current_credential_record and self._current_credential_record['id'] == cred_id:
                    self._current_credential_record.update(update_data)
            logger.debug(f"成功记录到凭证ID {cred_id}。")
        else:
            logger.error(f"记录成功到数据库失败，凭证ID {cred_id}")

    async def record_error(self, status_code: int, response_content: str = ""):
        """记录一次失败的API调用"""
        cred_record = self._current_credential_record
        if not cred_record:
            logger.warning("无法记录错误，因为没有当前凭证记录。")
            return

        cred_id = cred_record['id']
        cred_name = cred_record['name']
        
        try:
            current_errors_str = cred_record.get('error_codes', '[]')
            error_codes = json.loads(current_errors_str) if current_errors_str else []
            if status_code not in error_codes:
                error_codes.append(status_code)
            
            update_data = {'error_codes': json.dumps(error_codes)}
            update_result = await user_db.update_credential(cred_id, update_data)
            if update_result:
                async with self._lock:
                    if self._current_credential_record and self._current_credential_record['id'] == cred_id:
                        self._current_credential_record.update(update_data)
                logger.debug(f"错误 {status_code} 已记录到凭证 '{cred_name}' (ID: {cred_id})。")
            else:
                logger.error(f"记录错误到数据库失败，凭证ID {cred_id}，错误代码 {status_code}，响应内容: {response_content[:200] if response_content else 'None'}")
        except Exception as e:
            logger.error(f"记录错误时发生异常，凭证ID {cred_id}: {e}")

    async def add_credential(self, name: str, credential_data: Dict[str, Any]) -> bool:
        """添加新凭证到数据库并创建备份文件"""
        if not self.user_id:
            logger.error("无法添加凭证：user_id 未知。")
            return False
        
        try:
            cred_str = json.dumps(credential_data)
            project_id = credential_data.get('project_id')
            user_email = credential_data.get('client_email') # for service accounts

            cred_id = await user_db.add_credential(self.user_id, name, cred_str, project_id, user_email)
            if cred_id:
                logger.info(f"用户 '{self.username}' 添加凭证 '{name}' 成功。")
                await self.force_refresh_credential_cache()
                return True
            else:
                logger.error(f"用户 '{self.username}' 添加凭证 '{name}' 失败（可能已存在）。")
                return False
        except Exception as e:
            logger.error(f"添加凭证时发生异常: {e}")
            return False

    async def delete_credential(self, name: str) -> bool:
        """删除一个凭证"""
        if not self.user_id:
            logger.error("无法删除凭证：user_id 未知。")
            return False
            
        success = await user_db.delete_credential(self.user_id, name)
        if success:
            logger.info(f"用户 '{self.username}' 删除凭证 '{name}' 成功。")
            await self.force_refresh_credential_cache()
        return success

    async def get_all_credentials_status(self) -> List[Dict[str, Any]]:
        """获取用户所有凭证的状态信息"""
        if not self.user_id:
            await self.initialize()
        return await user_db.list_credentials_for_user(self.user_id)

    async def set_credential_active_status(self, name: str, is_active: bool) -> bool:
        """设置凭证的激活状态"""
        if not self.user_id:
            await self.initialize()
        
        all_creds = await user_db.list_credentials_for_user(self.user_id)
        cred_to_update = next((c for c in all_creds if c['name'] == name), None)

        if not cred_to_update:
            logger.warning(f"尝试更新不存在的凭证状态: {name}")
            return False

        cred_id = cred_to_update['id']
        success = await user_db.update_credential(cred_id, {'is_active': int(is_active)})
        if success:
            await self.force_refresh_credential_cache()
        return success

    def get_current_credential_info(self) -> Optional[Dict[str, Any]]:
        """获取当前正在使用的凭证的数据库记录"""
        return self._current_credential_record

    async def onboard_user(self, creds: Credentials, project_id: str):
        """优化的用户Onboarding流程"""
        if self._onboarding_complete:
            return
        async with self._lock:
            if self._onboarding_complete:
                return
            
            if creds.expired and creds.refresh_token:
                try:
                    request = GoogleAuthRequest(session=self._http_client)
                    await asyncio.to_thread(creds.refresh, request)
                except Exception as e:
                    raise Exception(f"在Onboarding期间刷新凭证失败: {str(e)}")

            headers = { "Authorization": f"Bearer {creds.token}", "Content-Type": "application/json", "User-Agent": get_user_agent() }
            load_assist_payload = { "cloudaicompanionProject": project_id, "metadata": get_client_metadata(project_id) }
            
            try:
                resp = await self._http_client.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist", json=load_assist_payload, headers=headers)
                resp.raise_for_status()
                load_data = resp.json()
                
                tier = None
                if load_data.get("currentTier"):
                    tier = load_data["currentTier"]
                else:
                    tier = next((t for t in load_data.get("allowedTiers", []) if t.get("isDefault")), None)
                    if not tier:
                        tier = {"id": "legacy-tier", "userDefinedCloudaicompanionProject": True}
                
                if tier.get("userDefinedCloudaicompanionProject") and not project_id:
                    raise ValueError("此账户需要设置 GOOGLE_CLOUD_PROJECT 环境变量。")

                if load_data.get("currentTier"):
                    self._onboarding_complete = True
                    return

                onboard_req_payload = { "tierId": tier.get("id"), "cloudaicompanionProject": project_id, "metadata": get_client_metadata(project_id) }
                while True:
                    onboard_resp = await self._http_client.post(f"{CODE_ASSIST_ENDPOINT}/v1internal:onboardUser", json=onboard_req_payload, headers=headers)
                    onboard_resp.raise_for_status()
                    lro_data = onboard_resp.json()
                    if lro_data.get("done"):
                        self._onboarding_complete = True
                        break
                    await asyncio.sleep(5)
            except httpx.HTTPStatusError as e:
                error_text = e.response.text if hasattr(e, 'response') else str(e)
                raise Exception(f"用户Onboarding失败。请检查您的Google Cloud项目权限。错误: {error_text}")
            except Exception as e:
                raise Exception(f"用户Onboarding因意外错误失败: {str(e)}")

