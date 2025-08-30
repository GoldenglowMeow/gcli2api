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
    """基于SQLite数据库的用户凭证管理器，支持用户隔离"""

    def __init__(self, username: str, calls_per_rotation: int = None):
        """
        初始化用户凭证管理器
        Args:
            username: 用户名
            calls_per_rotation: 每次轮换的调用次数
        """
        if not username:
            raise ValueError("UserCredentialManager必须使用用户名进行初始化。")

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
        """获取当前凭证，如果过期则刷新"""
        if not self._initialized:
            await self.initialize()

        async with self._lock:
            # 如果缓存有效，直接返回缓存的凭证
            if self._is_cache_valid():
                logger.debug(f"使用缓存的凭证 (调用计数: {self._call_count}/{self._calls_per_rotation})")
                self._call_count += 1  # 增加调用计数
                return self._cached_credentials_obj, self._current_credential_record.get('project_id')

            # 如果需要，从数据库刷新凭证缓存
            if not self._credentials_cache or time.time() - self._last_cache_refresh_time > 600:
                await self._load_credentials_from_db()

            if not self._credentials_cache:
                logger.error(f"用户 '{self.username}' 没有可用的凭证。")
                return None, None

            # 如果达到轮换阈值，切换到下一个凭证
            if self._call_count >= self._calls_per_rotation:
                self._current_credential_index = (self._current_credential_index + 1) % len(self._credentials_cache)
                self._call_count = 0
                logger.info(f"轮换到凭证索引 {self._current_credential_index}")
                # 清除缓存的凭证对象，强制重新加载
                self._cached_credentials_obj = None

            # 获取当前凭证记录
            self._current_credential_record = self._credentials_cache[self._current_credential_index]
            cred_record = self._current_credential_record
            cred_id = cred_record['id']
            cred_name = cred_record['name']
            logger.info(f"尝试加载凭证: {cred_name} (ID: {cred_id}, 索引: {self._current_credential_index})")

        try:
            creds_data = json.loads(cred_record['credential_data'])
            creds = self._create_credentials_obj(creds_data)
            
            if creds.expired and creds.refresh_token:
                logger.info(f"凭证 '{cred_name}' 已过期，正在刷新...")
                # 创建一个同步的请求对象，而不是使用异步客户端
                # 这里使用标准的 google.auth.transport.requests.Request 而不是传入异步客户端
                request = GoogleAuthRequest()
                await asyncio.to_thread(creds.refresh, request)
                logger.info(f"凭证 '{cred_name}' 刷新成功。")
                
                # 更新凭证缓存，避免重复刷新
                self._cached_credentials_obj = creds
                self._call_count = 0  # 重置调用计数
                self._last_refresh_time = time.time()  # 记录最后刷新时间
                
                # 更新数据库中的凭证数据
                cred_info = {
                    'token': creds.token,
                    'refresh_token': creds.refresh_token,
                    'token_uri': creds.token_uri,
                    'client_id': creds.client_id,
                    'client_secret': creds.client_secret,
                    'scopes': creds.scopes,
                    'expiry': creds.expiry.isoformat() if creds.expiry else None
                }
                await user_db.update_credential(cred_id, {'credential_data': json.dumps(cred_info)})
            
            project_id = cred_record.get('project_id') or creds_data.get('project_id')

        except Exception as e:
            logger.error(f"加载或刷新凭证 '{cred_name}' (ID: {cred_id}) 失败: {e}")
            await self.record_error(500, f"Credential load failed: {e}")
            await self._force_rotate_credential()
            # 防止无限递归，如果没有更多凭证可用，直接返回 None
            if len(self._credentials_cache) <= 1:
                logger.error(f"没有更多可用凭证，无法继续尝试")
                return None, None
            # 设置最大重试次数，避免无限递归
            if not hasattr(self, '_retry_count'):
                self._retry_count = 0
            self._retry_count += 1
            if self._retry_count > 3:
                logger.error(f"尝试获取凭证失败次数过多，放弃尝试")
                self._retry_count = 0
                return None, None
            # 尝试获取下一个凭证
            result = await self.get_credentials()
            self._retry_count = 0
            return result

        async with self._lock:
            self._cached_credentials_obj = creds
            await user_db.update_credential(cred_id, {'last_used_at': datetime.now(timezone.utc).isoformat()})
            return creds, project_id

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
            self._cached_credentials_obj = None
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

