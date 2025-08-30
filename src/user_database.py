import aiosqlite  # 替换 sqlite3
import sqlite3    # 仍然需要它用于 Row 工厂
import hashlib
import secrets
import os
import re
import json
from typing import Optional, List, Dict, Any
from log import log

# 数据库文件路径
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data.sqlite')

class UserDatabase:
    def __init__(self):
        self.db_path = DB_PATH
        # init_database 现在是异步的，不能在 __init__ 中直接调用
        # 它将在第一次数据库操作时被隐式调用或在程序启动时显式调用

    async def init_database(self):
        """初始化数据库表 (异步)"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # 创建用户表
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1
                    )
                ''')
                # 创建用户会话表
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_token TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')
                # 创建凭证表
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        credential_data TEXT NOT NULL,
                        project_id TEXT,
                        user_email TEXT,
                        is_active BOOLEAN DEFAULT 1,
                        last_used_at TIMESTAMP,
                        last_success_at TIMESTAMP,
                        next_reset_at TIMESTAMP,  -- 新增：下次重置时间
                        error_codes TEXT,
                        total_calls INTEGER DEFAULT 0,
                        gemini_25_pro_calls INTEGER DEFAULT 0,
                        daily_limit_total INTEGER DEFAULT 1500,
                        daily_limit_gemini_25_pro INTEGER DEFAULT 100,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        UNIQUE (user_id, name)
                    )
                ''')
                # 创建触发器
                await db.execute('''
                    CREATE TRIGGER IF NOT EXISTS update_credentials_updated_at
                    AFTER UPDATE ON credentials
                    FOR EACH ROW
                    BEGIN
                        UPDATE credentials SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
                    END;
                ''')
                await db.commit()
                log.info("用户数据库及凭证表初始化完成")
                
                # 检查是否需要创建默认用户
                # await self._create_default_user_if_needed()
        except Exception as e:
            log.error(f"数据库初始化失败: {e}")
            raise
            
    async def _create_default_user_if_needed(self):
        """如果数据库中没有用户，创建一个默认用户"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # 检查是否有用户
                async with db.execute("SELECT COUNT(*) FROM users") as cursor:
                    count = await cursor.fetchone()
                    if count and count[0] > 0:
                        log.info("数据库中已有用户，跳过默认用户创建")
                        return
                
                # 创建默认用户
                default_username = "admin"
                default_password = "admin123"
                
                # 检查用户名是否已存在
                async with db.execute("SELECT id FROM users WHERE username = ?", (default_username,)) as cursor:
                    if await cursor.fetchone():
                        log.info(f"默认用户 {default_username} 已存在")
                        return
                
                password_hash, salt = self.hash_password(default_password)
                api_key = self.generate_api_key()
                
                cursor = await db.execute('''
                    INSERT INTO users (username, password_hash, salt, api_key)
                    VALUES (?, ?, ?, ?)
                ''', (default_username, password_hash, salt, api_key))
                
                user_id = cursor.lastrowid
                await db.commit()
                
                # 创建用户凭证目录
                user_creds_dir = os.path.join(os.path.dirname(__file__), '..', 'creds', default_username)
                os.makedirs(user_creds_dir, exist_ok=True)
                
                log.info(f"已创建默认用户 {default_username}，ID: {user_id}，密码: {default_password}")
        except Exception as e:
            log.error(f"创建默认用户失败: {e}")
            # 不抛出异常，让程序继续运行

    # --- 辅助方法 (保持同步) ---
    def validate_username(self, username: str) -> bool:
        if not username: return False
        return bool(re.match(r'^[a-z0-9]+$', username)) and 3 <= len(username) <= 20

    def hash_password(self, password: str, salt: str = None) -> tuple:
        if salt is None: salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return password_hash.hex(), salt

    def generate_api_key(self) -> str:
        return f"gg-gcli-{secrets.token_urlsafe(32)}"

    def generate_session_token(self) -> str:
        return secrets.token_urlsafe(64)

    # --- 用户管理方法 (异步) ---
    async def create_user(self, username: str, password: str) -> Dict[str, Any]:
        if not self.validate_username(username):
            return {"success": False, "error": "用户名只能包含小写字母和数字，长度3-20位"}
        if len(password) < 6:
            return {"success": False, "error": "密码长度至少6位"}
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT id FROM users WHERE username = ?", (username,)) as cursor:
                    if await cursor.fetchone():
                        return {"success": False, "error": "用户名已存在"}
                
                password_hash, salt = self.hash_password(password)
                api_key = self.generate_api_key()
                
                cursor = await db.execute('''
                    INSERT INTO users (username, password_hash, salt, api_key)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, salt, api_key))
                
                user_id = cursor.lastrowid
                await db.commit()
                
                user_creds_dir = os.path.join(os.path.dirname(__file__), '..', 'creds', username)
                os.makedirs(user_creds_dir, exist_ok=True)
                
                log.info(f"用户 {username} 创建成功，ID: {user_id}")
                return {"success": True, "user_id": user_id, "username": username, "api_key": api_key}
        except Exception as e:
            log.error(f"创建用户失败: {e}")
            return {"success": False, "error": "创建用户时发生错误"}

    async def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cursor:
                    user = await cursor.fetchone()

                if not user:
                    return {"success": False, "error": "用户名或密码错误"}
                
                if not user["is_active"]:
                    return {"success": False, "error": "账户已被禁用"}
                
                password_hash, _ = self.hash_password(password, user["salt"])
                if password_hash != user["password_hash"]:
                    return {"success": False, "error": "用户名或密码错误"}
                
                await db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user["id"],))
                await db.commit()
                
                log.info(f"用户 {username} 登录成功")
                return {"success": True, "user_id": user["id"], "username": user["username"], "api_key": user["api_key"]}
        except Exception as e:
            log.error(f"用户认证失败: {e}")
            return {"success": False, "error": "认证时发生错误"}

    # --- 凭证管理 (CRUD) (异步) ---
    async def add_credential(self, user_id: int, name: str, credential_data: str, project_id: Optional[str] = None, user_email: Optional[str] = None) -> Optional[int]:
        try:
            # 计算下一个UTC 07:00的时间
            import datetime
            now = datetime.datetime.utcnow()
            next_reset = now.replace(hour=7, minute=0, second=0, microsecond=0)
            if now.hour >= 7:  # 如果当前时间已经过了UTC 07:00，则设置为明天的UTC 07:00
                next_reset += datetime.timedelta(days=1)
            
            # 格式化为ISO格式（带时区信息）
            next_reset_formatted = next_reset.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute('''
                    INSERT INTO credentials (user_id, name, credential_data, project_id, user_email, next_reset_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, name, credential_data, project_id, user_email, next_reset_formatted))
                cred_id = cursor.lastrowid
                await db.commit()
                
                log.info(f"为用户ID {user_id} 添加凭证 {name} (ID: {cred_id})，下次重置时间设为 {next_reset_formatted}")

                user_info = await self.get_user_by_id(user_id)
                if user_info:
                    user_creds_dir = os.path.join(os.path.dirname(__file__), '..', 'creds', user_info['username'])
                    backup_path = os.path.join(user_creds_dir, name)
                    os.makedirs(user_creds_dir, exist_ok=True)
                    with open(backup_path, 'w', encoding='utf-8') as f:
                        f.write(credential_data)
                    log.info(f"为用户ID {user_id} 添加凭证 {name} (ID: {cred_id}) 并创建备份。")
                else:
                    log.warning(f"为用户ID {user_id} 添加凭证后，未能找到用户信息以创建备份文件。")
                return cred_id
        except aiosqlite.IntegrityError:
            log.warning(f"尝试为用户ID {user_id} 添加已存在的凭证名称: {name}")
            return None
        except Exception as e:
            log.error(f"添加凭证失败: {e}")
            return None

    async def delete_credential(self, user_id: int, name: str) -> bool:
        try:
            user_info = await self.get_user_by_id(user_id)
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("DELETE FROM credentials WHERE user_id = ? AND name = ?", (user_id, name))
                if cursor.rowcount == 0:
                    log.warning(f"尝试删除不存在的凭证: 用户ID {user_id}, 名称 {name}")
                    return False
                await db.commit()

                if user_info:
                    backup_path = os.path.join(os.path.dirname(__file__), '..', 'creds', user_info['username'], name)
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                        log.info(f"删除了凭证备份文件: {backup_path}")
                log.info(f"成功删除用户ID {user_id} 的凭证: {name}")
                return True
        except Exception as e:
            log.error(f"删除凭证失败: {e}")
            return False

    async def list_credentials_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute("SELECT * FROM credentials WHERE user_id = ? ORDER BY name ASC", (user_id,)) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]
        except Exception as e:
            log.error(f"获取用户 {user_id} 的凭证列表失败: {e}")
            return []

    async def get_active_credentials_for_rotation(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute("SELECT * FROM credentials WHERE user_id = ? AND is_active = 1", (user_id,)) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]
        except Exception as e:
            log.error(f"获取用户 {user_id} 的可用凭证失败: {e}")
            return []

    async def update_credential(self, cred_id: int, data: Dict[str, Any]) -> bool:
        if not data: return False
        fields, values = [], []
        allowed_keys = ['name', 'credential_data', 'project_id', 'user_email', 'is_active', 'last_used_at', 'last_success_at', 'error_codes', 'total_calls', 'gemini_25_pro_calls', 'daily_limit_total', 'daily_limit_gemini_25_pro']
        for key, value in data.items():
            if key in allowed_keys:
                fields.append(f"{key} = ?")
                values.append(json.dumps(value) if isinstance(value, (dict, list)) else value)
        
        if not fields:
            log.warning("更新凭证时没有提供有效字段。")
            return False
        
        values.append(cred_id)
        query = f"UPDATE credentials SET {', '.join(fields)} WHERE id = ?"
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(query, tuple(values))
                await db.commit()
                if cursor.rowcount > 0:
                    return True
                else:
                    log.warning(f"更新凭证ID {cred_id} 失败: 没有找到匹配的记录或数据未变化，SQL: {query}, 值: {values}")
                    return False
        except sqlite3.Error as e:
            log.error(f"更新凭证ID {cred_id} 失败: 数据库错误 - {e.__class__.__name__}: {e}, SQL: {query}, 值: {values}")
            return False
        except Exception as e:
            log.error(f"更新凭证ID {cred_id} 失败: 未知错误 - {e.__class__.__name__}: {e}, SQL: {query}, 值: {values}")
            return False
            

    async def reset_daily_usage_for_all_credentials(self) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("UPDATE credentials SET total_calls = 0, gemini_25_pro_calls = 0")
                await db.commit()
                log.info(f"已重置所有凭证的每日调用统计，共影响 {cursor.rowcount} 条记录。")
                return True
        except Exception as e:
            log.error(f"重置凭证每日用量失败: {e}")
            return False
            
    async def reset_daily_usage_for_credential(self, cred_id: int) -> bool:
        """重置单个凭证的每日调用统计并更新下次重置时间"""
        try:
            # 计算下一个UTC 07:00的时间
            import datetime
            now = datetime.datetime.utcnow()
            next_reset = now.replace(hour=7, minute=0, second=0, microsecond=0)
            if now.hour >= 7:  # 如果当前时间已经过了UTC 07:00，则设置为明天的UTC 07:00
                next_reset += datetime.timedelta(days=1)
            
            # 格式化为ISO格式（带时区信息）
            next_reset_formatted = next_reset.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    "UPDATE credentials SET total_calls = 0, gemini_25_pro_calls = 0, next_reset_at = ? WHERE id = ?", 
                    (next_reset_formatted, cred_id)
                )
                await db.commit()
                if cursor.rowcount > 0:
                    log.info(f"已重置凭证ID {cred_id} 的每日调用统计，下次重置时间设为 {next_reset_formatted}")
                    return True
                else:
                    log.warning(f"未找到凭证ID {cred_id} 或重置失败")
                    return False
        except Exception as e:
            log.error(f"重置凭证ID {cred_id} 的每日用量失败: {e}")
            return False
            
    async def check_and_reset_expired_credentials(self) -> int:
        """检查并重置所有过期的凭证调用次数，返回重置的凭证数量"""
        try:
            import datetime
            now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
            
            # 先获取所有需要重置的凭证ID
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                # 查找next_reset_at为空或已过期的凭证
                async with db.execute(
                    "SELECT id FROM credentials WHERE next_reset_at IS NULL OR next_reset_at <= ?", 
                    (now,)
                ) as cursor:
                    expired_creds = await cursor.fetchall()
            
            # 重置每个过期凭证
            reset_count = 0
            for cred in expired_creds:
                if await self.reset_daily_usage_for_credential(cred['id']):
                    reset_count += 1
            
            if reset_count > 0:
                log.info(f"服务器启动时检查: 已重置 {reset_count} 个过期凭证的调用统计")
            return reset_count
        except Exception as e:
            log.error(f"检查并重置过期凭证失败: {e}")
            return 0

    # --- 用户信息获取 (异步) ---
    async def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else None
        except Exception as e:
            log.error(f"通过ID获取用户信息失败: {e}")
            return None
            
    async def update_user_password(self, user_id: int, new_password: str) -> Dict[str, Any]:
        """更新用户密码
        
        Args:
            user_id: 用户ID
            new_password: 新密码
            
        Returns:
            Dict: 包含操作结果的字典
        """
        try:
            if len(new_password) < 6:
                return {"success": False, "error": "密码长度至少6位"}
                
            # 检查用户是否存在
            user = await self.get_user_by_id(user_id)
            if not user:
                return {"success": False, "error": "用户不存在"}
            
            # 生成新的密码哈希
            password_hash, salt = self.hash_password(new_password)
            
            # 更新数据库中的密码和盐
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                    (password_hash, salt, user_id)
                )
                await db.commit()
                
            log.info(f"用户ID {user_id} 密码已更新")
            return {"success": True, "message": "密码已成功更新"}
        except Exception as e:
            log.error(f"更新用户密码时出错: {str(e)}")
            return {"success": False, "error": f"更新密码失败: {str(e)}"}
    
    async def get_all_users(self) -> List[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute("SELECT id, username, created_at, last_login, is_active FROM users ORDER BY created_at DESC") as cursor:
                    users = await cursor.fetchall()
                
                user_list = []
                for user_row in users:
                    user = dict(user_row)
                    user['credential_count'] = await self._get_user_credential_count_from_db(user['id'])
                    user['is_active'] = bool(user['is_active'])
                    user_list.append(user)
                return user_list
        except Exception as e:
            log.error(f"获取用户列表失败: {e}")
            return []

    async def _get_user_credential_count_from_db(self, user_id: int) -> int:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT COUNT(id) FROM credentials WHERE user_id = ?", (user_id,)) as cursor:
                    count = await cursor.fetchone()
                    return count[0] if count else 0
        except Exception as e:
            log.warning(f"从数据库获取用户 {user_id} 凭证数量失败: {e}")
            return 0

    async def get_user_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute('SELECT * FROM users WHERE api_key = ? AND is_active = 1', (api_key,)) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else None
        except Exception as e:
            log.error(f"获取用户信息失败: {e}")
            return None

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute('SELECT * FROM users WHERE username = ?', (username,)) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else None
        except Exception as e:
            log.error(f"通过用户名获取用户信息失败: {e}")
            return None

    async def regenerate_api_key(self, user_id: int) -> Dict[str, Any]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                new_api_key = self.generate_api_key()
                cursor = await db.execute('UPDATE users SET api_key = ? WHERE id = ? AND is_active = 1', (new_api_key, user_id))
                if cursor.rowcount == 0:
                    return {"success": False, "error": "用户不存在或已被禁用"}
                await db.commit()
                log.info(f"用户 {user_id} API密钥重新生成成功")
                return {"success": True, "api_key": new_api_key}
        except Exception as e:
            log.error(f"重新生成API密钥失败: {e}")
            return {"success": False, "error": "重新生成API密钥时发生错误"}

    # --- 会话管理 (异步) ---
    async def create_session(self, user_id: int, expires_hours: int = 24) -> str:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                session_token = self.generate_session_token()
                await db.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, datetime('now', '+{} hours'))
                '''.format(expires_hours), (user_id, session_token))
                await db.commit()
                return session_token
        except Exception as e:
            log.error(f"创建会话失败: {e}")
            return None

    async def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = sqlite3.Row
                async with db.execute('''
                    SELECT s.user_id, u.username, u.api_key
                    FROM user_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_token = ? AND s.is_active = 1 AND s.expires_at > datetime('now') AND u.is_active = 1
                ''', (session_token,)) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else None
        except Exception as e:
            log.error(f"验证会话失败: {e}")
            return None

    async def invalidate_session(self, session_token: str) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute('UPDATE user_sessions SET is_active = 0 WHERE session_token = ?', (session_token,))
                await db.commit()
                return cursor.rowcount > 0
        except Exception as e:
            log.error(f"使会话失效失败: {e}")
            return False

# 全局数据库实例
user_db = UserDatabase()
