import sqlite3
import hashlib
import secrets
import os
import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from log import log

# 数据库文件路径
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'users.db')

class UserDatabase:
    def __init__(self):
        self.db_path = DB_PATH
        self.init_database()
    
    def init_database(self):
        """初始化数据库表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 创建用户表
                cursor.execute('''
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
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_token TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # 创建用户凭证文件记录表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        filename TEXT NOT NULL,
                        original_filename TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        project_id TEXT,
                        is_enabled BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_used TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        UNIQUE(user_id, filename)
                    )
                ''')
                
                conn.commit()
                log.info("用户数据库初始化完成")
                
        except Exception as e:
            log.error(f"数据库初始化失败: {e}")
            raise
    
    def validate_username(self, username: str) -> bool:
        """验证用户名格式：只能包含小写字母和数字"""
        if not username:
            return False
        return bool(re.match(r'^[a-z0-9]+$', username)) and len(username) >= 3 and len(username) <= 20
    
    def hash_password(self, password: str, salt: str = None) -> tuple:
        """哈希密码"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)
        return password_hash.hex(), salt
    
    def generate_api_key(self) -> str:
        """生成API密钥"""
        return f"gca-{secrets.token_urlsafe(32)}"
    
    def generate_session_token(self) -> str:
        """生成会话令牌"""
        return secrets.token_urlsafe(64)
    
    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        """创建新用户"""
        try:
            # 验证用户名格式
            if not self.validate_username(username):
                return {
                    "success": False,
                    "error": "用户名只能包含小写字母和数字，长度3-20位"
                }
            
            # 验证密码强度
            if len(password) < 6:
                return {
                    "success": False,
                    "error": "密码长度至少6位"
                }
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 检查用户名是否已存在
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    return {
                        "success": False,
                        "error": "用户名已存在"
                    }
                
                # 生成密码哈希和API密钥
                password_hash, salt = self.hash_password(password)
                api_key = self.generate_api_key()
                
                # 插入新用户
                cursor.execute('''
                    INSERT INTO users (username, password_hash, salt, api_key)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, salt, api_key))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                # 创建用户凭证目录
                user_creds_dir = os.path.join(os.path.dirname(__file__), '..', 'creds', username)
                os.makedirs(user_creds_dir, exist_ok=True)
                
                log.info(f"用户 {username} 创建成功，ID: {user_id}")
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "username": username,
                    "api_key": api_key
                }
                
        except Exception as e:
            log.error(f"创建用户失败: {e}")
            return {
                "success": False,
                "error": "创建用户时发生错误"
            }
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """用户认证"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取用户信息
                cursor.execute('''
                    SELECT id, username, password_hash, salt, api_key, is_active
                    FROM users WHERE username = ?
                ''', (username,))
                
                user = cursor.fetchone()
                if not user:
                    return {
                        "success": False,
                        "error": "用户名或密码错误"
                    }
                
                user_id, username, stored_hash, salt, api_key, is_active = user
                
                if not is_active:
                    return {
                        "success": False,
                        "error": "账户已被禁用"
                    }
                
                # 验证密码
                password_hash, _ = self.hash_password(password, salt)
                if password_hash != stored_hash:
                    return {
                        "success": False,
                        "error": "用户名或密码错误"
                    }
                
                # 更新最后登录时间
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id,))
                
                conn.commit()
                
                log.info(f"用户 {username} 登录成功")
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "username": username,
                    "api_key": api_key
                }
                
        except Exception as e:
            log.error(f"用户认证失败: {e}")
            return {
                "success": False,
                "error": "认证时发生错误"
            }
    
    def get_user_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """通过API密钥获取用户信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, username, api_key, is_active
                    FROM users WHERE api_key = ? AND is_active = 1
                ''', (api_key,))
                
                user = cursor.fetchone()
                if user:
                    return {
                        "user_id": user[0],
                        "username": user[1],
                        "api_key": user[2],
                        "is_active": user[3]
                    }
                
                return None
                
        except Exception as e:
            log.error(f"获取用户信息失败: {e}")
            return None
    
    def regenerate_api_key(self, user_id: int) -> Dict[str, Any]:
        """重新生成API密钥"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                new_api_key = self.generate_api_key()
                
                cursor.execute('''
                    UPDATE users SET api_key = ?
                    WHERE id = ? AND is_active = 1
                ''', (new_api_key, user_id))
                
                if cursor.rowcount == 0:
                    return {
                        "success": False,
                        "error": "用户不存在或已被禁用"
                    }
                
                conn.commit()
                
                log.info(f"用户 {user_id} API密钥重新生成成功")
                
                return {
                    "success": True,
                    "api_key": new_api_key
                }
                
        except Exception as e:
            log.error(f"重新生成API密钥失败: {e}")
            return {
                "success": False,
                "error": "重新生成API密钥时发生错误"
            }
    
    def create_session(self, user_id: int, expires_hours: int = 24) -> str:
        """创建用户会话"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                session_token = self.generate_session_token()
                
                cursor.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, datetime('now', '+{} hours'))
                '''.format(expires_hours), (user_id, session_token))
                
                conn.commit()
                
                return session_token
                
        except Exception as e:
            log.error(f"创建会话失败: {e}")
            return None
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """验证会话令牌"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT s.user_id, u.username, u.api_key
                    FROM user_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_token = ? 
                    AND s.is_active = 1 
                    AND s.expires_at > datetime('now')
                    AND u.is_active = 1
                ''', (session_token,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        "user_id": result[0],
                        "username": result[1],
                        "api_key": result[2]
                    }
                
                return None
                
        except Exception as e:
            log.error(f"验证会话失败: {e}")
            return None
    
    def invalidate_session(self, session_token: str) -> bool:
        """使会话失效"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE user_sessions SET is_active = 0
                    WHERE session_token = ?
                ''', (session_token,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            log.error(f"使会话失效失败: {e}")
            return False

# 全局数据库实例
user_db = UserDatabase()