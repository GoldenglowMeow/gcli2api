import os
import json
import time
import shutil
from typing import Optional, List, Dict, Any
from log import log
from .user_database import user_db
from google.oauth2.credentials import Credentials

class UserCredentialManager:
    """用户凭证管理器"""
    
    def __init__(self):
        self.base_creds_dir = os.path.join(os.path.dirname(__file__), '..', 'creds')
        os.makedirs(self.base_creds_dir, exist_ok=True)
    
    def get_user_creds_dir(self, username: str) -> str:
        """获取用户凭证目录路径"""
        user_dir = os.path.join(self.base_creds_dir, username)
        os.makedirs(user_dir, exist_ok=True)
        return user_dir
    
    def save_user_credential(self, user_id: int, username: str, file_content: str, 
                           original_filename: str, project_id: str = None) -> Dict[str, Any]:
        """保存用户凭证文件"""
        try:
            # 验证JSON格式
            try:
                cred_data = json.loads(file_content)
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": "无效的JSON格式"
                }
            
            # 验证凭证文件必要字段
            required_fields = ['client_id', 'client_secret']
            for field in required_fields:
                if field not in cred_data:
                    return {
                        "success": False,
                        "error": f"缺少必要字段: {field}"
                    }
            
            # 获取用户凭证目录
            user_creds_dir = self.get_user_creds_dir(username)
            
            # 生成唯一文件名
            timestamp = int(time.time())
            base_name = os.path.splitext(original_filename)[0]
            filename = f"{base_name}-{timestamp}.json"
            file_path = os.path.join(user_creds_dir, filename)
            
            # 确保文件名唯一
            counter = 1
            while os.path.exists(file_path):
                filename = f"{base_name}-{timestamp}-{counter}.json"
                file_path = os.path.join(user_creds_dir, filename)
                counter += 1
            
            # 保存文件
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(cred_data, f, indent=2, ensure_ascii=False)
            
            # 记录到数据库
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_credentials 
                    (user_id, filename, original_filename, file_path, project_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, filename, original_filename, file_path, project_id))
                conn.commit()
            
            log.info(f"用户 {username} 凭证文件保存成功: {filename}")
            
            return {
                "success": True,
                "filename": filename,
                "file_path": file_path
            }
            
        except Exception as e:
            log.error(f"保存用户凭证失败: {e}")
            return {
                "success": False,
                "error": "保存凭证时发生错误"
            }
    
    def get_user_credentials(self, user_id: int) -> List[Dict[str, Any]]:
        """获取用户的所有凭证文件信息"""
        try:
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT filename, original_filename, file_path, project_id, 
                           is_enabled, created_at, last_used
                    FROM user_credentials
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                ''', (user_id,))
                
                credentials = []
                for row in cursor.fetchall():
                    filename, original_filename, file_path, project_id, is_enabled, created_at, last_used = row
                    
                    # 检查文件是否存在
                    file_exists = os.path.exists(file_path)
                    file_size = os.path.getsize(file_path) if file_exists else 0
                    
                    credentials.append({
                        "filename": filename,
                        "original_filename": original_filename,
                        "project_id": project_id,
                        "is_enabled": bool(is_enabled),
                        "created_at": created_at,
                        "last_used": last_used,
                        "file_exists": file_exists,
                        "file_size": file_size
                    })
                
                return credentials
                
        except Exception as e:
            log.error(f"获取用户凭证列表失败: {e}")
            return []
    
    def toggle_credential_status(self, user_id: int, filename: str, enabled: bool) -> Dict[str, Any]:
        """启用/禁用凭证文件"""
        try:
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                
                # 检查凭证是否属于该用户
                cursor.execute('''
                    SELECT id FROM user_credentials
                    WHERE user_id = ? AND filename = ?
                ''', (user_id, filename))
                
                if not cursor.fetchone():
                    return {
                        "success": False,
                        "error": "凭证文件不存在或无权限"
                    }
                
                # 更新状态
                cursor.execute('''
                    UPDATE user_credentials
                    SET is_enabled = ?
                    WHERE user_id = ? AND filename = ?
                ''', (enabled, user_id, filename))
                
                conn.commit()
                
                action = "启用" if enabled else "禁用"
                log.info(f"用户 {user_id} {action}凭证文件: {filename}")
                
                return {
                    "success": True,
                    "message": f"凭证文件已{action}"
                }
                
        except Exception as e:
            log.error(f"切换凭证状态失败: {e}")
            return {
                "success": False,
                "error": "操作失败"
            }
    
    def delete_credential(self, user_id: int, filename: str) -> Dict[str, Any]:
        """删除凭证文件"""
        try:
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取文件路径
                cursor.execute('''
                    SELECT file_path FROM user_credentials
                    WHERE user_id = ? AND filename = ?
                ''', (user_id, filename))
                
                result = cursor.fetchone()
                if not result:
                    return {
                        "success": False,
                        "error": "凭证文件不存在或无权限"
                    }
                
                file_path = result[0]
                
                # 删除物理文件
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                # 从数据库删除记录
                cursor.execute('''
                    DELETE FROM user_credentials
                    WHERE user_id = ? AND filename = ?
                ''', (user_id, filename))
                
                conn.commit()
                
                log.info(f"用户 {user_id} 删除凭证文件: {filename}")
                
                return {
                    "success": True,
                    "message": "凭证文件已删除"
                }
                
        except Exception as e:
            log.error(f"删除凭证文件失败: {e}")
            return {
                "success": False,
                "error": "删除失败"
            }
    
    def get_enabled_credentials(self, user_id: int) -> List[str]:
        """获取用户启用的凭证文件路径列表"""
        try:
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_path FROM user_credentials
                    WHERE user_id = ? AND is_enabled = 1
                    ORDER BY created_at DESC
                ''', (user_id,))
                
                file_paths = []
                for row in cursor.fetchall():
                    file_path = row[0]
                    if os.path.exists(file_path):
                        file_paths.append(file_path)
                
                return file_paths
                
        except Exception as e:
            log.error(f"获取启用凭证列表失败: {e}")
            return []
    
    def load_credential_file(self, file_path: str) -> Optional[Credentials]:
        """加载凭证文件为Google Credentials对象"""
        try:
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                cred_data = json.load(f)
            
            # 创建Credentials对象
            credentials = Credentials(
                token=cred_data.get('token'),
                refresh_token=cred_data.get('refresh_token'),
                token_uri=cred_data.get('token_uri', 'https://oauth2.googleapis.com/token'),
                client_id=cred_data.get('client_id'),
                client_secret=cred_data.get('client_secret'),
                scopes=cred_data.get('scopes')
            )
            
            return credentials
            
        except Exception as e:
            log.error(f"加载凭证文件失败 {file_path}: {e}")
            return None
    
    def update_last_used(self, user_id: int, filename: str):
        """更新凭证文件最后使用时间"""
        try:
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE user_credentials
                    SET last_used = CURRENT_TIMESTAMP
                    WHERE user_id = ? AND filename = ?
                ''', (user_id, filename))
                conn.commit()
                
        except Exception as e:
            log.error(f"更新凭证使用时间失败: {e}")
    
    def get_credential_content(self, user_id: int, filename: str) -> Optional[Dict[str, Any]]:
        """获取凭证文件内容"""
        try:
            import sqlite3
            with sqlite3.connect(user_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_path FROM user_credentials
                    WHERE user_id = ? AND filename = ?
                ''', (user_id, filename))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                file_path = result[0]
                if not os.path.exists(file_path):
                    return None
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
                    
        except Exception as e:
            log.error(f"获取凭证文件内容失败: {e}")
            return None

# 全局用户凭证管理器实例
user_credential_manager = UserCredentialManager()