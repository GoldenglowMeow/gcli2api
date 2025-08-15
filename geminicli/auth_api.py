"""
认证API模块 - 处理OAuth认证流程和批量上传
"""
import os
import json
import time
import logging
import secrets
import threading
from typing import Optional, Dict, Any, List
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import uuid

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

from .config import CREDENTIALS_DIR

# OAuth Configuration
CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
CLIENT_SECRET = "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"
SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# 回调服务器配置
CALLBACK_HOST = os.getenv('OAUTH_CALLBACK_HOST', 'localhost')
CALLBACK_PORT = int(os.getenv('OAUTH_CALLBACK_PORT', '8080'))
CALLBACK_URL = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}"

# 全局状态管理
auth_flows = {}  # 存储进行中的认证流程
oauth_server = None  # 全局OAuth回调服务器
oauth_server_thread = None  # 服务器线程

class AuthCallbackHandler(BaseHTTPRequestHandler):
    """OAuth回调处理器"""
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        code = query_components.get("code", [None])[0]
        state = query_components.get("state", [None])[0]
        
        logging.info(f"收到OAuth回调: code={'已获取' if code else '未获取'}, state={state}")
        
        if code and state and state in auth_flows:
            # 更新流程状态
            auth_flows[state]['code'] = code
            auth_flows[state]['completed'] = True
            
            logging.info(f"OAuth回调成功处理: state={state}")
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # 成功页面
            self.wfile.write(b"<h1>OAuth authentication successful!</h1><p>You can close this window. Please return to the original page and click 'Get Credentials' button.</p>")
        else:
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication failed.</h1><p>Please try again.</p>")
    
    def log_message(self, format, *args):
        # 减少日志噪音
        pass


def create_auth_url(project_id: str, user_session: str = None) -> Dict[str, Any]:
    """创建认证URL"""
    try:
        # 确保OAuth回调服务器正在运行
        if not ensure_oauth_server_running():
            return {
                'success': False,
                'error': f'无法启动OAuth回调服务器，端口{CALLBACK_PORT}可能被占用'
            }
        # 创建OAuth流程
        client_config = {
            "installed": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
        
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=CALLBACK_URL
        )
        
        flow.oauth2session.scope = SCOPES
        
        # 生成状态标识符，包含用户会话信息
        if user_session:
            state = f"{user_session}_{str(uuid.uuid4())}"
        else:
            state = str(uuid.uuid4())
        
        # 生成认证URL
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes='true',
            state=state
        )
        
        # 保存流程状态
        auth_flows[state] = {
            'flow': flow,
            'project_id': project_id,
            'user_session': user_session,
            'code': None,
            'completed': False,
            'created_at': time.time()
        }
        
        # 清理过期的流程（30分钟）
        cleanup_expired_flows()
        
        logging.info(f"OAuth流程已创建: state={state}, project_id={project_id}")
        logging.info(f"用户需要访问认证URL，然后OAuth会回调到 {CALLBACK_URL}")
        
        return {
            'auth_url': auth_url,
            'state': state,
            'success': True
        }
        
    except Exception as e:
        logging.error(f"创建认证URL失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def start_callback_server():
    """启动回调服务器"""
    try:
        # 使用配置的主机和端口
        host = "" if CALLBACK_HOST == "localhost" else CALLBACK_HOST
        server = HTTPServer((host, CALLBACK_PORT), AuthCallbackHandler)
        return server
    except OSError as e:
        if "Address already in use" in str(e):
            logging.warning(f"端口{CALLBACK_PORT}已被占用，可能有其他OAuth流程正在进行")
            return None
        raise


def wait_for_callback_sync(state: str, timeout: int = 300) -> Optional[str]:
    """同步等待OAuth回调完成"""
    server = start_callback_server()
    
    if not server:
        logging.error("无法启动回调服务器，端口可能被占用")
        return None
    
    try:
        logging.info("启动OAuth回调服务器，等待用户授权...")
        
        # 使用handle_request()等待单个请求
        server.handle_request()
        
        # 检查是否获取到了授权码
        if state in auth_flows:
            return auth_flows[state].get('code')
        
        return None
        
    except Exception as e:
        logging.error(f"等待回调时出错: {e}")
        return None
    finally:
        try:
            server.server_close()
        except:
            pass


def complete_auth_flow(project_id: str, user_session: str = None) -> Dict[str, Any]:
    """完成认证流程并保存凭证，等待OAuth回调"""
    try:
        # 查找对应的认证流程，优先匹配用户会话
        state = None
        flow_data = None
        for s, data in auth_flows.items():
            if data['project_id'] == project_id:
                # 如果指定了用户会话，优先匹配相同会话的流程
                if user_session and data.get('user_session') == user_session:
                    state = s
                    flow_data = data
                    break
                # 如果没有指定会话，或没找到匹配会话的流程，使用第一个匹配项目ID的
                elif not state:
                    state = s
                    flow_data = data
        
        if not state or not flow_data:
            return {
                'success': False,
                'error': '未找到对应的认证流程，请先点击获取认证链接'
            }
        
        flow = flow_data['flow']
        
        # 如果还没有授权码，需要等待回调
        if not flow_data.get('code'):
            logging.info(f"等待用户完成OAuth授权 (state: {state})")
            auth_code = wait_for_callback_sync(state)
            
            if not auth_code:
                return {
                    'success': False,
                    'error': '未接收到授权回调，请确保完成了浏览器中的OAuth认证'
                }
            
            # 更新流程数据
            auth_flows[state]['code'] = auth_code
            auth_flows[state]['completed'] = True
        else:
            auth_code = flow_data['code']
        
        # 使用认证代码获取凭证
        import oauthlib.oauth2.rfc6749.parameters
        original_validate = oauthlib.oauth2.rfc6749.parameters.validate_token_parameters
        
        def patched_validate(params):
            try:
                return original_validate(params)
            except Warning:
                pass
        
        oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = patched_validate
        
        try:
            flow.fetch_token(code=auth_code)
            credentials = flow.credentials
            
            # 保存凭证文件
            file_path = save_credentials(credentials, project_id)
            
            # 准备返回的凭证数据
            creds_data = {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "scopes": credentials.scopes if credentials.scopes else SCOPES,
                "token_uri": "https://oauth2.googleapis.com/token",
                "project_id": project_id
            }
            
            if credentials.expiry:
                if credentials.expiry.tzinfo is None:
                    from datetime import timezone
                    expiry_utc = credentials.expiry.replace(tzinfo=timezone.utc)
                else:
                    expiry_utc = credentials.expiry
                creds_data["expiry"] = expiry_utc.isoformat()
            
            # 清理使用过的流程
            if state in auth_flows:
                del auth_flows[state]
            
            logging.info("OAuth认证成功，凭证已保存")
            return {
                'success': True,
                'credentials': creds_data,
                'file_path': file_path
            }
            
        except Exception as e:
            logging.error(f"获取凭证失败: {e}")
            return {
                'success': False,
                'error': f'获取凭证失败: {str(e)}'
            }
        finally:
            oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate
            
    except Exception as e:
        logging.error(f"完成认证流程失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }


async def asyncio_complete_auth_flow(project_id: str, user_session: str = None) -> Dict[str, Any]:
    """异步完成认证流程，避免阻塞Web请求"""
    import asyncio
    
    try:
        # 查找对应的认证流程，优先匹配用户会话
        state = None
        flow_data = None
        for s, data in auth_flows.items():
            if data['project_id'] == project_id:
                # 如果指定了用户会话，优先匹配相同会话的流程
                if user_session and data.get('user_session') == user_session:
                    state = s
                    flow_data = data
                    break
                # 如果没有指定会话，或没找到匹配会话的流程，使用第一个匹配项目ID的
                elif not state:
                    state = s
                    flow_data = data
        
        if not state or not flow_data:
            return {
                'success': False,
                'error': '未找到对应的认证流程，请先点击获取认证链接'
            }
        
        # 检查是否已经有授权码
        max_wait_time = 60  # 最多等待60秒
        wait_interval = 1   # 每秒检查一次
        waited = 0
        
        while waited < max_wait_time:
            if flow_data.get('code'):
                logging.info(f"检测到OAuth授权码，开始处理凭证 (等待时间: {waited}秒)")
                break
            
            # 异步等待
            await asyncio.sleep(wait_interval)
            waited += wait_interval
            
            # 刷新flow_data引用，因为可能被回调更新了
            if state in auth_flows:
                flow_data = auth_flows[state]
        
        if not flow_data.get('code'):
            return {
                'success': False,
                'error': '等待OAuth回调超时，请确保完成了浏览器中的认证并看到成功页面'
            }
        
        flow = flow_data['flow']
        auth_code = flow_data['code']
        
        # 使用认证代码获取凭证
        import oauthlib.oauth2.rfc6749.parameters
        original_validate = oauthlib.oauth2.rfc6749.parameters.validate_token_parameters
        
        def patched_validate(params):
            try:
                return original_validate(params)
            except Warning:
                pass
        
        oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = patched_validate
        
        try:
            flow.fetch_token(code=auth_code)
            credentials = flow.credentials
            
            # 保存凭证文件
            file_path = save_credentials(credentials, project_id)
            
            # 准备返回的凭证数据
            creds_data = {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "scopes": credentials.scopes if credentials.scopes else SCOPES,
                "token_uri": "https://oauth2.googleapis.com/token",
                "project_id": project_id
            }
            
            if credentials.expiry:
                if credentials.expiry.tzinfo is None:
                    from datetime import timezone
                    expiry_utc = credentials.expiry.replace(tzinfo=timezone.utc)
                else:
                    expiry_utc = credentials.expiry
                creds_data["expiry"] = expiry_utc.isoformat()
            
            # 清理使用过的流程
            if state in auth_flows:
                del auth_flows[state]
            
            logging.info("OAuth认证成功，凭证已保存")
            return {
                'success': True,
                'credentials': creds_data,
                'file_path': file_path
            }
            
        except Exception as e:
            logging.error(f"获取凭证失败: {e}")
            return {
                'success': False,
                'error': f'获取凭证失败: {str(e)}'
            }
        finally:
            oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate
            
    except Exception as e:
        logging.error(f"异步完成认证流程失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def save_credentials(creds: Credentials, project_id: str) -> str:
    """保存凭证到文件"""
    # 确保目录存在
    os.makedirs(CREDENTIALS_DIR, exist_ok=True)
    
    # 生成文件名（使用project_id和时间戳）
    timestamp = int(time.time())
    filename = f"{project_id}-{timestamp}.json"
    file_path = os.path.join(CREDENTIALS_DIR, filename)
    
    # 准备凭证数据
    creds_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "scopes": creds.scopes if creds.scopes else SCOPES,
        "token_uri": "https://oauth2.googleapis.com/token",
        "project_id": project_id
    }
    
    if creds.expiry:
        if creds.expiry.tzinfo is None:
            from datetime import timezone
            expiry_utc = creds.expiry.replace(tzinfo=timezone.utc)
        else:
            expiry_utc = creds.expiry
        creds_data["expiry"] = expiry_utc.isoformat()
    
    # 保存到文件
    with open(file_path, "w", encoding='utf-8') as f:
        json.dump(creds_data, f, indent=2, ensure_ascii=False)
    
    logging.info(f"凭证已保存到: {file_path}")
    return file_path


def cleanup_expired_flows():
    """清理过期的认证流程"""
    current_time = time.time()
    expired_states = []
    
    for state, flow_data in auth_flows.items():
        if current_time - flow_data['created_at'] > 1800:  # 30分钟过期
            expired_states.append(state)
    
    for state in expired_states:
        del auth_flows[state]
    
    if expired_states:
        logging.info(f"清理了 {len(expired_states)} 个过期的认证流程")


def get_auth_status(project_id: str) -> Dict[str, Any]:
    """获取认证状态"""
    for state, flow_data in auth_flows.items():
        if flow_data['project_id'] == project_id:
            return {
                'status': 'completed' if flow_data['completed'] else 'pending',
                'state': state,
                'created_at': flow_data['created_at']
            }
    
    return {
        'status': 'not_found'
    }


# 鉴权功能
auth_tokens = {}  # 存储有效的认证令牌


def verify_password(password: str) -> bool:
    """验证密码"""
    correct_password = os.getenv('PASSWORD', 'pwd')
    if not correct_password:
        logging.warning("PASSWORD环境变量未设置，拒绝访问")
        return False
    
    return password == correct_password


def generate_auth_token() -> str:
    """生成认证令牌"""
    token = secrets.token_urlsafe(32)
    auth_tokens[token] = {
        'created_at': time.time(),
        'valid': True
    }
    return token


def verify_auth_token(token: str) -> bool:
    """验证认证令牌"""
    if not token or token not in auth_tokens:
        return False
    
    token_data = auth_tokens[token]
    
    # 检查令牌是否过期 (24小时)
    if time.time() - token_data['created_at'] > 86400:
        del auth_tokens[token]
        return False
    
    return token_data['valid']


def invalidate_auth_token(token: str):
    """使认证令牌失效"""
    if token in auth_tokens:
        del auth_tokens[token]


# 批量上传功能
def validate_credential_file(file_content: str) -> Dict[str, Any]:
    """验证认证文件格式"""
    try:
        creds_data = json.loads(file_content)
        
        # 检查必要字段
        required_fields = ['client_id', 'client_secret', 'refresh_token', 'token_uri']
        missing_fields = [field for field in required_fields if field not in creds_data]
        
        if missing_fields:
            return {
                'valid': False,
                'error': f'缺少必要字段: {", ".join(missing_fields)}'
            }
        
        # 检查project_id
        if 'project_id' not in creds_data:
            logging.warning("认证文件缺少project_id字段")
        
        return {
            'valid': True,
            'data': creds_data
        }
        
    except json.JSONDecodeError as e:
        return {
            'valid': False,
            'error': f'JSON格式错误: {str(e)}'
        }
    except Exception as e:
        return {
            'valid': False,
            'error': f'文件验证失败: {str(e)}'
        }


def save_uploaded_credential(file_content: str, original_filename: str) -> Dict[str, Any]:
    """保存上传的认证文件"""
    try:
        # 验证文件格式
        validation = validate_credential_file(file_content)
        if not validation['valid']:
            return {
                'success': False,
                'error': validation['error']
            }
        
        creds_data = validation['data']
        
        # 确保目录存在
        os.makedirs(CREDENTIALS_DIR, exist_ok=True)
        
        # 生成文件名
        project_id = creds_data.get('project_id', 'unknown')
        timestamp = int(time.time())
        
        # 从原文件名中提取有用信息
        base_name = os.path.splitext(original_filename)[0]
        filename = f"{base_name}-{timestamp}.json"
        file_path = os.path.join(CREDENTIALS_DIR, filename)
        
        # 确保文件名唯一
        counter = 1
        while os.path.exists(file_path):
            filename = f"{base_name}-{timestamp}-{counter}.json"
            file_path = os.path.join(CREDENTIALS_DIR, filename)
            counter += 1
        
        # 保存文件
        with open(file_path, "w", encoding='utf-8') as f:
            json.dump(creds_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"认证文件已上传保存: {file_path}")
        
        return {
            'success': True,
            'file_path': file_path,
            'project_id': project_id
        }
        
    except Exception as e:
        logging.error(f"保存上传文件失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def batch_upload_credentials(files_data: List[Dict[str, str]]) -> Dict[str, Any]:
    """批量上传认证文件"""
    results = []
    success_count = 0
    
    for file_data in files_data:
        filename = file_data.get('filename', 'unknown.json')
        content = file_data.get('content', '')
        
        result = save_uploaded_credential(content, filename)
        result['filename'] = filename
        results.append(result)
        
        if result['success']:
            success_count += 1
    
    return {
        'uploaded_count': success_count,
        'total_count': len(files_data),
        'results': results
    }


def start_oauth_server():
    """启动全局OAuth回调服务器"""
    global oauth_server, oauth_server_thread
    
    if oauth_server is not None:
        logging.info(f"OAuth回调服务器已在运行 ({CALLBACK_URL})")
        return True
    
    try:
        host = "" if CALLBACK_HOST == "localhost" else CALLBACK_HOST
        oauth_server = HTTPServer((host, CALLBACK_PORT), AuthCallbackHandler)
        oauth_server_thread = threading.Thread(target=oauth_server.serve_forever, daemon=True)
        oauth_server_thread.start()
        logging.info(f"OAuth回调服务器已启动，监听地址: {CALLBACK_URL}")
        return True
    except OSError as e:
        if "Address already in use" in str(e):
            logging.warning(f"端口{CALLBACK_PORT}已被占用，OAuth回调可能无法正常工作")
            return False
        logging.error(f"启动OAuth服务器失败: {e}")
        return False
    except Exception as e:
        logging.error(f"启动OAuth服务器时出现未知错误: {e}")
        return False


def stop_oauth_server():
    """停止OAuth回调服务器"""
    global oauth_server, oauth_server_thread
    
    if oauth_server is not None:
        oauth_server.shutdown()
        oauth_server.server_close()
        oauth_server = None
        logging.info("OAuth回调服务器已停止")
    
    if oauth_server_thread is not None:
        oauth_server_thread.join(timeout=5)
        oauth_server_thread = None


def ensure_oauth_server_running():
    """确保OAuth服务器正在运行"""
    global oauth_server
    
    if oauth_server is None:
        return start_oauth_server()
    return True