"""
认证API模块 - 处理OAuth认证流程和批量上传
"""
import os
import json
import time
from log import log
import secrets
import threading
import subprocess
from typing import Optional, Dict, Any, List
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import uuid

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
import httpx

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
CALLBACK_HOST = 'localhost'
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
        
        log.info(f"收到OAuth回调: code={'已获取' if code else '未获取'}, state={state}")
        
        if code and state and state in auth_flows:
            # 更新流程状态
            auth_flows[state]['code'] = code
            auth_flows[state]['completed'] = True
            
            log.info(f"OAuth回调成功处理: state={state}")
            
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


async def enable_required_apis(credentials: Credentials, project_id: str) -> bool:
    """自动启用必需的API服务"""
    try:
        # 确保凭证有效
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(GoogleAuthRequest())
        
        headers = {
            "Authorization": f"Bearer {credentials.token}",
            "Content-Type": "application/json",
            "User-Agent": "geminicli-oauth/1.0",
        }
        
        # 需要启用的服务列表
        required_services = [
            "geminicloudassist.googleapis.com",  # Gemini Cloud Assist API
            "cloudaicompanion.googleapis.com"    # Gemini for Google Cloud API
        ]
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            for service in required_services:
                log.info(f"正在检查并启用服务: {service}")
                
                # 检查服务是否已启用
                check_url = f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services/{service}"
                try:
                    check_response = await client.get(check_url, headers=headers)
                    if check_response.status_code == 200:
                        service_data = check_response.json()
                        if service_data.get("state") == "ENABLED":
                            log.info(f"服务 {service} 已启用")
                            continue
                except Exception as e:
                    log.debug(f"检查服务状态失败，将尝试启用: {e}")
                
                # 启用服务
                enable_url = f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services/{service}:enable"
                try:
                    enable_response = await client.post(enable_url, headers=headers, json={})
                    
                    if enable_response.status_code in [200, 201]:
                        log.info(f"✅ 成功启用服务: {service}")
                    elif enable_response.status_code == 400:
                        error_data = enable_response.json()
                        if "already enabled" in error_data.get("error", {}).get("message", "").lower():
                            log.info(f"✅ 服务 {service} 已经启用")
                        else:
                            log.warning(f"⚠️ 启用服务 {service} 时出现警告: {error_data}")
                    else:
                        log.warning(f"⚠️ 启用服务 {service} 失败: {enable_response.status_code} - {enable_response.text}")
                        
                except Exception as e:
                    log.warning(f"⚠️ 启用服务 {service} 时发生异常: {e}")
                    
        return True
        
    except Exception as e:
        log.error(f"启用API服务时发生错误: {e}")
        return False


async def get_user_projects(credentials: Credentials) -> List[Dict[str, Any]]:
    """获取用户可访问的Google Cloud项目列表"""
    try:
        # 确保凭证有效
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(GoogleAuthRequest())
        
        headers = {
            "Authorization": f"Bearer {credentials.token}",
            "User-Agent": "geminicli-oauth/1.0",
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 使用v3 API的projects:search端点
            url = "https://cloudresourcemanager.googleapis.com/v3/projects:search"
            log.info(f"正在调用API: {url}")
            response = await client.get(url, headers=headers)
            
            log.info(f"API响应状态码: {response.status_code}")
            if response.status_code != 200:
                log.error(f"API响应内容: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                projects = data.get('projects', [])
                # 只返回活跃的项目
                active_projects = [
                    project for project in projects 
                    if project.get('state') == 'ACTIVE'
                ]
                log.info(f"获取到 {len(active_projects)} 个活跃项目")
                return active_projects
            elif response.status_code == 403:
                log.warning(f"没有权限访问项目列表: {response.text}")
                # 尝试用户信息API来获取一些线索
                try:
                    userinfo_response = await client.get(
                        "https://www.googleapis.com/oauth2/v2/userinfo",
                        headers=headers
                    )
                    if userinfo_response.status_code == 200:
                        userinfo = userinfo_response.json()
                        log.info(f"获取到用户信息: {userinfo.get('email')}")
                except:
                    pass
                return []
            else:
                log.warning(f"获取项目列表失败: {response.status_code} - {response.text}")
                return []
                
    except Exception as e:
        log.error(f"获取用户项目列表失败: {e}")
        return []


async def select_default_project(projects: List[Dict[str, Any]]) -> Optional[str]:
    """从项目列表中选择默认项目"""
    if not projects:
        return None
    
    # 策略1：查找显示名称或项目ID包含"default"的项目
    for project in projects:
        display_name = project.get('displayName', '').lower()
        project_id = project.get('projectId', '')
        if 'default' in display_name or 'default' in project_id.lower():
            log.info(f"选择默认项目: {project_id} ({project.get('displayName', project_id)})")
            return project_id
    
    # 策略2：选择第一个项目
    first_project = projects[0]
    project_id = first_project.get('projectId', '')
    log.info(f"选择第一个项目作为默认: {project_id} ({first_project.get('displayName', project_id)})")
    return project_id


async def auto_detect_project_id() -> Optional[str]:
    """尝试从Google Cloud环境自动检测项目ID"""
    try:
        # 尝试从Google Cloud Metadata服务获取项目ID
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                headers={"Metadata-Flavor": "Google"}
            )
            if response.status_code == 200:
                project_id = response.text.strip()
                log.info(f"从Google Cloud Metadata自动检测到项目ID: {project_id}")
                return project_id
    except Exception as e:
        log.debug(f"无法从Metadata服务获取项目ID: {e}")
    
    # 尝试从gcloud配置获取默认项目
    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "project"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            project_id = result.stdout.strip()
            if project_id != "(unset)":
                log.info(f"从gcloud配置自动检测到项目ID: {project_id}")
                return project_id
    except Exception as e:
        log.debug(f"无法从gcloud配置获取项目ID: {e}")
    
    log.info("无法自动检测项目ID，将需要用户手动输入")
    return None


def create_auth_url(project_id: Optional[str] = None, user_session: str = None) -> Dict[str, Any]:
    """创建认证URL，支持自动检测项目ID"""
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
            'project_id': project_id,  # 可能为None，稍后在回调时确定
            'user_session': user_session,
            'code': None,
            'completed': False,
            'created_at': time.time(),
            'auto_project_detection': project_id is None  # 标记是否需要自动检测项目ID
        }
        
        # 清理过期的流程（30分钟）
        cleanup_expired_flows()
        
        log.info(f"OAuth流程已创建: state={state}, project_id={project_id}")
        log.info(f"用户需要访问认证URL，然后OAuth会回调到 {CALLBACK_URL}")
        
        return {
            'auth_url': auth_url,
            'state': state,
            'success': True,
            'auto_project_detection': project_id is None,
            'detected_project_id': project_id
        }
        
    except Exception as e:
        log.error(f"创建认证URL失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def start_callback_server():
    """启动回调服务器"""
    try:
        # 回源服务器监听0.0.0.0
        server = HTTPServer(("0.0.0.0", CALLBACK_PORT), AuthCallbackHandler)
        return server
    except OSError as e:
        if "Address already in use" in str(e):
            log.warning(f"端口{CALLBACK_PORT}已被占用，可能有其他OAuth流程正在进行")
            return None
        raise


def wait_for_callback_sync(state: str, timeout: int = 300) -> Optional[str]:
    """同步等待OAuth回调完成"""
    server = start_callback_server()
    
    if not server:
        log.error("无法启动回调服务器，端口可能被占用")
        return None
    
    try:
        log.info("启动OAuth回调服务器，等待用户授权...")
        
        # 使用handle_request()等待单个请求
        server.handle_request()
        
        # 检查是否获取到了授权码
        if state in auth_flows:
            return auth_flows[state].get('code')
        
        return None
        
    except Exception as e:
        log.error(f"等待回调时出错: {e}")
        return None
    finally:
        try:
            server.server_close()
        except:
            pass


async def complete_auth_flow(project_id: Optional[str] = None, user_session: str = None) -> Dict[str, Any]:
    """完成认证流程并保存凭证，支持自动检测项目ID"""
    try:
        # 查找对应的认证流程
        state = None
        flow_data = None
        
        # 如果指定了project_id，先尝试匹配指定的项目
        if project_id:
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
        
        # 如果没有指定项目ID或没找到匹配的，查找需要自动检测项目ID的流程
        if not state:
            for s, data in auth_flows.items():
                if data.get('auto_project_detection', False):
                    # 如果指定了用户会话，优先匹配相同会话的流程
                    if user_session and data.get('user_session') == user_session:
                        state = s
                        flow_data = data
                        break
                    # 使用第一个找到的需要自动检测的流程
                    elif not state:
                        state = s
                        flow_data = data
        
        if not state or not flow_data:
            return {
                'success': False,
                'error': '未找到对应的认证流程，请先点击获取认证链接'
            }
        
        # 如果需要自动检测项目ID且没有提供项目ID
        if flow_data.get('auto_project_detection', False) and not project_id:
            log.info("尝试自动检测项目ID...")
            detected_project_id = await auto_detect_project_id()
            if detected_project_id:
                project_id = detected_project_id
                flow_data['project_id'] = project_id
                log.info(f"自动检测到项目ID: {project_id}")
            else:
                return {
                    'success': False,
                    'error': '无法自动检测项目ID，请手动指定项目ID',
                    'requires_manual_project_id': True
                }
        elif not project_id:
            project_id = flow_data.get('project_id')
            if not project_id:
                return {
                    'success': False,
                    'error': '缺少项目ID，请指定项目ID',
                    'requires_manual_project_id': True
                }
        
        flow = flow_data['flow']
        
        # 如果还没有授权码，需要等待回调
        if not flow_data.get('code'):
            log.info(f"等待用户完成OAuth授权 (state: {state})")
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
            
            # 如果需要自动检测项目ID且没有提供项目ID
            if flow_data.get('auto_project_detection', False) and not project_id:
                log.info("尝试通过API获取用户项目列表...")
                log.info(f"使用的token: {credentials.token[:20]}...")
                log.info(f"Token过期时间: {credentials.expiry}")
                user_projects = await get_user_projects(credentials)
                
                if user_projects:
                    # 如果只有一个项目，自动使用
                    if len(user_projects) == 1:
                        project_id = user_projects[0].get('projectId')
                        if project_id:
                            flow_data['project_id'] = project_id
                            log.info(f"自动选择唯一项目: {project_id}")
                    # 如果有多个项目，尝试选择默认项目
                    else:
                        project_id = await select_default_project(user_projects)
                        if project_id:
                            flow_data['project_id'] = project_id
                            log.info(f"自动选择默认项目: {project_id}")
                        else:
                            # 返回项目列表让用户选择
                            return {
                                'success': False,
                                'error': '请从以下项目中选择一个',
                                'requires_project_selection': True,
                                'available_projects': [
                                    {
                                        'projectId': p.get('projectId'),
                                        'name': p.get('displayName') or p.get('projectId'),
                                        'projectNumber': p.get('projectNumber')
                                    }
                                    for p in user_projects
                                ]
                            }
                else:
                    # 如果无法获取项目列表，提示手动输入
                    return {
                        'success': False,
                        'error': '无法获取您的项目列表，请手动指定项目ID',
                        'requires_manual_project_id': True
                    }
            
            # 如果仍然没有项目ID，返回错误
            if not project_id:
                return {
                    'success': False,
                    'error': '缺少项目ID，请指定项目ID',
                    'requires_manual_project_id': True
                }
            
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
            
            log.info("OAuth认证成功，凭证已保存")
            return {
                'success': True,
                'credentials': creds_data,
                'file_path': file_path,
                'auto_detected_project': flow_data.get('auto_project_detection', False)
            }
            
        except Exception as e:
            log.error(f"获取凭证失败: {e}")
            return {
                'success': False,
                'error': f'获取凭证失败: {str(e)}'
            }
        finally:
            oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate
            
    except Exception as e:
        log.error(f"完成认证流程失败: {e}")
        return {
            'success': False,
            'error': str(e)
        }


async def asyncio_complete_auth_flow(project_id: Optional[str] = None, user_session: str = None) -> Dict[str, Any]:
    """异步完成认证流程，支持自动检测项目ID"""
    import asyncio
    
    try:
        log.info(f"[ASYNC] asyncio_complete_auth_flow开始执行: project_id={project_id}, user_session={user_session}")
        
        # 查找对应的认证流程
        state = None
        flow_data = None
        
        log.debug(f"[ASYNC] 当前所有auth_flows: {list(auth_flows.keys())}")
        
        # 如果指定了project_id，先尝试匹配指定的项目
        if project_id:
            log.info(f"[ASYNC] 尝试匹配指定的项目ID: {project_id}")
            for s, data in auth_flows.items():
                if data['project_id'] == project_id:
                    # 如果指定了用户会话，优先匹配相同会话的流程
                    if user_session and data.get('user_session') == user_session:
                        state = s
                        flow_data = data
                        log.info(f"[ASYNC] 找到匹配的用户会话: {s}")
                        break
                    # 如果没有指定会话，或没找到匹配会话的流程，使用第一个匹配项目ID的
                    elif not state:
                        state = s
                        flow_data = data
                        log.info(f"[ASYNC] 找到匹配的项目ID: {s}")
        
        # 如果没有指定项目ID或没找到匹配的，查找需要自动检测项目ID的流程
        if not state:
            log.info(f"[ASYNC] 没有找到指定项目的流程，查找自动检测流程")
            for s, data in auth_flows.items():
                log.debug(f"[ASYNC] 检查流程 {s}: auto_project_detection={data.get('auto_project_detection', False)}")
                if data.get('auto_project_detection', False):
                    # 如果指定了用户会话，优先匹配相同会话的流程
                    if user_session and data.get('user_session') == user_session:
                        state = s
                        flow_data = data
                        log.info(f"[ASYNC] 找到匹配用户会话的自动检测流程: {s}")
                        break
                    # 使用第一个找到的需要自动检测的流程
                    elif not state:
                        state = s
                        flow_data = data
                        log.info(f"[ASYNC] 找到自动检测流程: {s}")
        
        if not state or not flow_data:
            log.error(f"[ASYNC] 未找到认证流程: state={state}, flow_data存在={bool(flow_data)}")
            log.debug(f"[ASYNC] 当前所有flow_data: {list(auth_flows.keys())}")
            return {
                'success': False,
                'error': '未找到对应的认证流程，请先点击获取认证链接'
            }
        
        log.info(f"[ASYNC] 找到认证流程: state={state}")
        log.info(f"[ASYNC] flow_data内容: project_id={flow_data.get('project_id')}, auto_project_detection={flow_data.get('auto_project_detection')}")
        log.info(f"[ASYNC] 传入的project_id参数: {project_id}")
        
        # 如果需要自动检测项目ID且没有提供项目ID
        log.info(f"[ASYNC] 检查auto_project_detection条件: auto_project_detection={flow_data.get('auto_project_detection', False)}, not project_id={not project_id}")
        if flow_data.get('auto_project_detection', False) and not project_id:
            log.info("[ASYNC] 进入自动检测项目ID分支")
            log.info("尝试自动检测项目ID...")
            try:
                detected_project_id = await auto_detect_project_id()
                log.info(f"[ASYNC] auto_detect_project_id返回: {detected_project_id}")
                if detected_project_id:
                    project_id = detected_project_id
                    flow_data['project_id'] = project_id
                    log.info(f"自动检测到项目ID: {project_id}")
                else:
                    log.info("[ASYNC] 环境自动检测失败，跳过OAuth检查，直接进入等待阶段")
            except Exception as e:
                log.error(f"[ASYNC] auto_detect_project_id发生异常: {e}")
        elif not project_id:
            log.info("[ASYNC] 进入project_id检查分支")
            project_id = flow_data.get('project_id')
            if not project_id:
                log.error("[ASYNC] 缺少项目ID，返回错误")
                return {
                    'success': False,
                    'error': '缺少项目ID，请指定项目ID',
                    'requires_manual_project_id': True
                }
        else:
            log.info(f"[ASYNC] 使用提供的项目ID: {project_id}")
        
        # 检查是否已经有授权码
        log.info(f"[ASYNC] 开始检查OAuth授权码...")
        max_wait_time = 60  # 最多等待60秒
        wait_interval = 1   # 每秒检查一次
        waited = 0
        
        while waited < max_wait_time:
            log.debug(f"[ASYNC] 等待OAuth授权码... ({waited}/{max_wait_time}秒)")
            if flow_data.get('code'):
                log.info(f"[ASYNC] 检测到OAuth授权码，开始处理凭证 (等待时间: {waited}秒)")
                break
            
            # 异步等待
            await asyncio.sleep(wait_interval)
            waited += wait_interval
            
            # 刷新flow_data引用，因为可能被回调更新了
            if state in auth_flows:
                flow_data = auth_flows[state]
                log.debug(f"[ASYNC] 刷新flow_data: completed={flow_data.get('completed')}, code存在={bool(flow_data.get('code'))}")
        
        if not flow_data.get('code'):
            log.error(f"[ASYNC] 等待OAuth回调超时，等待了{waited}秒")
            return {
                'success': False,
                'error': '等待OAuth回调超时，请确保完成了浏览器中的认证并看到成功页面'
            }
        
        flow = flow_data['flow']
        auth_code = flow_data['code']
        
        log.info(f"[ASYNC] 开始使用授权码获取凭证: code={'***' + auth_code[-4:] if auth_code else 'None'}")
        
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
            log.info(f"[ASYNC] 调用flow.fetch_token...")
            flow.fetch_token(code=auth_code)
            credentials = flow.credentials
            log.info(f"[ASYNC] 成功获取凭证，token前缀: {credentials.token[:20] if credentials.token else 'None'}...")
            
            log.info(f"[ASYNC] 检查是否需要项目检测: auto_project_detection={flow_data.get('auto_project_detection')}, project_id={project_id}")
            
            # 如果需要自动检测项目ID且没有提供项目ID
            if flow_data.get('auto_project_detection', False) and not project_id:
                log.info("尝试通过API获取用户项目列表...")
                log.info(f"使用的token: {credentials.token[:20]}...")
                log.info(f"Token过期时间: {credentials.expiry}")
                user_projects = await get_user_projects(credentials)
                
                if user_projects:
                    # 如果只有一个项目，自动使用
                    if len(user_projects) == 1:
                        project_id = user_projects[0].get('projectId')
                        if project_id:
                            flow_data['project_id'] = project_id
                            log.info(f"自动选择唯一项目: {project_id}")
                            # 自动启用必需的API服务
                            log.info("正在自动启用必需的API服务...")
                            await enable_required_apis(credentials, project_id)
                    # 如果有多个项目，尝试选择默认项目
                    else:
                        project_id = await select_default_project(user_projects)
                        if project_id:
                            flow_data['project_id'] = project_id
                            log.info(f"自动选择默认项目: {project_id}")
                            # 自动启用必需的API服务
                            log.info("正在自动启用必需的API服务...")
                            await enable_required_apis(credentials, project_id)
                        else:
                            # 返回项目列表让用户选择
                            return {
                                'success': False,
                                'error': '请从以下项目中选择一个',
                                'requires_project_selection': True,
                                'available_projects': [
                                    {
                                        'projectId': p.get('projectId'),
                                        'name': p.get('displayName') or p.get('projectId'),
                                        'projectNumber': p.get('projectNumber')
                                    }
                                    for p in user_projects
                                ]
                            }
                else:
                    # 如果无法获取项目列表，提示手动输入
                    return {
                        'success': False,
                        'error': '无法获取您的项目列表，请手动指定项目ID',
                        'requires_manual_project_id': True
                    }
            elif project_id:
                # 如果已经有项目ID（手动提供或环境检测），也尝试启用API服务
                log.info("正在为已提供的项目ID自动启用必需的API服务...")
                await enable_required_apis(credentials, project_id)
            
            # 如果仍然没有项目ID，返回错误
            if not project_id:
                return {
                    'success': False,
                    'error': '缺少项目ID，请指定项目ID',
                    'requires_manual_project_id': True
                }
            
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
            
            log.info("OAuth认证成功，凭证已保存")
            return {
                'success': True,
                'credentials': creds_data,
                'file_path': file_path,
                'auto_detected_project': flow_data.get('auto_project_detection', False)
            }
            
        except Exception as e:
            log.error(f"获取凭证失败: {e}")
            return {
                'success': False,
                'error': f'获取凭证失败: {str(e)}'
            }
        finally:
            oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate
            
    except Exception as e:
        log.error(f"异步完成认证流程失败: {e}")
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
    
    log.info(f"凭证已保存到: {file_path}")
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
        log.info(f"清理了 {len(expired_states)} 个过期的认证流程")


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
        log.warning("PASSWORD环境变量未设置，拒绝访问")
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
            log.warning("认证文件缺少project_id字段")
        
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
        
        log.info(f"认证文件已上传保存: {file_path}")
        
        return {
            'success': True,
            'file_path': file_path,
            'project_id': project_id
        }
        
    except Exception as e:
        log.error(f"保存上传文件失败: {e}")
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
        log.info(f"OAuth回调服务器已在运行")
        return True
    
    try:
        # 回源服务器监听0.0.0.0
        oauth_server = HTTPServer(("0.0.0.0", CALLBACK_PORT), AuthCallbackHandler)
        oauth_server_thread = threading.Thread(target=oauth_server.serve_forever, daemon=True)
        oauth_server_thread.start()
        log.info(f"OAuth回调服务器已启动")
        return True
    except OSError as e:
        if "Address already in use" in str(e):
            log.warning(f"端口{CALLBACK_PORT}已被占用，OAuth回调可能无法正常工作")
            return False
        log.error(f"启动OAuth服务器失败: {e}")
        return False
    except Exception as e:
        log.error(f"启动OAuth服务器时出现未知错误: {e}")
        return False


def stop_oauth_server():
    """停止OAuth回调服务器"""
    global oauth_server, oauth_server_thread
    
    if oauth_server is not None:
        oauth_server.shutdown()
        oauth_server.server_close()
        oauth_server = None
        log.info("OAuth回调服务器已停止")
    
    if oauth_server_thread is not None:
        oauth_server_thread.join(timeout=5)
        oauth_server_thread = None


def ensure_oauth_server_running():
    """确保OAuth服务器正在运行"""
    global oauth_server
    
    if oauth_server is None:
        return start_oauth_server()
    return True