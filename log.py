import sys
import os
import threading
import contextvars
from datetime import datetime
import shutil
import time
import queue
from threading import Thread
from typing import Optional

# --- 配置导入部分 ---
_user_context = contextvars.ContextVar('user_context', default=None)
_config_imported = False
_get_log_level, _get_max_log_size, _get_max_log_files, _get_log_buffer_size, _get_log_flush_interval = (None,) * 5

def _import_config():
    global _config_imported, _get_log_level, _get_max_log_size, _get_max_log_files, _get_log_buffer_size, _get_log_flush_interval
    if not _config_imported:
        try:
            from config import get_log_level, get_max_log_size, get_max_log_files, get_log_buffer_size, get_log_flush_interval
            _get_log_level = get_log_level
            _get_max_log_size = get_max_log_size
            _get_max_log_files = get_max_log_files
            _get_log_buffer_size = get_log_buffer_size
            _get_log_flush_interval = get_log_flush_interval
        except ImportError:
            _get_log_level = lambda: "INFO"
            _get_max_log_size = lambda: 500  # 500KB
            _get_max_log_files = lambda: 5
            _get_log_buffer_size = lambda: 100
            _get_log_flush_interval = lambda: 1.0
        _config_imported = True

# --- 日志级别定义 ---
LOG_LEVELS = {
    'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3, 'CRITICAL': 4
}

# 关闭信号对象
_SHUTDOWN_SENTINEL = object()


class _LogWriter:
    """
    封装日志写入线程、队列和文件操作的内部类。
    确保所有文件IO都由单个线程处理，避免竞态条件。
    """
    def __init__(self):
        self.queue = queue.Queue(maxsize=1000)
        self._thread: Optional[Thread] = None
        self._running = False
        self._file_lock = threading.Lock()
        self._log_file_path = self._get_log_file_path()

    def _get_log_file_path(self):
        """获取日志文件路径"""
        log_file = "log.txt"
        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        return os.path.join(logs_dir, log_file)

    def start(self):
        """启动日志写入线程"""
        if self._running:
            return
        self._running = True
        self._thread = Thread(target=self._writer_loop, daemon=True, name="LogWriterThread")
        self._thread.start()

    def stop(self):
        """优雅地停止日志写入线程"""
        if not self._running or not self._thread:
            return
        
        # 发送停止信号
        try:
            self.queue.put(_SHUTDOWN_SENTINEL, block=True, timeout=1.0)
        except queue.Full:
            # 如果队列已满，尝试清空一些空间
            try:
                self.queue.get_nowait()
                self.queue.put(_SHUTDOWN_SENTINEL, block=False)
            except:
                pass
        
        # 等待线程结束
        self._thread.join(timeout=5.0)
        self._running = False
        
        # 如果线程仍在运行，记录警告但不干预其操作
        if self._thread and self._thread.is_alive():
            print("Warning: Log thread did not terminate gracefully within timeout", file=sys.stderr)
        
        self._thread = None
        
    def submit(self, message: str):
        """将日志消息提交到队列"""
        if not self._running:
            self.start()
        
        try:
            # 使用短暂的超时而不是立即失败，提供更平滑的性能
            self.queue.put(message, block=True, timeout=0.1)
        except queue.Full:
            # 对于ERROR和CRITICAL级别的日志，尝试直接写入
            if "[ERROR]" in message or "[CRITICAL]" in message:
                try:
                    with self._file_lock:
                        with open(self._log_file_path, 'a', encoding='utf-8') as f:
                            f.write(message + '\n')
                            f.flush()
                except Exception as e:
                    print(f"Warning: Failed to write log directly: {e}", file=sys.stderr)
            # 可选：记录一个警告，表明日志系统过载
            if "[WARNING]" not in message and random.random() < 0.01:  # 只有1%的概率记录，避免刷屏
                warning_msg = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} [WARNING]: Log system overloaded, some logs may be dropped"
                print(warning_msg, file=sys.stderr)

    def _rotate_logs(self):
        """轮转日志文件"""
        try:
            # 如果日志文件不存在，不需要轮转
            if not os.path.exists(self._log_file_path):
                return
                
            # 获取最大日志文件数量
            max_log_files = _get_max_log_files()
                
            # 删除最旧的日志文件（如果达到最大数量）
            if os.path.exists(f"{self._log_file_path}.{max_log_files}"):
                os.remove(f"{self._log_file_path}.{max_log_files}")
                
            # 轮转现有的日志文件（从后向前）
            for i in range(max_log_files-1, 0, -1):
                if os.path.exists(f"{self._log_file_path}.{i}"):
                    shutil.move(f"{self._log_file_path}.{i}", f"{self._log_file_path}.{i+1}")
                    
            # 将当前日志文件移动为第一个备份
            shutil.move(self._log_file_path, f"{self._log_file_path}.1")
        except Exception as e:
            print(f"Warning: Failed to rotate log files: {e}", file=sys.stderr)

    def _flush_batch(self, messages_to_write, current_log_file):
        """批量写入日志消息并处理文件轮转"""
        try:
            # 确保文件已打开
            if not current_log_file or current_log_file.closed:
                current_log_file = open(self._log_file_path, 'a', encoding='utf-8')
            
            # 批量写入所有消息
            for msg in messages_to_write:
                current_log_file.write(msg + '\n')
            current_log_file.flush()
            
            # 检查文件大小并在需要时进行轮转
            current_size = current_log_file.tell()
            max_log_size_bytes = _get_max_log_size() * 1024  # 转换为字节
            
            # 只有当文件大小真正超过限制时才进行轮转
            if current_size >= max_log_size_bytes:
                with self._file_lock:
                    # 关闭当前文件
                    current_log_file.close()
                    current_log_file = None
                    self._rotate_logs()
            
            # 标记消息已处理
            for _ in range(len(messages_to_write)):
                self.queue.task_done()
            
            return current_log_file
        except Exception as e:
            print(f"Error in log flush: {e}", file=sys.stderr)
            # 清空消息列表，避免因一条消息的错误导致整个队列阻塞
            for _ in range(len(messages_to_write)):
                try:
                    self.queue.task_done()
                except:
                    pass
            
            # 关闭并重新打开文件
            if current_log_file:
                try:
                    current_log_file.close()
                except:
                    pass
                current_log_file = None
            
            return None

    def _writer_loop(self):
        """日志写入线程的主循环"""
        _import_config()
        
        # 缓存配置，提高性能
        flush_interval = _get_log_flush_interval()
        buffer_size = _get_log_buffer_size()

        log_file = None
        messages = []

        try:
            # 使用无限循环，由内部break控制退出，更清晰表达意图
            while True:
                try:
                    # 阻塞获取第一条消息，带有超时
                    message = self.queue.get(timeout=flush_interval)

                    # 检查是否是终止消息
                    if message is _SHUTDOWN_SENTINEL:
                        self.queue.task_done()  # 标记终止消息已处理
                        break  # 退出主循环，准备处理剩余消息并关闭
                    
                    messages.append(message)
                    
                    # 非阻塞地获取队列中剩余的消息，直到达到缓冲区大小
                    while len(messages) < buffer_size:
                        try:
                            message = self.queue.get_nowait()
                            # 检查是否是终止消息
                            if message is _SHUTDOWN_SENTINEL:
                                self.queue.task_done()  # 标记终止消息已处理
                                break  # 退出内循环
                            messages.append(message)
                        except queue.Empty:
                            break
                    
                    # 如果发现了终止消息，退出主循环
                    if message is _SHUTDOWN_SENTINEL:
                        break
                except queue.Empty:
                    # 超时，如果有消息则刷新
                    pass
                
                # 如果有消息，则刷新日志
                if messages:
                    log_file = self._flush_batch(messages, log_file)
                    messages = []
            
            # 线程结束前处理队列中剩余的所有消息
            try:
                # 处理剩余的所有消息
                remaining_messages = []
                while True:
                    try:
                        message = self.queue.get_nowait()
                        if message is not _SHUTDOWN_SENTINEL:  # 忽略终止消息
                            remaining_messages.append(message)
                        self.queue.task_done()
                    except queue.Empty:
                        break
                
                # 如果有剩余消息，确保它们被写入
                if remaining_messages:
                    log_file = self._flush_batch(remaining_messages, log_file)
            except Exception as e:
                print(f"Error processing remaining logs during shutdown: {e}", file=sys.stderr)
        
        finally:
            # 线程结束前关闭文件
            if log_file and not log_file.closed:
                try:
                    log_file.close()
                except:
                    pass


# --- 全局日志写入器实例 ---
_writer = _LogWriter()

# --- 公共API函数 ---

def _get_current_log_level():
    """获取当前日志级别"""
    _import_config()
    try:
        level = _get_log_level().upper()
        return LOG_LEVELS.get(level, LOG_LEVELS['INFO'])
    except Exception:
        return LOG_LEVELS['INFO']

def set_log_level(level):
    """设置日志级别（向后兼容）"""
    # 这个函数保留为空，因为实际的日志级别是从配置中获取的
    pass

def log(message, level=None):
    """记录日志消息（向后兼容）"""
    # 获取当前上下文的用户ID
    user_id = _user_context.get(None)
    
    # 获取当前时间
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # 确定日志级别
    if level is None:
        level = 'INFO'
    elif level not in LOG_LEVELS:
        level = 'INFO'
    
    # 格式化日志消息
    formatted_message = f"{timestamp} [{level}]"
    if user_id:
        formatted_message += f" [User: {user_id}]"
    formatted_message += f": {message}"
    
    # 检查日志级别
    if LOG_LEVELS.get(level, 99) >= _get_current_log_level():
        # 打印到控制台
        print(formatted_message, file=sys.stderr if level in ['ERROR', 'CRITICAL'] else sys.stdout)
        
        # 提交到日志写入器
        _writer.submit(formatted_message)


class Logger:
    """提供更现代化的日志接口"""
    
    def debug(self, message):
        log(message, 'DEBUG')
    
    def info(self, message):
        log(message, 'INFO')
    
    def warning(self, message):
        log(message, 'WARNING')
    
    def error(self, message):
        log(message, 'ERROR')
    
    def critical(self, message):
        log(message, 'CRITICAL')
    
    def __call__(self, message, level=None):
        """允许直接调用实例"""
        log(message, level)
    
    def set_user(self, user_id):
        """设置当前用户上下文"""
        class UserContext:
            def __init__(self, user_id):
                self.user_id = user_id
                self.token = None
            
            def __enter__(self):
                self.token = _user_context.set(self.user_id)
                return self
            
            def __exit__(self, exc_type, exc_val, exc_tb):
                _user_context.reset(self.token)
        
        return UserContext(user_id)
    
    def shutdown(self):
        """关闭日志系统"""
        self.info("日志系统正在关闭...")
        _writer.stop()
        print("日志系统已关闭", file=sys.stdout)


# 创建全局logger实例
logger = Logger()

# 注册退出处理器
import atexit
atexit.register(logger.shutdown)

# 向后兼容的导出
__all__ = ['log', 'set_log_level', 'LOG_LEVELS', 'logger']

# 为了完全向后兼容，添加旧版API的别名
debug = logger.debug
info = logger.info
warning = logger.warning
error = logger.error
critical = logger.critical
shutdown = logger.shutdown