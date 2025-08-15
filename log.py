import sys

# 日志级别定义
LOG_LEVELS = {
    'debug': 0,
    'info': 1,
    'warning': 2,
    'error': 3,
    'critical': 4
}

# 当前日志级别
current_level = LOG_LEVELS['debug']

def set_log_level(level):
    """设置日志级别"""
    global current_level
    if level.lower() in LOG_LEVELS:
        current_level = LOG_LEVELS[level.lower()]
    else:
        print(f"Warning: Unknown log level '{level}'")

def _log(level, message):
    """
    简单的日志函数，内部使用，不直接导出为模块级函数
    """
    level = level.lower()
    if level not in LOG_LEVELS:
        print(f"Warning: Unknown log level '{level}'")
        return
    if LOG_LEVELS[level] < current_level:
        return
    entry = f"[{level.upper()}] {message}"
    if level in ('error', 'critical'):
        print(entry, file=sys.stderr)
    else:
        print(entry)

class Logger:
    """支持 log('info', 'msg') 和 log.info('msg')"""
    def __call__(self, level, message):
        _log(level, message)

    def debug(self, message):
        _log('debug', message)
    def info(self, message):
        _log('info', message)
    def warning(self, message):
        _log('warning', message)
    def error(self, message):
        _log('error', message)
    def critical(self, message):
        _log('critical', message)

# 导出一个 Logger 实例，兼容 import log; log(...) 和 from log import log; log.info(...)
log = Logger()