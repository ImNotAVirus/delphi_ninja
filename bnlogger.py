from binaryninja import log, LogLevel
from datetime import datetime
from enum import IntEnum


class BNLogger(object):
    @staticmethod
    def init_console(min_level=LogLevel.InfoLog):
        log.log_to_stdout(LogLevel.InfoLog)


    @staticmethod
    def log(msg: str, level=LogLevel.InfoLog):
        now = datetime.now()
        real_msg = f'<DelphiNinja> [{now.strftime("%H:%M:%S.%f")[:-3]}] [{level.name}] {msg}'

        if level == LogLevel.DebugLog:
            log.log_debug(real_msg)
        elif level == LogLevel.InfoLog:
            log.log_info(real_msg)
        elif level == LogLevel.WarningLog:
            log.log_warn(real_msg)
        elif level == LogLevel.ErrorLog:
            log.log_error(real_msg)
        elif level == LogLevel.AlertLog:
            log.log_alert(real_msg)
        else:
            raise Exception('Invalid LogLevel')
