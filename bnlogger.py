from binaryninja import log, LogLevel
from datetime import datetime
from enum import IntEnum


class BNLogger(object):
    @staticmethod
    def init_console(min_level=LogLevel.InfoLog):
        log.log_to_stdout(LogLevel.InfoLog)


    @staticmethod
    def log(msg: str, level=LogLevel.InfoLog):
        # FIXME: Duplicate logs when level > LogLevel.InfoLog (stdout + stderr)
        now = datetime.now()
        real_msg = f'<DelphiNinja> [{now.strftime("%H:%M:%S.%f")[:-3]}] [{level.name}] {msg}'
        log.log(level, real_msg)
