import logging
import sys
import re


class PasswordFilter(logging.Filter):
    def __init__(self, pattern):
        self.pattern = pattern

    def filter(self, record):
        # Use a regular expression to replace passwords in log messages
        record.msg = re.sub(self.pattern, r"\1********", record.msg)
        return True


# log configuration
level = logging.DEBUG
formatter = "%(asctime)s %(levelname)8s %(message)s"
file = "test.log"

# create custom loggers
_file_logger: logging.Logger = logging.getLogger("file_logger")
_console_logger: logging.Logger = logging.getLogger("console_logger")
_file_logger.setLevel(level)
_console_logger.setLevel(level)

# create handlers
c_handler = logging.StreamHandler(sys.stdout)
f_handler = logging.FileHandler(file)
c_handler.setLevel(level)
f_handler.setLevel(level)

# create formatters and add it to handlers
c_format = logging.Formatter(formatter)
f_format = logging.Formatter(formatter)
c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)

# add filter to the handlers
password_pattern = re.compile(r"(pass.*?[=: ]\s*)\s*\S+", re.IGNORECASE)
c_handler.addFilter(PasswordFilter(password_pattern))
f_handler.addFilter(PasswordFilter(password_pattern))

# add handlers to the loggers
_console_logger.addHandler(c_handler)
_file_logger.addHandler(f_handler)


def critical(msg, *args, **kwargs):
    _console_logger.critical(f"{msg}\n", *args, **kwargs)
    _file_logger.critical(msg, *args, **kwargs)


def fatal(msg, *args, **kwargs):
    _console_logger.fatal(f"{msg}\n", *args, **kwargs)
    _file_logger.fatal(msg, *args, **kwargs)


def error(msg, *args, **kwargs):
    _console_logger.error(f"{msg}\n", *args, **kwargs)
    _file_logger.error(msg, *args, **kwargs)


def warn(msg, *args, **kwargs):
    _console_logger.warn(f"{msg}\n", *args, **kwargs)
    _file_logger.warn(msg, *args, **kwargs)


def info(msg, *args, **kwargs):
    _console_logger.info(f"{msg}\n", *args, **kwargs)
    _file_logger.info(msg, *args, **kwargs)


def debug(msg, *args, **kwargs):
    _console_logger.debug(f"{msg}\n", *args, **kwargs)
    _file_logger.debug(msg, *args, **kwargs)
