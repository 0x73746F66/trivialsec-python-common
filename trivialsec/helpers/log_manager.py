import logging
import colorlog


class LogManager:
    log = None

    def __init__(self, **kwargs):
        logging.getLogger().setLevel(logging.WARNING)
        self.log = logging.getLogger('trivialsec')
        self.configure(**kwargs)

    def debug(self, *args, **kwargs):
        self.log.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self.log.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self.log.warning(*args, **kwargs)

    def warn(self, *args, **kwargs):
        self.log.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self.log.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self.log.critical(*args, **kwargs)

    def exception(self, *args, **kwargs):
        self.log.exception(*args, **kwargs)

    def configure(self, **kwargs):
        self.format_str = kwargs.get('format_str', '[%(asctime)s] %(process)-4d | %(levelname)-8s | %(filename)s:%(lineno)d | %(message)s')
        self.date_format = kwargs.get('date_format', '%Y-%m-%d %H:%M:%S')
        self.log_level = kwargs.get('log_level', logging.WARNING)
        self.log.setLevel(self.log_level)

    def create_file_logger(self, file_path: str, format_str: str = None, date_format: str = None):
        file_handler = logging.StreamHandler(open(file_path, 'a+'))
        if format_str is None:
            format_str = self.format_str
        if date_format is None:
            date_format = self.date_format
        formatter = logging.Formatter(format_str, date_format)
        file_handler.setFormatter(formatter)
        self.log.addHandler(file_handler)

    def create_stream_logger(self, colourise: bool = False, format_str: str = None, date_format: str = None):
        stream_handler = logging.StreamHandler()
        if format_str is None:
            format_str = self.format_str
        if date_format is None:
            date_format = self.date_format
        if colourise is not True:
            formatter = logging.Formatter(format_str, date_format)
        else:
            cformat = '%(log_color)s' + format_str
            colors = {
                'DEBUG': 'reset',
                'INFO': 'bold_blue',
                'WARNING': 'bold_yellow',
                'ERROR': 'bold_red',
                'CRITICAL': 'bold_red'
            }
            formatter = colorlog.ColoredFormatter(cformat, date_format, log_colors=colors)

        stream_handler.setFormatter(formatter)
        self.log.addHandler(stream_handler)

logger = LogManager()
