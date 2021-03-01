import logging
import stackprinter


__module__ = 'trivialsec.helpers.log_manager'

logging.getLogger().setLevel(logging.WARNING)

class VerboseExceptionFormatter(logging.Formatter):
    def formatException(self, exc_info):
        msg = stackprinter.format(exc_info)
        msg_indented = '    ' + '\n    '.join(msg.split('\n')).strip()
        return msg_indented

class LogManager(logging.Logger):
    _format_str = None
    _date_format = None

    def __init__(self, **kwargs):
        if not kwargs.get('name'):
            kwargs['name'] = 'trivialsec'
        super().__init__(**kwargs)

    def configure(self, **kwargs):
        self._format_str = kwargs.get('format_str', '[%(asctime)s] %(process)-4d | %(levelname)-8s | %(filename)s:%(lineno)d | %(message)s')
        self._date_format = kwargs.get('date_format', '%Y-%m-%d %H:%M:%S')
        log_level = kwargs.get('log_level', logging.WARNING)
        self.setLevel(log_level)

    def create_file_logger(self, file_path: str, format_str: str = None, date_format: str = None):
        file_handler = logging.StreamHandler(open(file_path, 'a+'))
        if format_str is None:
            format_str = self._format_str
        if date_format is None:
            date_format = self._date_format
        formatter = logging.Formatter(format_str, date_format)
        file_handler.setFormatter(formatter)
        self.addHandler(file_handler)

    def create_stream_logger(self, pretty: bool = True, format_str: str = None, date_format: str = None):
        stream_handler = logging.StreamHandler()
        if format_str is None:
            format_str = self._format_str
        if date_format is None:
            date_format = self._date_format
        if pretty is True:
            formatter = VerboseExceptionFormatter(format_str, date_format)

        stream_handler.setFormatter(formatter)
        self.addHandler(stream_handler)

logger = LogManager()
