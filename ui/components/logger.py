import logging


class StreamlitHandler(logging.Handler):
    def __init__(self, placeholder):
        logging.Handler.__init__(self, level=logging.DEBUG)
        self.placeholder = placeholder
        self._msg = ''

    def emit(self, record):
        self._msg = self.format(record)
        self.placeholder.info(self._msg)
