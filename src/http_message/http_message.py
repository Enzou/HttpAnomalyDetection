
class HttpMessage:
    def __init__(self, raw):
        self._raw = raw

    def get_size(self):
        return len(self._raw)
