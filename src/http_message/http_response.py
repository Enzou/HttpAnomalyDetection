import io
from base64 import b64encode
from typing import Optional
from http.client import HTTPResponse

from .http_message import HttpMessage


class _SocketMock:
    def __init__(self, raw, encoding=None, errors=None, newline=None):
        self._raw = raw
        self._encoding = encoding
        self._errors = errors
        self._newline = newline

    def makefile(self, mode):
        buffer = io.BufferedReader(io.BytesIO(self._raw))
        # self._encoding, self._errors, self._newline)
        # text.mode = mode
        return buffer


class HttpResponse(HttpMessage):
    """
    """

    def __init__(self, raw_response: bytes, timestamp: float = 0.,
                 status_code: int = 0, reason: str = ''):
        super().__init__(raw_response)
        self._raw_headers, self._raw_body = raw_response.split(b'\r\n\r\n', 1)
        self._timestamp = timestamp
        self.status_code = status_code
        self.reason = reason

        sock = _SocketMock(self._raw_headers)
        res = HTTPResponse(sock)
        res.begin()
        self.status_code = res.status
        self._reason = res.reason
        self._headers = res.headers._headers

    def get_time(self):
        return self._timestamp

    def get_status_code(self):
        return self.status_code

    @property
    def headers(self):
        return self._headers

    def get_body(self) -> Optional[bytes]:
        return self._raw_body

    def set_body(self, body: bytes) -> None:
        self._raw_body = body

    def encode_base64(self) -> bytes:
        return b64encode(self._raw)
