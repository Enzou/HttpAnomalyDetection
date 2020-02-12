from typing import Dict, Optional, List
from collections import OrderedDict
import logging


def setup_logger(name: Optional[str] = 'default', handler: logging.Handler = None) -> None:
    if handler is None:
        handler = logging.StreamHandler()
    fmt = logging.Formatter("{asctime} [{levelname}]: {message}", style='{')
    handler.setFormatter(fmt)
    logger = logging.getLogger(name)
    logger.addHandler(handler)


def flatten_list(lst: List) -> str:
    if lst is None:
        return ''
    lines = []
    for l in lst:
        if isinstance(l, tuple):
            lines.append(f"{l[0]}: {l[1]}")
        else:
            lines.append(l)
    return '\n'.join(lines)


def http_exchange_to_series(self) -> Dict[str, str]:
    mapping = OrderedDict()
    request = self.get_request()
    response = self.get_response()

    mapping['source_ip'] = self.src_ip
    mapping['destination_ip'] = self.dst_ip
    # TODO add ports
    mapping['timestamp'] = self.timestamp
    mapping['method'] = self.method
    mapping['path'] = self.path
    # mapping['#_headers'] = self.num_headers
    # mapping['host'] = request.get_header('Host')
    # mapping['connection'] = request.get_header('Connection')
    # mapping['transfer_encoding'] = request.get_header('Transfer-Encoding')
    # mapping['content_length'] = request.get_header('Content-Length')
    # mapping['content-type'] = request.get_header('Content-Type')
    # mapping['user_agent'] = request.get_header('User-Agent')
    # mapping['referer'] = request.get_header('Referer')
    mapping['rtt'] = self.rtt
    mapping['status_code'] = response.status_code if response else ''
    # mapping['status_reason'] = response.reason if response else ''
    # mapping['source'] = self.source
    # mapping['note'] = self.note
    # mapping['tags'] = ''.join(self.tags)
    mapping['request_problems'] = request.get_problems()
    mapping['request_headers'] = flatten_list(request.headers)
    mapping['request_body'] = request.get_body()
    mapping['request_size'] = request.get_size()
    # mapping['raw_request'] = request.get_body(as_string=True)
    mapping['response_headers'] = flatten_list(response.headers) if response else ''
    mapping['response_size'] = response.get_size() if response else '0'
    # mapping['__ref'] = self
    return mapping
