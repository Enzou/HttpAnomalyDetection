from typing import List, Optional, Any
from src.http_message.http_request import HttpRequest
from src.http_message.http_response import HttpResponse
from collections import OrderedDict
from typing import Dict
from utils import flatten_list


class HttpExchange:
	"""
	An HTTP Exchange consists of a HTTP request-response pair, i.e. the request and it's response from the server.
	An exchange happens from the point of view of the client, thus is the `src_ip` the IP address of the client.
	and `dst_ip` the IP address of the responding service. The `timestamp` is the start of the exchange, which equals
	the timestamp of the request.
	"""
	
	def __init__(self, src_ip: str, dst_ip: str, timestamp: float, raw_request: bytes,
	             source: str = '', note: str = '', raw_response: Optional[bytes] = None, rtt: float = -1):
		self.src_ip = src_ip
		self.dst_ip = dst_ip
		self.timestamp = timestamp
		self.rtt = rtt
		self.tags: List[str] = []
		self.source = source
		self.note: str = note
		self._response = None
		if raw_response is not None:
			self._response: Optional[HttpResponse] = HttpResponse(raw_response)
			if rtt < 0:
				self._calculate_rtt()
		
		r = HttpRequest(raw_request, self.src_ip, self.dst_ip)
		self._request = r
		self._request._timestamp = self.timestamp  # exchange starts with request  # TODO properly set timestamp
		
		self.method = r.method
		self.path = r.path
		self.version = r.http_version
		hdrs = dict(r.headers)
		self.num_headers = len(hdrs)
	
	def __eq__(self, other):
		return self.src_ip == other.src_ip and \
		       self.dst_ip == other.dst_ip and \
		       self.path == other.path and \
		       self.method == other.method and \
		       self.num_headers == other.num_headers and \
		       self.source == other.source and \
		       self.request_body == other.request_body
	
	def __hash__(self):
		return hash((self.src_ip, self.dst_ip, self.path, self.method,
		             hash(self._request), hash(self._response)))
	
	def set_content(self, content, for_request=True):
		if for_request:
			self._request.set_body(content)
		else:
			if self._response is None:
				self._response = HttpResponse(b'')
			self._response.set_body(content)
	
	def get_request(self):
		return self._request
	
	def get_response(self):
		return self._response
	
	def set_response(self, raw_headers, raw_body, tmp_scapy_response=None):
		if isinstance(raw_headers, bytes):
			self._response = HttpResponse(raw_headers)
			self._response.set_body(raw_body)
			self._response._timestamp = tmp_scapy_response.time  # TODO properly set timestamp
			self._calculate_rtt()
		else:
			raise ValueError('Response is of types bytes')
	
	def get(self, field: str, default: Optional[Any] = None):
		"""
		Generic getter for attributes on the HTTP exchange, HTTP request or HTTP response.
		If same attribute exists on multiple objects, the first one is used.
		The order of objects is [exchange > request > response]
		:param field: the attribute to look for on the exchange and its children
		:param default: value to use if attribute could not be found
		:return: the value of the attribute or the default value if no such attribute was found.
		"""
		# priority of objects on which to look for the field
		for obj in [self, self._request, self._response]:
			if obj:
				attr = getattr(obj, field, None)
				if attr:
					return attr
		return default
	
	def _calculate_rtt(self):
		self.rtt = (self._response.get_time() - self._request.get_time()) * 1000  # use milliseconds
	
	def set_note(self, note):
		self.note = note if note is not None else ''
	
	# def to_series(self, detector=None) -> Dict[str, str]:
	# 	mapping = OrderedDict()
	# 	request = self.get_request()
	# 	response = self.get_response()
	#
	# 	mapping['source_ip'] = self.src_ip
	# 	mapping['destination_ip'] = self.dst_ip
	# 	mapping['timestamp'] = self.timestamp
	# 	mapping['method'] = self.method
	# 	mapping['path'] = self.path
	# 	mapping['#_headers'] = self.num_headers
	# 	# mapping['host'] = request.get_header('Host')
	# 	mapping['connection'] = request.get_header('Connection')
	# 	mapping['transfer_encoding'] = request.get_header('Transfer-Encoding')
	# 	mapping['content_length'] = request.get_header('Content-Length')
	# 	mapping['content-type'] = request.get_header('Content-Type')
	# 	mapping['user_agent'] = request.get_header('User-Agent')
	# 	# mapping['referer'] = request.get_header('Referer')
	# 	mapping['status_code'] = response.status_code if response else ''
	# 	# mapping['status_reason'] = response.reason if response else ''
	# 	mapping['rtt'] = self.rtt
	# 	mapping['source'] = self.source
	# 	mapping['note'] = self.note
	# 	mapping['tags'] = ''.join(self.tags)
	# 	mapping['problems'] = request.get_problems()
	# 	mapping['request_headers'] = flatten_list(request.headers)
	# 	mapping['raw_request'] = request.get_body(as_string=True)
	# 	mapping['response_headers'] = flatten_list(response.headers) if response else ''
	# 	mapping['__ref'] = self
	#
	# 	# if detector:
	# 	#     result = detector.detect(self)
	# 	#     # TODO use all detectors
	# 	#     http_smuggling_score, reason = result['http_request_smuggling']
	# 	#     mapping['score'] = http_smuggling_score
	# 	#     mapping['verdict_reasons'] = flatten_list(reason)
	# 	return mapping
	
	def to_csv_entry(self, label: Optional[str] = None) -> Dict[str, str]:
		mapping = OrderedDict()
		mapping['source_ip'] = self.src_ip
		mapping['destination_ip'] = self.dst_ip
		mapping['request_ts'] = self.get_request().get_time()
		mapping['response_ts'] = self.get_response().get_time()
		mapping['request_b64'] = self.get_request().encode_base64()
		mapping['response_b64'] = self.get_request().encode_base64()
		mapping['source'] = self.source
		mapping['note'] = self.note
		mapping['tags'] = ';'.join(self.tags)
		mapping['label'] = '' if label is None else label
		return mapping
