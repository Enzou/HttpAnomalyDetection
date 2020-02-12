import io
import re
from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
from typing import Union, Optional, List
from base64 import b64encode
import logging

from .http_message import HttpMessage
from src.http_message.validation import evaluate_headers, HeaderProblem, RequestProblem

HTTP_METHODS = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE']


class _HttpRequestHandler(BaseHTTPRequestHandler):
	def __init__(self, raw_request: Union[bytes, str]):
		# super().__init__(request, client_address, server)
		if isinstance(raw_request, bytes):
			self.rfile = io.BytesIO(raw_request)
		else:
			self.rfile = io.BytesIO(raw_request.encode('iso-8859-1'))
		self.headers = []
		self.raw_requestline = self.rfile.readline()
		self.error_code = self.error_message = None
		if self.parse_request():
			self._fix_headers()
		else:
			if self.error_code == HTTPStatus.BAD_REQUEST:
				self._fix_requestline()
				if self.parse_request():
					self._fix_headers()
				else:
					print(f"Error while parsing {self.error_code}: {self.error_message}")

	def _fix_requestline(self):
		try:
			# fix request line and try parsing again
			requestline = str(self.raw_requestline, 'iso-8859-1')
			requestline = requestline.rstrip('\r\n')
			self.requestline = requestline
			words = requestline.split()
			if len(words) > 3:
				fixed_requestline = f"{words[0]} {'%20'.join(words[1:-1])} {words[-1]}"
				self.raw_requestline = fixed_requestline.encode('iso-8859-1')
		except:
			print(f"Error while parsing {self.error_code}: {self.error_message}")
	
	def send_error(self, code, message):
		self.error_code = code
		self.error_message = message
	
	def _fix_headers(self):
		"""Fix bugged wrongly parsed headers"""
		logger = logging.getLogger("")
		fixed_headers = []
		# BaseHTTPRequestHandler has trouble parsing a header with a leading space (header is part of previous entry)
		for header_name, value in self.headers._headers:
			if '\r\n' in value:
				# TODO move this correction to 'fix_problem' in HttpRequest, so this case
				prev_value, new_header = [v for v in value.split('\r\n')]
				fixed_headers.append((header_name, prev_value))
				new_name, new_value = [h for h in new_header.split(':')]
				fixed_headers.append((new_name, new_value))
				logger.info(
					fr"Had to fix header entries, because \r\n was not correctly handled (malformed_value: {value}, new header: {new_header})")
			else:
				fixed_headers.append((header_name, value))
		
		# BaseHTTPRequestHandler seems to interpret headers as payload once an error occurs
		# -> special handling required to retrieve them nontheless
		if len(self.headers._payload) > 0:
			# BaseHTTPRequestHandle has trouble parsing a header with a space between field name and colon
			tmp_hdrs = re.compile(r"(?<=\w)(?:\r\n)+(?=\w|$)").split(self.headers._payload)
			other_fields = [tuple(h.split(": ")) for h in tmp_hdrs if len(h) > 0]
			diff = set(other_fields).difference(set(fixed_headers))
			if len(diff) > 0:
				if len(diff) == 2:
					fixed_headers += diff
				# split between header and value occurred => previous header has no actual value
				elif len(diff) == 1 and len(fixed_headers[-1][
												1]) == 0:  # TODO find reason for split and add it to value to keep original payload
					hdr_name, _ = fixed_headers.pop()
					hdr_val = '\n' + list(diff)[0][0]
					fixed_headers.append((hdr_name, hdr_val))
				logger.info(f"Augmented list of parsed headers, because {len(diff)} entries were missing: {diff}")
		
		self.headers._headers = fixed_headers


class HttpRequest(HttpMessage):
	def __init__(self, raw_request: Union[bytes, str], src_ip: str, dst_ip: str):
		# super().__init__(raw_request, client_address, server)
		super().__init__(raw_request)
		self._problems = {}
		self._req = _HttpRequestHandler(raw_request)
		self._headers = self._req.headers._headers
		self.path = self._req.path
		self._timestamp = 0.

		if self._req.error_code is not None:
			self._problems['request'] = [RequestProblem(reason=self._req.error_message)]
		
		try:
			self.body = raw_request[raw_request.index(b"\r\n\r\n") + 4:].rstrip()
		except ValueError:
			self.body = b''
		
		self._problems.update(evaluate_headers(True, self._headers))
		if len(self._problems):
			self._fix_problems(self._problems)
		
		self._cookies = self._extract_cookies()
	
	def _fix_problems(self, problems):
		headers = dict(self._headers)
		for hdr_name, problems in self._problems.items():
			for p in problems:
				if p.code == HeaderProblem.MALFORMED_HEADER or \
						p.code == HeaderProblem.ATYPICAL_CAPITALIZATION:
					hdr_val = headers[p.headers]
					del headers[p.headers]
					# headers[p.headers.strip()] = hdr_val
					headers[hdr_name] = hdr_val
		self._headers = list(zip(headers.keys(), headers.values()))
	
	def _extract_cookies(self) -> List:
		cookies = []
		raw_cookies = self._req.headers.get("cookie")
		
		if raw_cookies:
			for raw_cookie in raw_cookies.split(";"):
				cookie_parts = raw_cookie.split("=")
				cookie_name = cookie_parts[0].strip()
				cookie_value = "".join(cookie_parts[1:]).strip()
				cookies.append((cookie_name, cookie_value))
		return cookies
	
	@staticmethod
	def _get_headers(req):
		except_fields = ['Method', 'Http_Version', 'Path', 'Unknown_Headers']
		headers = {k: v.decode('utf-8') for k, v in req.fields.items()
				   if k not in except_fields}
		unknown_headers = {k: v.decode('utf-8') for k, v in req.fields.get('Unknown_Headers', {}).items()}
		return headers, unknown_headers
	
	def __hash__(self):
		return hash((self.method, self.path, self.headers))
	
	def get_time(self):
		return self._timestamp
	
	@property
	def method(self):  # use standard vocabulary for parts of the request
		return self._req.command
	
	@property
	def http_version(self):
		return self._req.request_version
	
	@property
	def headers(self):
		return self._headers
	
	def get_header(self, header_name: str) -> str:
		"""Retrieve the value of the header with the given name"""
		return next((hdr_value for hdr_name, hdr_value in self._headers if hdr_name == header_name), None)
	
	def get_body(self, as_string: bool = False) -> Optional[Union[bytes, str]]:
		if as_string:
			try:
				return self.body.decode('utf-8')
			except UnicodeDecodeError as exc:
				print(f"Warning, couldn't decode body: '{str(exc)}'")
				return ''
		else:
			return self.body
	
	def set_body(self, body: bytes) -> None:
		self.body = body
	
	def get_problems(self, problem_type: Optional[HeaderProblem] = None):
		if problem_type is None:
			return self._problems.values()
		return [p for hdr_problems in self._problems.values()
				for p in hdr_problems if p.code == problem_type]

	@property
	def user_agent(self):
		return self.get_header('User-Agent')
	
	@property
	def referer(self):
		return self.get_header('Referer')
	
	@property
	def cookies(self):
		return self.get_header('Cookie')
	
	def encode_base64(self) -> bytes:
		return b64encode(self._raw)
