from typing import Optional, Tuple, List
from enum import IntFlag
import re


# source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

# TODO handle regulation of multiple header entries with same header-name -> merge to list (if header entry allows multiple values)
# TODO check for missing headers
# TODO check if categorization of general/request only/ response only headers is correct

# ----------------- helper functions ------------------------

def _check_authenticate(header_value: str) -> Tuple[bool, Optional[str]]:
	# <type> realm=<realm>
	# TODO implement
	return True, ''


def _check_authorization(header_value: str) -> Tuple[bool, Optional[str]]:
	# <type> <credentials>
	# TODO implement
	return True, ''


class HeaderProperty(IntFlag):
	NUMERIC = 1
	UNIQUE = 2  # no duplicate headers allowed


class HeaderConstraints:
	def __init__(self, allowed_values: List = None, flags: int = 0, predicate=None):
		self.allowed_values = allowed_values
		self._flags = flags
		self.predicate = predicate

	def _is_allowed_value(self, value):
		if self.allowed_values is None:		# no restrictions given
			return True

		for v in self.allowed_values:
			if isinstance(v, re.Pattern):
				m = v.fullmatch(value)
				if m is not None:
					return True
			elif v == value:
				return True
		return False

	def is_valid(self, header_value: str) -> Tuple[bool, Optional[str]]:
		is_valid = True
		reason = ''
		if self._flags & HeaderProperty.NUMERIC:
			if not header_value.isdigit():
				is_valid, reason = False, 'Value is not a valid number'
		if self._flags & HeaderProperty.UNIQUE:
			pass  # TODO implement unique header constraint

		if is_valid and self.allowed_values is not None:
			is_valid = self._is_allowed_value(header_value)
			if not is_valid:
				allowed_vals_str = ', '.join(self.allowed_values)
				reason = f"'{header_value}' is not one of [{allowed_vals_str}]"

		return is_valid, reason


# TODO add mechanics to check for problems between headers

# Pattern: <Header name>: <Restrictions>

GENERAL_HEADERS = {  # most common: Date, Cache-Control or Connection
	"Cache-Control": HeaderConstraints(allowed_values=[re.compile(r'max-age=\d+'), 'no-cache', 'no-store', 'no-transform']),
	"Connection": ['keep-alive', 'close'],
	"Date": None,
	"Keep-Alive": ['timeout=<seconds>', 'max=<no requests>'],
	# Connection header needs to be set to "keep-alive" for this header to have any meaning
	"Pragma": ['no-cache'],
	"Transfer-Encoding": HeaderConstraints(allowed_values=['chunked', 'compress', 'deflate', 'gzip', 'identity']),
	"Trailer": None,
	"Upgrade": None,  # https://tools.ietf.org/html/rfc7230#section-6.7
	"Via": None,  # https://tools.ietf.org/html/rfc7230#section-5.7.1
	"Warning": None  # has pattern <code> <text>  https://tools.ietf.org/html/rfc7234#section-5.5
}

COMMON_NON_STANDARD_GENERAL_HEADERS = {
	"X-Request-ID": None,
	"X-Correlation-ID": None
}

#  Entity-header fields define metainformation about the entity-body or,
#  if no body is present, about the resource identified by the request
ENTITY_HEADERS = {
	"Allow": None,
	"Content-Encoding": ["gzip", "compress", "deflate", "identity", "br"],
	"Content-Language": None,
	"Content-Location": None,
	"Content-Length": HeaderConstraints(flags=HeaderProperty.UNIQUE | HeaderProperty.NUMERIC,
										predicate=lambda v: (v.isdigit(), None)),
	# TODO not in conjunction with Transfer-Encoding -> has lower priority
	"Content-MD5": None,  # is obsolete
	"Content-Range": None,
	"Content-Type": None,  # media type of the body
	"Expires": None,
	"Last-Modified": None,
}

REQUEST_HEADERS = {
	"A-IM": None,
	"Accept": None,
	"Accept-Charset": None,
	"Accept-Encoding": None,  # " gzip, compress, deflate, identity, br, *, ;q=(qvlaues weighting)"
	"Accept-Language": None,
	"Accept-Datetime": None,
	"Access-Control-Request-Method": None,
	"Access-Control-Request-Headers": None,
	"Authorization": _check_authorization,
	"Cookie": None,
	"Expect": None,
	"Forwarded": None,
	"From": None,
	"Host": None,
	"HTTP2-Settings": None,
	"If-Match": None,
	"If-Modified-Since": None,
	"If-None-Match": None,
	"If-Range": None,
	"If-Unmodified-Since": None,
	"Max-Forwards": None,
	"Origin": None,
	"Proxy-Authorization": None,
	"Range": None,
	"Referer": None,
	"TE": None,
	"User-Agent": None
}

COMMON_NON_STANDARD_REQUEST_HEADERS = {
	"Upgrade-Insecure-Requests": None,
	"X-Requested-With": None,
	"DNT": None,
	"X-Forwarded-For": None,
	"X-Forwarded-Host": None,
	"X-Forwarded-Proto": None,
	"Front-End-Https": None,
	"X-Http-Method-Override": None,
	"X-ATT-DeviceId": None,
	"X-Wap-Profile": None,
	"Proxy-Connection": None,
	"X-UIDH": None,
	"X-Csrf-Token": None,
	"Save-Data": None
}

RESPONSE_HEADERS = {
	"Access-Control-Allow-Origin": None,
	"Access-Control-Allow-Credentials": None,
	"Access-Control-Expose-Headers": None,
	"Access-Control-Max-Age": None,
	"Access-Control-Allow-Methods": None,
	"Access-Control-Allow-Headers": None,
	"Accept-Patch": None,
	"Accept-Ranges": None,
	"Age": None,
	"Alt-Svc": None,
	"Content-Disposition": None,
	"Delta-Base": None,
	"ETag": None,
	"IM": None,
	"Link": None,
	"Location": None,
	"Permanent": None,
	"P3P": None,
	"Proxy-Authenticate": _check_authenticate,
	"Public-Key-Pins": None,
	"Retry-After": None,
	"Server": None,
	"Set-Cookie": None,
	"Strict-Transport-Security": None,
	"Tk": None,
	"Vary": None,
	"WWW-Authenticate": _check_authenticate,
	"X-Frame-Options": None
}

COMMON_NON_STANDARD_RESPONSE_HEADERS = {
	"Content-Security-Policy": None,
	"X-Content-Security-Policy": None,
	"X-WebKit-CSP": None,
	"Refresh": None,
	"Status": None,
	"Timing-Allow-Origin": None,
	"X-Content-Duration": None,
	"X-Content-Type-Options": None,
	"X-Powered-By": None,
	"X-UA-Compatible": None,
	"X-XSS-Protection": None
}


def generate_headers(for_request=True, include_non_standards=True):
	"""Generate the header fields based on their name"""
	# Order headers
	header_groups = [
		GENERAL_HEADERS,
		ENTITY_HEADERS,
		REQUEST_HEADERS if for_request else RESPONSE_HEADERS,
		COMMON_NON_STANDARD_GENERAL_HEADERS,
		COMMON_NON_STANDARD_REQUEST_HEADERS if for_request else COMMON_NON_STANDARD_RESPONSE_HEADERS
	]
	all_headers = {}
	for headers in header_groups:
		all_headers.update(headers)
	# Generate header fields
	# results = []
	# for h in sorted(all_headers):
	#     results.append(h, None)
	return all_headers
