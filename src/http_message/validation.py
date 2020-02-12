import re
from typing import List, Tuple, Union, Dict, Optional
from dataclasses import dataclass
import logging
from logging import CRITICAL, ERROR, WARNING, INFO, NOTSET

from src.http_message.HttpHeaders import generate_headers, HeaderConstraints


# TODO combine Requestproblem and HeaderProblem

@dataclass
class RequestProblem:
    BAD_REQUESTLINE = 1

    code: int = BAD_REQUESTLINE
    reason: str = ''
    severity: int = ERROR  # use pythons logging levels [CRITICAL, ERROR, WARNING, INFO, NOTSET]


@dataclass
class HeaderProblem:
    INVALID_VALUE = 2
    CONFLICTING_HEADERS = 3
    DUPLICATE_HEADERS = 4  # just a warning, values will be merged if possible for that field
    INVALID_CHARACTERS = 5
    MALFORMED_HEADER = 6
    NONSTANDARD_HEADER = 7
    ATYPICAL_CAPITALIZATION = 8

    code: int
    headers: Union[str, Tuple[str, str]]
    reason: str
    severity: int = ERROR  # use pythons logging levels [CRITICAL, ERROR, WARNING, INFO, NOTSET]


def evaluate_headers(is_request: bool, headers: List[Tuple[str, str]]) -> Dict[str, List[HeaderProblem]]:
    """Standardize the given headers and evaluate, if there are any deviations from the RFC 7234 spec.
	All deviations are collected in a dictionary, where the key is the header name and
	 the value is an error code and an explanation of the problem."""
    # TODO's
    # - extra headers
    # invalid bytes (null bytes, etc.)
    # TODO handle non-standard (and not common) headers
    # Set-Cookie header may appear multiple times w/o being aggregated to a single entry
    wellknown_hdrs = generate_headers(for_request=is_request)
    problems: Dict[str, List[HeaderProblem]] = {}
    # hdr_pattern = re.compile(r"(?P<name>[\w\-]+):[ \t]?(?P<value>.+)")
    tchar = r"!#$%&'*+-.^_`|~\w"  # valid value char according to RFC7230
    extrachars = r"/=,;:()"
    value_pattern = re.compile(fr"^[\t ]?([ {tchar}{extrachars}]+?)[\t ]*$")
    uri_pattern = re.compile(fr"\w+:(\/?\/?)[^\s]+")

    # duplicate headers
    hdr_frequency = _check_duplicate_headers(headers)
    for hdr_name, hdr_count in [(hdr, hdr_count) for hdr, hdr_count in hdr_frequency.items() if hdr_count > 1]:
        problems[hdr_name] = [HeaderProblem(HeaderProblem.DUPLICATE_HEADERS, hdr_name,
                                            f"Header '{hdr_name}' found {hdr_count} times!")]

    for hdr_name, value in headers:
        hdr_problems = []
        try:
            hdr_contraints = wellknown_hdrs[hdr_name]
            if hdr_contraints is not None:
                if isinstance(hdr_contraints, HeaderConstraints):
                    is_valid, reason = hdr_contraints.is_valid(value)
                    if not is_valid:
                        hdr_problems.append(HeaderProblem(HeaderProblem.INVALID_VALUE, hdr_name, reason))
                elif isinstance(hdr_contraints, list):  # list of possible values
                    if value not in hdr_contraints:
                        hdr_problems.append(HeaderProblem(HeaderProblem.INVALID_VALUE, hdr_name,
                                                          f"'{value}' is not one of {', '.join(hdr_contraints)}"))
                elif callable(hdr_contraints):  # predicate function to validate header
                    is_valid, reason = hdr_contraints(value)
                    if not is_valid:
                        hdr_problems.append(HeaderProblem(HeaderProblem.INVALID_VALUE, hdr_name, reason))
                else:
                    raise NotImplementedError
            m = value_pattern.match(value)
            if m is None:
                uri_match = uri_pattern.match(value)  # TODO allow URI pattern only for specific headers (e.g. Referer,
                if uri_match is None:
                    hdr_problems.append(HeaderProblem(HeaderProblem.MALFORMED_HEADER, hdr_name,
                                                      f"'{value}' is a malformed value for header'{hdr_name}'"))
            if '\r\n' in value:
                hdr_problems.append(HeaderProblem(HeaderProblem.INVALID_CHARACTERS, hdr_name,
                                                  f"'\\r\\n' are not allowed"))
        except KeyError as exc:  # header is not well-known
            if hdr_name.strip() in wellknown_hdrs:  # header had 'just' malformed whitespaces
                reason = f"Header name '{hdr_name}' must not contain leading or trailing whitespaces"
                hdr_problems.append(HeaderProblem(HeaderProblem.MALFORMED_HEADER, hdr_name, reason))
                hdr_name = hdr_name.strip()
            else:
                standard_cap = _check_header_capitalization(hdr_name, list(wellknown_hdrs.keys()))
                if standard_cap is not None:
                    reason = f"Header '{hdr_name}' has an atypical capitalization; correct would be '{standard_cap}'"
                    hdr_problems.append(
                        HeaderProblem(HeaderProblem.ATYPICAL_CAPITALIZATION, hdr_name, reason, WARNING))
                    hdr_name = standard_cap
                else:
                    # TODO temporary workaround for unknown headers
                    hdr_problems.append(HeaderProblem(HeaderProblem.NONSTANDARD_HEADER, hdr_name, value, INFO))
                    hdr_name = "UNKNOWN_HEADER"

        if len(hdr_problems) > 0:
            problems[hdr_name] = hdr_problems

    conflicts = _check_conflicting_headers(headers)
    for hdr1, hdr2 in conflicts:
        problems[hdr1] = [HeaderProblem(HeaderProblem.CONFLICTING_HEADERS, (hdr1, hdr2),
                                        f"'{hdr1}' and '{hdr2}' must not be set together")]
    return problems


def _check_header_capitalization(hdr_name: str, known_headers: List[str]) -> Optional[str]:
    """Check if the case of the header is off and if so, what the 'standard' case should be"""
    hdr_as_lower_case = hdr_name.lower()
    correct_name = next((h for h in known_headers if h.lower() == hdr_as_lower_case), None)
    return correct_name


def _check_duplicate_headers(headers: List[Tuple[str, str]]) -> Dict[str, int]:
    """Count number occurrences of every header field. Ideally every field should occur only once.
	The names of HTTP headers and thus the comparison is case-insensitive."""
    hdr_counts = {}
    case_mapping = {}

    logging.info(f"checking for duplicates in {headers}")

    for hdr, _ in headers:
        hdr_lower = hdr.lower()
        hdr_counts[hdr_lower] = hdr_counts.get(hdr_lower, 0) + 1
        # keep track of original formatting to restore original case
        if hdr_lower not in case_mapping.keys():
            case_mapping[hdr_lower] = hdr

    # TODO check if values are identical and thus duplicate header can be dropped

    # restore original case of headers, so access
    return {case_mapping[k]: v for k, v in hdr_counts.items()}


def _check_conflicting_headers(headers: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Check for headers that may no not appear in conjunction"""
    hdrs = dict(
        headers)  # temporary workaround; converting to dict may lead to unwanted behavior for duplicate headers
    antagonists = [
        ('Transfer-Encoding', 'Content-Length')
    ]

    conflicts = [(h1, h2) for h1, h2 in antagonists if h1 in hdrs and h2 in hdrs]
    return conflicts
