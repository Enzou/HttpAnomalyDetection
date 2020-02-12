from src.http_message.http_request import HttpRequest


class HttpPreprocessor:
    def __init__(self, req_text):
        # method = req_text[:req_text.index(' ')]
        a = HttpRequest(req_text)


def preprocess_request(req_text):
    pkt = HttpRequest(req_text)
    return pkt

# from Requests.utils
# def get_encodings_from_content(content):
#     """Returns encodings from given content string.
#     :param content: bytestring to extract encodings from.
#     """
#     warnings.warn((
#         'In requests 3.0, get_encodings_from_content will be removed. For '
#         'more information, please see the discussion on issue #2266. (This'
#         ' warning should only appear once.)'),
#         DeprecationWarning)
#
#     charset_re = re.compile(r'<meta.*?charset=["\']*(.+?)["\'>]', flags=re.I)
#     pragma_re = re.compile(r'<meta.*?content=["\']*;?charset=(.+?)["\'>]', flags=re.I)
#     xml_re = re.compile(r'^<\?xml.*?encoding=["\']*(.+?)["\'>]')
#
#     return (charset_re.findall(content) +
#             pragma_re.findall(content) +
#             xml_re.findall(content))
#
