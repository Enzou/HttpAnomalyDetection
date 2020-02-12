from typing import Optional, Tuple, List

from scapy.all import *
from src.http_message.http_exchange import HttpExchange


# TODO  timestamp: int
#       Content_Length: int
# TODO  tests for DoS attacks if sessions are not ended (input from Martin)

CRLF = b'\r\n'


class PcapReader:
    """
    Parse frames within a given PCAP file and extract HTTP requests and corresponding responses.
    """
    def __init__(self):
        load_layer("http")

    def load_samples(self, file_path):
        packets = rdpcap(str(file_path))
        # tcp_pakets = packets[TCP]
        # bind_layers(TCP, HttpRequest, dport=80)
        exchanges = []  # combinations of request/response

        http_traffic = packets[HTTP]
        is_request = False
        remaining_len = 0
        for title, session in http_traffic.sessions(self._full_duplex).items():
            waiting_for_content = False
            exchange, res = None, None
            for raw_pkt in session:
                http = raw_pkt.getlayer('HTTP')
                if raw_pkt.haslayer('HTTPRequest'):
                    is_request = True
                    exchange, waiting_for_content = self._process_request(raw_pkt)
                    exchanges.append(exchange)
                elif raw_pkt.haslayer('HTTPResponse'):
                    is_request = False
                    res = raw_pkt.getlayer('HTTPResponse')
                    res.is_chunked = res.Transfer_Encoding is not None and b'chunked' in res.Transfer_Encoding
                    if res.is_chunked:
                        # TODO res.payload.original should be the used attribute, but scapy has a bug, where length of 1st chunk is being dropped
                        chunks, remaining_len, waiting_for_content = read_chunks(res.original)
                        if not waiting_for_content:  # final chunk received -> add to content as to request
                            exchange.set_response(res.original, b''.join(chunks), res)
                            res.is_chunked = False
                            res, exchange = None, None
                    elif res.Content_Length and int(res.Content_Length) > 0:
                        waiting_for_content = True
                elif raw_pkt.haslayer('HTTP'):       # probably a subsequent fragment for a request/response
                    if is_request and exchange and waiting_for_content:
                        try:
                            exchange.set_content(raw_pkt.getlayer('HTTP').original)
                        except UnicodeDecodeError as exc:
                            print(exc)
                    elif waiting_for_content:
                        if res and res.is_chunked:
                            # TODO see other todo with res.payload.original
                            new_chunks, remaining_len, waiting_for_content = read_chunks(http.original, remaining_len)
                            chunks += new_chunks
                            if not waiting_for_content:  # final chunk received -> add to content as to request
                                exchange.set_response(res.original, b''.join(chunks), res)
                                res.is_chunked = False
                                res, exchange = None, None
        return exchanges

    @staticmethod
    def _full_duplex(p):
        # From here https://pen-testing.sans.org/blog/2017/10/13/scapy-full-duplex-stream-reassembly
        sess = "Other"
        if 'Ether' in p or 'CookedLinux' in p:  # CookedLinux = capture from all interfaces
            if 'IP' in p:
                if 'TCP' in p:
                    sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str))
                elif 'UDP' in p:
                    sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport], key=str))
                elif 'ICMP' in p:
                    sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id], key=str))
                else:
                    sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto], key=str))
            elif 'ARP' in p:
                sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst], key=str))
            else:
                sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
        return sess

    @classmethod
    def _process_request(cls, raw_pkt):
        pkt = raw_pkt.getlayer('HTTPRequest')
        src_ip, dst_ip = raw_pkt[IP].src, raw_pkt[IP].dst
        timestamp = float(raw_pkt.time)
        fields = pkt.fields
        notes = cls._parse_comments(raw_pkt.options)
        exchange = HttpExchange(src_ip, dst_ip, timestamp, pkt.original, source='PCAP', note=notes)
        waiting_for_content = False
        if pkt.TE and b'chunked' in pkt.TE:
            waiting_for_content = True
        if 'Content_Length' in fields:
            waiting_for_content = int(fields.get('Content_Length', 0)) > 0
        return exchange, waiting_for_content

    @staticmethod
    def _parse_comments(pkt_options):
        # https://pcapng.github.io/pcapng/#section_opt
        if pkt_options is None or len(pkt_options) == 0:
            return ''
        notes = [opt[1].decode('utf-8') for opt in pkt_options if opt[0] == 1]  # opt_code 1 = OPT_COMMENT
        return ';\n'.join(notes)


def read_chunks(body: bytes, remaining_len: int = 0, trailer: Optional[str] = None) -> Tuple[List[bytes], int, bool]:
    """
    Splits the given bytearray into chunks. Each chunk is represented as chunk length as hex and the chunk itself.
    The last chunk is indicated by length = 0 (see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding#Directives)
    :param body: the chunks which have to be read
    :param remaining_len: number of bytes belonging to the previous chunk without having a length specified
    :param trailer: trailer with header fields as stated in the request
    :return: list of extracted chunks, number pending bytes in the next fragment, flag if the last chunk has been read
    """
    # TODO support trailer (stated in request)-> should that be handled?
    # workaround for scapy bug where length of 1st chunk is being dropped -> parse raw packet
    crlfcrlf = b"\r\n\r\n"
    crlfcrlfIndex = body.find(crlfcrlf)
    if crlfcrlfIndex != -1:
        body = body[crlfcrlfIndex + len(crlfcrlf):]

    if remaining_len:  # bytes are part of chunk from previous packet
        chunk, body2 = body[:remaining_len], body[remaining_len:]
        # prepend remaining chunk length to match expected format
        body = b''.join([hex(remaining_len).encode('utf-8'), b'\r\n', chunk, body2])

    chunks = []
    length, rem_len = 0, remaining_len
    while body:
        length, _, body = body.partition(CRLF)
        try:
            length = int(length, 16)
        except ValueError as exc:  # Not a valid chunk. Ignore
            raise ValueError(f"'{length.decode('utf-8')}' is not a valid chunk size")
        else:
            chunk = body[:length]
            body = body[length + 2:]
            rem_len = length - len(chunk)
            if length > 0:  # final chunk has length 0
                chunks.append(chunk)
    return chunks, rem_len, length != 0
