from pathlib import Path
from typing import Union, Generator, Dict

# from DataWeaver.dataset_reader import BaseReader
from .datasource_base import DataSourceBase
from src.http_message.http_exchange import HttpExchange
import pandas as pd
import dateutil.parser as date_parser
import re
import math
import csv


class CsvReader:
	def load_samples(self, path: Union[str, Path]) -> Generator[HttpExchange, None, None]:
		with open(path, 'r') as f:
			column_name_line = f.readline()
			column_names = set([c.strip() for c in column_name_line.split(',')])
		if all(c in column_names for c in BurpLogReader.column_names):
			# TODO use intersection of most important columns as order of columns can change in burp
			return BurpLogReader.load_samples(path)
		elif all(c in column_names for c in BurpLogReader.column_names):
			return ProcessedCsvReader.load_samples(path)
		else:
			# print('Columns: ' + column_name_line + 'not in ')
			# df = pd.read_csv(path)  # TODO fix bug when reading cells containing null-bytes
			# for index, row in df.iterrows():
			#     # exchange = HttpExchange('127.0.0.1', row['Host'], req_time,
			#     #                         raw_request=cls._fix_http_message(row['Request']),
			#     #                         raw_response=response,
			#     #                         note=row['RequestTime'],
			#     #                         rtt=rtt, source='BurpLog')
			#     yield HttpExchange('127.0.0.1', 'arst')
			raise NotImplementedError


def _read_csv(path: Path) -> Generator[Dict[str, str], None, None]:
	with open(path) as f:
		for line in csv.DictReader(f):
			yield dict(line)


class BurpLogReader:
	"""A reader for responses and requests stored in a full csv export of the Burps Logger++ plugin"""
	column_names = ["Number", "Complete", "Tool", "Host", "Method", 'Path', "Query", "Params", "Status",
					"ResponseLength", "MimeType", "Comment", "NewCookies",
					"RequestTime", "ResponseDelay", "ListenerInterface", "Regex1Req",
					"Regex1Resp", "Request", "Response"]

	@staticmethod
	def _burp_time_str_to_timestamp(time_str: str) -> float:
		dt = date_parser.parse(time_str)
		return dt.timestamp()

	@staticmethod
	def _parse_delay_string(delay: Union[str, float]) -> float:
		if isinstance(delay, float):
			return -1. if math.isnan(delay) else delay
		else:
			pattern = r'(?:(\d+)s\s)?(\d+)ms'
			m = re.search(pattern, delay)
			sec, ms = m.groups()
			return (int(sec) * 60 if sec else 0) + int(ms)

	@staticmethod
	def _fix_http_message(msg: Union[bytes, str]) -> bytes:
		"""Workaround for CSV reader, which converts \r\n line delimeters to \n resulting in malformed requests"""
		if isinstance(msg, bytes):
			# return msg.replace(b'\n', b'\r\n')
			return msg
		else:
			# msg = msg.replace('\n', '\r\n')
			return msg.encode('utf-8')

	@classmethod
	def load_samples(cls, path: Union[str, Path]) -> Generator[HttpExchange, None, None]:
		# rows = _read_csv(path)
		df = pd.read_csv(path)  # TODO fix bug when reading cells containing null-bytes

		for index, row in df.iterrows():
			req_time = cls._burp_time_str_to_timestamp(row['RequestTime'])
			# delay is more precise than calculating difference between request and response
			rtt = cls._parse_delay_string(row['ResponseDelay'])
			res_entry = row['Response']
			response = cls._fix_http_message(res_entry) if isinstance(res_entry, str) else None
			exchange = HttpExchange(row['Host'], row['Host'], req_time,
									raw_request=cls._fix_http_message(row['Request']),
									raw_response=response,
									note=row['RequestTime'],
									rtt=rtt, source='BurpLog')
			exchange.tags = ['from_extension' if row['Tool'] == 'Extender' else '']
			yield exchange


class ProcessedCsvReader(DataSourceBase):
	column_names = ['source_ip', 'destination_ip', 'request_ts', 'response_ts',
					'request_b64', 'response_b64', 'source', 'note', 'tags', 'label']

	@classmethod
	def load_samples(cls, path: Union[str, Path]) -> Generator[HttpExchange, None, None]:
		pass
