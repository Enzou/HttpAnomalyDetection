import time
from typing import Generator, Iterator
import numpy as np

import streamlit as st

from ui.components import data_selector


def load_data() -> Iterator[int]:
	for i in range(10):
		yield i
		time.sleep(.5)


# @st.cache(suppress_st_warning=True)
# def my_load(val, fn):
# 	data = []
# 	progress_bar = st.progress(0)
# 	status_text = st.empty()
# 	for i in load_data():
# 		progress_bar.progress(i)
# 		v = np.random.randn(2, 10)
# 		fn(v)
# 		data.append(v)
# 		status_text.text(f"Latest: {i}")
# 	st.write(data)
# 	return data


def main():
	sel_files, df = data_selector.select_file('raw', default='unsw-nb15/17-02-2015/27_http.pcap')

	chart = st.line_chart()
	
	# v = st.slider('Test', min_value=1, max_value=10)
	# data = my_load(v, lambda x: chart.add_rows(x))
	
	# for d in data:
	# 	chart.add_rows(d)
	st.write('Done')
