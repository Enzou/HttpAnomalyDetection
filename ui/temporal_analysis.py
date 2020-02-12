from typing import List

import pandas as pd
import streamlit as st
import altair as alt

from src import utils
from ui.components import data_selector


def plot_timeseries(df, y_feature: str) -> None:
	chart = alt.Chart(df).mark_circle().encode(
		x='ts_offset',
		y=y_feature,
		color='source_ip'
	)
	st.altair_chart(chart, use_container_width=True)


@st.cache
def align_sessions(df: pd.DataFrame, id_attr: str = 'source_ip') -> pd.DataFrame:
	traces = df.groupby([id_attr])
	df['ts_offset'] = traces.timestamp.transform(lambda x: x - x.min())
	df = df[['source_ip', 'destination_ip', 'timestamp', 'ts_offset', 'method', 'path', '#_headers', 'content_length',
			 'content-type', 'user_agent', 'status_code', 'rtt']]
	return df


@st.cache
def extract_features(df: pd.DataFrame) -> pd.DataFrame:
	return df


def main():
	# data = data_selector.select_file('raw', default='smuggling_labeled.pcapng')
	sel_files, df = data_selector.select_file('raw', default='UNSW-NB15/pcaps_17-2-2015/27_http.pcap')
	
	df = extract_features(df)
	df = align_sessions(df)
	
	st.dataframe(df)
	
	ts_feature = st.selectbox('Feature timeseries:', options=['#_headers'])
	plot_timeseries(df, '#_headers')


if __name__ == "__main__":
	main()
