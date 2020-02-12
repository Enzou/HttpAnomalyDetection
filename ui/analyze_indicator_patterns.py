from datetime import datetime
import time
from functools import partial
import os
from typing import List, Callable, Optional, Dict, Tuple
import pandas as pd
import streamlit as st
import altair as alt

import datasource
from src import utils
from src.http_message.http_exchange import HttpExchange
from src.indicator_registry import registry as indicator_registry
from src.history_store import HistoryStore
from src.micro_layer import micro_indicators
from src.macro_layer import macro_indicators
from src import ReconDetector

from src.result_evaluator import evaluate_result

SAMPLES_DIR = 'samples/demo'




@st.cache
def load_samples(files: List[str], src_dir: str = SAMPLES_DIR):
	samples = datasource.load_samples_from_files(files, src_dir)
	return samples


# @st.cache(allow_output_mutation=True)
# def process_samples(samples: List[HttpExchange]) -> pd.DataFrame:
# 	df = pd.DataFrame([exchange.to_series() for exchange in samples])
# 	if not df.empty and 'label' not in df.columns:
# 		df['label'] = df.apply(label_fn, axis=1)
# 	return df


def create_scatter_plot(df: pd.DataFrame) -> alt.Chart:
	# single_nearest = alt.selection_single(on='click', nearest=True)

	ch = alt.Chart(df).mark_circle().encode(
		x='timestamp:T', y='indicator:N',
		tooltip=['request_id', 'reason'],
		color='indicator_type:N'
	# ).facet(
	# 	row='indicator_type:N'
	# ).add_selection(
	# 	single_nearest
	).interactive()
	return ch


def indicator_activation_to_dict(indicators: Dict, request_id: int, timestamp: float) -> List[Dict]:
	activations = []
	for indicator_type, activated_indicators in indicators.items():
		for indicator, reason in activated_indicators.items():
			activations.append({
				'request_id': request_id,
				'timestamp': datetime.fromtimestamp(timestamp),
				'indicator': indicator,
				'indicator_type': indicator_type,
				'reason': reason
			})
	return activations


def show_indicator_over_time(samples, pipeline, hidden_indicators: List[str]):
	# history = HistoryStore(columns=indicator_registry.indicator_names + ['rtt', 'status_code'])

	activated_indicators = []
	for i, sample in enumerate(samples):
		fired_indicators, infos = pipeline(sample)
		ts = infos['timestamp']
		activated_indicators += indicator_activation_to_dict(fired_indicators, i, ts)
	df = pd.DataFrame(activated_indicators, columns=['request_id', 'timestamp', 'indicator', 'indicator_type', 'reason'])
	st.altair_chart(create_scatter_plot(df))


def replay(samples, pipeline, hidden_indicators: List[str]):
	df = pd.DataFrame(columns=['request_id', 'timestamp', 'indicator', 'indicator_type', 'reason'])
	chart = st.altair_chart(create_scatter_plot(df))
	progress_bar = st.progress(0)

	replay_speed = st.slider("Replay Speed: ", min_value=0.1, max_value=50., value=1.)

	last_ts = 0.
	num_samples = len(samples)
	for i, sample in enumerate(samples):
		fired_indicators, infos = pipeline(sample)
		ts = infos['timestamp']
		for ind_activation in indicator_activation_to_dict(fired_indicators, i, ts):
			chart.add_rows([ind_activation])
		if last_ts > 0:
			delay = (ts - last_ts) / replay_speed
			print(f"Waiting {delay:2f} s")
			time.sleep(delay)  # sleep same time as time passed between requests
		last_ts = ts
		progress_bar.progress(i/num_samples)


def show_exchange(xch: HttpExchange) -> None:
	st.text(xch.get_request()._raw.decode('utf-8'))


def main():
	st.title("Analyze Macro Indicators")
	datasets = utils.filter_supported_datasets(os.listdir(SAMPLES_DIR))
	selected_samples = st.sidebar.multiselect('Select Dataset:', datasets, default=['burp_hrs_filtered.csv'])

	if len(selected_samples) == 0:
		st.info("Please select at least one dataset!")
		return
	samples = load_samples(selected_samples)
	st.text(f"Loaded {len(samples)} samples")

	history = HistoryStore()
	recon_detector = ReconDetector()
	pipeline = recon_detector.setup_analysis_pipeline(history)

	# TODO implement filter of indicators
	# TODO implement proper mechanic for history handling (indicators + tracked fields for macro indicators)

	hidden_indicators = st.multiselect("Hidden Indicators: ", options=indicator_registry.indicator_names)

	if st.checkbox("Animate processing"):
		replay(samples, pipeline, hidden_indicators)
	else:
		show_indicator_over_time(samples, pipeline, hidden_indicators)

	df = history.get_data()
	grp = df.groupby([pd.Grouper(freq='10s'), 'src_ip'])
	res = grp['timestamp'].count().unstack('src_ip').fillna(0)
	req_id = st.slider("Request to inspect:", min_value=0, max_value=len(samples)-1)
	show_exchange(samples[req_id])

# dot = """
#         // The graph name and the semicolons are optional
#         graph pipeline {
#         	HttpRequest [shape=box]
#             HttpRequest -> Preprocess -> "Extract Indicators" -> "Analyze Exchange" -> "Evaluate Results" -> Watchlist
#             Preprocess -> "Extract Temporal Indicators" -> "Analyze Temporal Behavior" -> "Evaluate Results"
#         }
#         """
# st.graphviz_chart(dot)


if __name__ == "__main__":
	main()
