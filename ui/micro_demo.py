import streamlit as st
import os
import pandas as pd
from typing import Dict, List, Optional

import datasource
from src import utils
from src.http_message.http_exchange import HttpExchange
from src.micro_layer.models.manual import ManualDetector
from ui.components import data_selector

SAMPLES_DIR = 'samples/demo'


@st.cache
def load_samples(files: List[str], src_dir: str = SAMPLES_DIR):
	samples = datasource.load_samples_from_files(files, src_dir)
	# return list(utils.load_samples_from_file(SAMPLES_DIR / file_name))
	return samples


@st.cache
def classify_samples(df: pd.DataFrame, model: ManualDetector, weights: Dict) -> pd.DataFrame:
	"""Classifies the samples and attach the prediction and optionally
	the probabilities of all possible classes """
	predictions = model.predict(df['__ref'], include_probabilities=True, prediction_prefix='prob_')
	return predictions


def get_model(model_name: str):
	if model_name == 'manual':
		return ManualDetector()
	else:
		raise ValueError(f"{model_name} is not a valid model!")


def show_confusion_matrix(df: pd.DataFrame) -> None:
	def _colorize_cells(x):
		false_bg = 'background-color: #ecc0c0'
		true_bg = 'background-color: #c2ecc0'
		df = x.copy()
		df.iloc[:, :] = ''
		df.iloc[0, 0] = true_bg
		df.iloc[1, 1] = true_bg
		df.iloc[0, 1] = false_bg
		df.iloc[1, 0] = false_bg
		return df
	st.subheader("Confusion Matrix:")
	mat_df = pd.crosstab(df['predicted'], df['label'])
	# conf_mat = alt.Chart(mat_df, height=500, title="Confusion Matrix").mark_rect(opacity=.7).encode()
	t = mat_df.style.apply(_colorize_cells, axis=None)
	st.dataframe(t)


def show_dataframe(title: str, df: pd.DataFrame, cols: Optional[List[str]] = None) -> None:
	st.subheader(title)
	df_format = {}
	st.dataframe(df[cols].style.format(df_format).background_gradient(cmap='OrRd', subset=['rtt']))
	st.write(f"Showing {len(df)} samples")


def inspect_exchange(df: pd.DataFrame) -> None:
	"""Display detailed information about the classification of a sample"""
	if len(df) > 0:
		st.subheader("Inspecting HTTP Exchange")
		st.write("Drag the slider to select the entry from the previous dataframe for inspection.")
		selected_sample_idx = st.slider("Sample to inspect:", 0, len(df) - 1)
		s = df.iloc[selected_sample_idx]
		sample_xch = s['__ref']

		if st.checkbox('Show details of the selected HTTP exchange?'):
			st.write(s)

		if st.checkbox('Show request headers?'):
			for hdr_name, hdr_value in sample_xch.get_request().headers:
				st.write(f"**{hdr_name}:** {hdr_value}")

		model = ManualDetector()
		# st.text(model.detectors)
		ind_reasons = model.evaluate_indicators(sample_xch)
		explanation_df = pd.DataFrame({'Indicator': list(ind_reasons.keys()), 'Reason': list(ind_reasons.values())})
		if len(explanation_df) == 0:
			st.info('No detailed information available')
		else:
			st.markdown('### Explanation')
			st.table(explanation_df)
		predictions_probs = model.predict(pd.Series(sample_xch), include_probabilities=True)
		probs_df = predictions_probs.loc[:, predictions_probs.columns != 'predicted']
		st.write('Classification probabilities:')
		st.write(probs_df)


def label_fn(s) -> str:
	if s['transfer_encoding'] is not None and s['content_length'] is not None:
		return 'HttpRequestSmuggling'
	elif s['tags'] == 'from_extension':
		return 'HttpRequestSmuggling'
	else:
		return 'benign'


@st.cache(allow_output_mutation=True)
def process_samples(df: pd.DataFrame) -> pd.DataFrame:
	# df = pd.DataFrame([exchange.to_series() for exchange in samples])
	if not df.empty and 'label' not in df.columns:
		df['label'] = df.apply(label_fn, axis=1)
	return df


def analyze_results(df: pd.DataFrame, model: ManualDetector) -> None:
	""" Code for analysis after the classification has been completed """
	default_cols = ['method', 'path', '#_headers', 'transfer_encoding',
					'content_length', 'rtt', 'status_code', 'label', 'predicted']
	diff = set(default_cols).difference(df.columns)
	shown_columns = st.sidebar.multiselect('Shown columns:', list(df.columns), default=default_cols)
	show_confusion_matrix(df)
	views = {
		'All': df,
		'False Negatives': df[(df['predicted'] == 'benign') & (df['label'] != 'benign')].reset_index(),
		'False Positives': df[(df['predicted'] != 'benign') & (df['label'] == 'benign')].reset_index()
	}

	st.subheader('Inspect results ')
	shown_data_view = st.selectbox('Show Data: ', list(views.keys()), index=0)
	show_dataframe(shown_data_view, views[shown_data_view], shown_columns)

	inspect_exchange(views[shown_data_view])


def export_to_csv(df: pd.DataFrame, dst_path: str) -> None:
	"""Exports processed dataframe to csv file; must contain `label` column"""
	# exp_df = pd.DataFrame([row['__ref'] exchange.to_csv_entry() for row in df.iterrows])
	exp_df = df.transform([lambda x: x['__ref'].to_csv_entry()])
	a = 5


def tune_classifier_weights(model: ManualDetector) -> Dict:
	hrs_weights = model.get_weights('HttpRequestSmuggling')

	new_weights = {}
	for indicator, weight in hrs_weights.items():
		new_weights[indicator] = st.slider(indicator, min_value=0., max_value=5., value=weight, step=0.01)

	model.update_weights('HttpRequestSmuggling', new_weights)
	return new_weights


def main():
	st.title("Recon Detector")
	sel_files, df = data_selector.select_file('raw', default='smuggling_labeled.pcapng')
	# datasets = utils.filter_supported_datasets(os.listdir(SAMPLES_DIR))
	# selected_samples = st.sidebar.multiselect('Select Dataset:', datasets, default=['burp_hrs_filtered.csv'])
	# selected_samples = st.sidebar.multiselect('Select Dataset:', datasets)
	if len(sel_files) == 0:
		st.info("Please select at least one dataset!")
		return

	# samples = load_samples(selected_samples)
	# st.text(f"Loaded {len(samples)} samples")

	df = process_samples(df)
	# selected_model = st.sidebar.selectbox('Model:', ['Manual'])
	selected_model = 'manual'
	model = get_model(selected_model)

	# if st.checkbox('Tune weights?'):
	# 	weights = tune_classifier_weights(model)  # weights are used as indicator for caching
	# else:
	weights = {}
	predictions = classify_samples(df, model, weights)
	classified_df = pd.concat([df, predictions], axis=1)
	st.text(f"Classified samples with '{selected_model}' detector")

	if not classified_df.empty:
		analyze_results(classified_df, model)
		# if st.button("Export?"):
		# 	export_to_csv(df, Path(SAMPLES_DIR) / 'burp_hrs_labeled.csv')
	else:
		st.error("Couldn't classify provided samples")


if __name__ == "__main__":
	main()
