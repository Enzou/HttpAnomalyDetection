import streamlit as st
import logging

from src.utils import setup_logger
from ui.components.logger import StreamlitHandler
import ui.preprocessing

# import ui.temporal_analysis
# import ui.analyze_indicator_patterns
# import ui.micro_demo


PAGES = {
    "Preprocessing": ui.preprocessing,
    # "Micro Demo": ui.micro_demo,
    # "Temporal Analysis": ui.temporal_analysis,
    # "Analyze Indicator Patterns": ui.analyze_indicator_patterns
}


def setup_logging():
    placeholder = st.empty()
    st_handler = StreamlitHandler(placeholder)
    setup_logger(None, handler=st_handler)


def main():
    st.title("HTTP Anomaly Detection ")
    setup_logging()
    st.sidebar.title("Navigation")
    pages = list(PAGES.keys())
    default_page = pages.index('Preprocessing')
    # default_page = pages.index('Temporal Analysis')
    # default_page = pages.index('Clustering')
    selection = st.sidebar.radio("Go to", pages, index=default_page)

    with st.spinner(f"Loading {selection} ..."):
        page = PAGES[selection]
        st.title(selection)
        page.main()


if __name__ == "__main__":
    main()




# DATA_DIR = Path('data/raw')
#
#
# def load_unsw_nb15(id: int) -> pd.DataFrame:
#     feature_df = pd.read_csv(DATA_DIR/'UN')
#     pass
#
#
# @st.cache
# def load_samples(files: List[str], src_dir: str = DATA_DIR):
#     # samples = utils.load_samples_from_files(files, src_dir)
#     samples = pd.read_csv(src_dir/files[0])
#     return samples
#
#
# def main():
#     st.title("Analyze Macro Indicators")
#     datasets = utils.filter_supported_datasets(os.listdir(DATA_DIR))
#     selected_sample_files = st.sidebar.multiselect('Select Dataset:', datasets, default=['UNSW_NB15_training-set.csv'])
#
#     if len(selected_sample_files) == 0:
#         st.info("Please select at least one dataset!")
#         return
#     samples = load_samples(selected_sample_files)
#     st.text(f"Loaded {len(samples)} samples")
#
#     st.write(samples.describe())
