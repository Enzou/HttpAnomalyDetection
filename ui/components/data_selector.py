import os
from pathlib import Path
from typing import Tuple, Optional, List

import streamlit as st
import pandas as pd

import datasource
import src.utils as utils


DATA_DIR = Path('data')


@st.cache(show_spinner=False)
def load_data(files: List[str], src_dir: Path = DATA_DIR) -> pd.DataFrame:
    samples = datasource.load_samples_from_files(files, src_dir)
    return samples


@st.cache
def to_dataframe(data: List, ignored_cols: Optional[List] = None) -> pd.DataFrame:
    df = pd.DataFrame([exchange.to_series() for exchange in data])
    if ignored_cols is not None:
        df = df.drop(ignored_cols, axis=1)
    # return df[['source_ip', 'destination_ip', 'timestamp']]
    return df


def get_available_files(src_dir: Path) -> List[str]:
    """
    Create a full list of all files in given folder and its subfolders
    :param src_dir: folder whose content will be listed
    :return: list of all files in given folder
    """
    fs = [str(Path(dp).relative_to(src_dir)/f) for dp, dn, fn in os.walk(src_dir) for f in fn]
    return fs


def select_file(src_folder: str, default: Optional[str] = None) -> Tuple[str, pd.DataFrame]:
    """
    Selection widget for choosing the file to work on.
    :param src_folder: sub-directory within the 'data'-directory from where the files should be used
    :param default: preset file
    :return: tuple with name of selected file and loaded file as pandas dataframe
    """
    # available_files = utils._available_datasets(src_dir)
    st.sidebar.header("Select source file(s)")

    src_dir = DATA_DIR/src_folder
    available_files = get_available_files(src_dir)

    file_types = list(set([Path(f).suffix for f in available_files]))
    file_types = utils.get_supported_filetypes(file_types)
    sel_file_types = st.sidebar.multiselect("File types:", options=file_types, default=file_types)

    datasets = utils.filter_supported_datasets(available_files, sel_file_types)
    if default not in datasets:
        try:
            def_f = Path(default)
            default = next(ds for ds in datasets if Path(ds) == def_f)
        except StopIteration:
            default = None
    selected_files = st.sidebar.multiselect("Source file: ", options=datasets, default=default)

    ignored_col_options = ['request_headers', 'raw_request', 'response_headers', '__ref']
    ignored_cols = st.sidebar.multiselect("Ignore columns:", options=ignored_col_options, default=ignored_col_options)
    ignored_cols = []

    if len(selected_files) == 0:
        st.error("No valid file selected")
        return '', pd.DataFrame()
    else:
        with st.spinner("Loading data " + ', '.join(selected_files)):
            data = load_data(selected_files, src_dir)
            df = to_dataframe(data, ignored_cols=ignored_cols)
        st.write(f"Loaded {len(df)} entries")
        return selected_files, df
