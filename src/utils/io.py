import functools
import os
from pathlib import Path
from typing import Callable, List, Optional

import pandas as pd

_DATA_DIR = Path('./data/')


# def get_supported_file_types() -> List[str]:
#     return ['.pcap, .csv']

def get_supported_filetypes(available_types: Optional[List[str]] = None) -> List[str]:
    supported_types = ['.pcap', '.pcapng', '.csv']
    if available_types is not None:
        return [f for f in available_types if f in supported_types]
    return supported_types


def filter_supported_datasets(datasets: List[str], allowed_exts: Optional[List[str]] = None) -> List[str]:
    if allowed_exts is None:
        allowed_exts = get_supported_filetypes()
    return [ds for ds in datasets if Path(ds).suffix in allowed_exts]


def get_available_datasets() -> List[str]:
    # Get the list of all files in directory tree at given path
    files = []
    base_dir = _DATA_DIR / 'raw'
    for (dirpath, dirnames, filenames) in os.walk(base_dir):
        files += [os.path.join(dirpath, file) for file in filenames]

    return files


def filter_dt_session(df: pd.DataFrame) -> pd.DataFrame:
    return df.loc[df.ua_type != "Xhr", df.columns != 'ua_type']


@functools.lru_cache()
def load_csv_data(file_name: str, prep_fn: Callable = filter_dt_session) -> pd.DataFrame:
    """
    Read csv file from directory.
    """
    _DATA_DIR = Path('./data/')
    filtered_file = _DATA_DIR / 'interim' / file_name

    if os.path.exists(filtered_file):
        return pd.read_csv(filtered_file)
    else:
        df = pd.read_csv(_DATA_DIR / 'raw' / file_name)
        df_filtered = prep_fn(df)
        print(f"Loaded data: {len(df)} / after filtering {len(df_filtered)}")
        df_filtered.to_csv(filtered_file)  # store filtered DF for later re-usage
        print("Saved filtered dataframe")

        return df_filtered


