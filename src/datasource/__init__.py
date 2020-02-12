from pathlib import Path
from typing import List, Union, Generator

from .csv_reader import CsvReader
from .pcap_reader import PcapReader
from .datasource_base import DataSourceBase


def get_dataset_reader(extension: str) -> DataSourceBase:
    if extension.startswith('.'):
        extension = extension[1:]
    if extension in ['pcapng', 'pcap']:
        return PcapReader()
    elif extension == 'csv':
        return CsvReader()
    else:
        raise NotImplementedError


def load_samples_from_files(file_paths: List[Union[Path, str]], src_dir: str = '.') -> List:
    """
    Load all the samples from the given files. The kind of dataset is inferred by the extension of every file
    :return: List of loaded HttpExchanges
    """
    samples = []
    for p in file_paths:
        samples += load_samples_from_file(Path(src_dir) / p)
    return samples


def load_samples_from_file(file_path: Path) -> Generator:
    """
    Load all the samples from the given `file_path`. The kind of dataset is inferred by the extension of the file
    :return: List of loaded HttpExchanges
    """
    reader = get_dataset_reader(file_path.suffix)
    return reader.load_samples(file_path)