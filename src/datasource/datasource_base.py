from pathlib import Path
from typing import Union, Generator, Any


class DataSourceBase:
    def load_samples(self, path: Union[str, Path]) -> Generator[Any, None, None]:
        raise NotImplemented
