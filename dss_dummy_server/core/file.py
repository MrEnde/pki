import pathlib
from functools import cache

TEMP_DIRECTORY_FILES = "/tmp/"


def join_temp_path(filename: str) -> pathlib.Path:
    return pathlib.Path(TEMP_DIRECTORY_FILES).joinpath(filename)


@cache
def temp_path():
    return pathlib.Path(TEMP_DIRECTORY_FILES)


temp_path()
