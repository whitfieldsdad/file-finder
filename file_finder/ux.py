import math
from typing import Optional
import humanize
import logging

logger = logging.getLogger(__name__)


def parse_number_of_bytes(sz: str) -> int:
    return parse_human_readable_number_of_bytes(sz)


def parse_human_readable_number_of_bytes(sz: str) -> int:
    try:
        return int(float(sz))
    except ValueError:
        for unit, e in [
            ["KiB", 2**10],
            ["MiB", 2**20],
            ["GiB", 2**30],
            ["TiB", 2**40],
            ["PiB", 2**50],
            ["EiB", 2**60],
            ["ZiB", 2**70],
            ["YiB", 2**80],
            ["KB", 10**3],
            ["MB", 10**6],
            ["GB", 10**9],
            ["TB", 10**12],
            ["PB", 10**15],
            ["EB", 10**18],
            ["ZB", 10**21],
            ["YB", 10**24],
            ["B", 1],
        ]:
            if sz.endswith(unit):
                sz = sz[:-len(unit)]
                sz = sz.strip()
                sz = float(sz)
                sz = math.ceil(sz * e)
                return sz
    raise ValueError(f"Unable to parse {sz}")


def get_human_readable_number_of_bytes(sz: int, use_metric_system: bool = True) -> str:
    if use_metric_system:
        return humanize.naturalsize(sz, binary=False)
    else:
        return humanize.naturalsize(sz, binary=True)
