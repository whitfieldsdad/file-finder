from dataclasses import dataclass
import sys
from typing import Iterable, Iterator, List, Optional

import errno
import logging
import os

logger = logging.getLogger(__name__)

FOLLOW_SYMLINKS = False
FOLLOW_MOUNTS = False


@dataclass()
class Search:
    roots: List[str]
    follow_mounts: bool = FOLLOW_MOUNTS
    follow_symlinks: bool = FOLLOW_SYMLINKS
    excluded_directories: Optional[List[str]] = None

    @property
    def total_results(self) -> int:
        return self.count_matching_files()

    def walk(self) -> Iterator[str]:
        excluded_directories = self.excluded_directories
        follow_mounts = self.follow_mounts
        follow_symlinks = self.follow_symlinks

        for root in self.roots:
            if os.path.exists(root):
                yield root
                yield from walk(
                    path=root,
                    excluded_directories=excluded_directories,
                    follow_mounts=follow_mounts,
                    follow_symlinks=follow_symlinks,
                )

    def iter_matching_files(self) -> Iterator[str]:
        yield from self.walk()

    def count_matching_files(self) -> int:
        return sum(1 for _ in self)

    def __iter__(self):
        yield from self.walk()


def walk(
        path: str,
        excluded_directories: Optional[Iterable[str]] = None,
        follow_symlinks: bool = FOLLOW_SYMLINKS,
        follow_mounts: bool = FOLLOW_MOUNTS) -> Iterator[str]:

    if not os.path.isdir(path):
        yield path
        return

    try:
        entries = os.scandir(path)
    except (OSError, PermissionError):
        return

    for entry in entries:
        try:
            is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
        except (OSError, PermissionError):
            continue

        if is_dir:
            yield entry.path

            # Skip mount points.
            if not follow_mounts and (os.stat(entry.path).st_dev != os.stat(path).st_dev):
                logger.info(f"Skipping mount point: {entry.path}")
                continue

            # Skip excluded directories.
            if excluded_directories and any(in_directory(entry.path, d) for d in excluded_directories):
                logger.info(f"Skipping excluded directory: {entry.path}")
                continue

            yield from walk(
                path=entry.path,
                excluded_directories=excluded_directories,
                follow_mounts=follow_mounts,
                follow_symlinks=follow_symlinks,
            )
        else:
            yield entry.path


def in_directory(path: str, directory: str) -> bool:
    path = os.path.abspath(path)
    directory = os.path.abspath(directory)
    return os.path.commonpath([path, directory]) == directory
