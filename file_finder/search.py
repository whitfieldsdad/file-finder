from dataclasses import dataclass
import functools
from typing import Iterable, Iterator, List, Optional, Union

import logging
import os
import yara
import fnmatch

logger = logging.getLogger(__name__)

FOLLOW_SYMLINKS = False
FOLLOW_MOUNTS = False


@dataclass()
class Search:
    roots: List[str]
    filename_patterns: Optional[List[str]] = None
    follow_mounts: bool = FOLLOW_MOUNTS
    follow_symlinks: bool = FOLLOW_SYMLINKS
    excluded_directories: Optional[List[str]] = None
    min_file_size: Optional[int] = None
    max_file_size: Optional[int] = None
    yara_rule_paths: Optional[List[str]] = None

    @property
    def total_results(self) -> int:
        return self.count_matching_files()

    def walk(self) -> Iterator[str]:
        paths = self._walk()

        # Optionally filter files by size.
        if self.min_file_size or self.max_file_size:
            paths = filter_paths_by_file_size(
                paths=paths,
                min_file_size=self.min_file_size,
                max_file_size=self.max_file_size
            )

        # Optionally filter files by name ($).
        if self.min_file_size or self.max_file_size:
            paths = filter_paths_by_filename(
                paths=paths,
                filename_patterns=self.filename_patterns
            )

        # Optionally filter files using YARA rules ($$$).
        if self.yara_rule_paths:
            rules = read_yara_rules(self.yara_rule_paths)
            paths = iter_files_matching_any_yara_ruleset(paths, rules)

        total = 0
        for path in paths:
            yield path
            total += 1

        logger.info(f"Found {total} matching files")

    def _walk(self) -> Iterator[str]:
        f = functools.partial(
            walk,
            excluded_directories=self.excluded_directories,
            follow_mounts=self.follow_mounts,
            follow_symlinks=self.follow_symlinks,
        )
        for root in self.roots:
            if os.path.exists(root):
                yield from f(root)

    def iter_matching_files(self) -> Iterator[str]:
        yield from self.walk()

    def count_matching_files(self) -> int:
        return sum(1 for _ in self)

    def __iter__(self):
        yield from self.walk()


def walk(
        path: str,
        excluded_directories: Optional[Iterable[str]] = None,
        filename_patterns: Optional[Iterable[str]] = None,
        follow_symlinks: bool = FOLLOW_SYMLINKS,
        follow_mounts: bool = FOLLOW_MOUNTS,
        min_file_size: Optional[int] = None,
        max_file_size: Optional[int] = None) -> Iterator[str]:

    yield path
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

            # Handle mount points.
            if not follow_mounts and (os.stat(entry.path).st_dev != os.stat(path).st_dev):
                logger.debug(f"Skipping mount point: {entry.path}")
                continue

            # Skip excluded directories.
            if excluded_directories and any(in_directory(entry.path, d) for d in excluded_directories):
                logger.debug(f"Skipping excluded directory: {entry.path}")
                continue

            yield from walk(
                path=entry.path,
                excluded_directories=excluded_directories,
                filename_patterns=filename_patterns,
                follow_mounts=follow_mounts,
                follow_symlinks=follow_symlinks,
                min_file_size=min_file_size,
                max_file_size=max_file_size
            )
        else:

            yield entry.path


def filter_paths_by_filename(paths: Iterable[str], filename_patterns: Optional[Iterable[str]] = None) -> Iterator[str]:
    for path in paths:
        if filename_patterns:
            if any(fnmatch.fnmatch(path, pattern) for pattern in filename_patterns):
                yield path
        else:
            yield path


def filter_paths_by_file_size(
        paths: Iterable[str],
        min_file_size: Optional[int] = None,
        max_file_size: Optional[int] = None):

    for path in paths:
        try:
            file_size = os.stat(path).st_size
        except (OSError, PermissionError) as e:
            logger.debug(f"Unable to stat file: {path} - {e}")
            continue

        if min_file_size and file_size < min_file_size:
            continue

        if max_file_size and file_size > max_file_size:
            continue

        yield path


def in_directory(path: str, directory: str) -> bool:
    path = os.path.abspath(path)
    directory = os.path.abspath(directory)
    return os.path.commonpath([path, directory]) == directory


def read_yara_rules(paths: List[str]) -> List[yara.Rules]:
    def stream():
        for path in Search(paths):
            if path.endswith('.yar') or path.endswith('.yara'):
                try:
                    rules = yara.compile(path)
                except yara.Error:
                    logger.warning(f"Skipping invalid YARA rules file: {path}")
                else:
                    yield rules
    return list(stream())


def get_yara_matches(path: str, rules: Union[yara.Rules, Iterable[yara.Rules]]) -> List[yara.Match]:
    return list(iter_yara_matches(path, rules))


def iter_yara_matches(path: str, rules: Union[yara.Rules, Iterable[yara.Rules]]) -> Iterator[yara.Match]:
    if os.path.isdir(path):
        return

    rulesets = [rules] if isinstance(rules, yara.Rules) else rules
    for ruleset in rulesets:
        try:
            matches = ruleset.match(path)
        except yara.Error:
            continue
        else:
            yield from matches


def has_matching_yara_rule(path: str, rules: Union[yara.Rules, Iterable[yara.Rules]]) -> bool:
    for _ in iter_yara_matches(path, rules):
        return True
    return False


def iter_files_matching_any_yara_ruleset(paths: Iterator[str], rules: Union[yara.Rules, Iterable[yara.Rules]]) -> Iterator[str]:
    for path in paths:
        if has_matching_yara_rule(path, rules):
            yield path
