from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Union

import logging
import os
import yara

logger = logging.getLogger(__name__)

FOLLOW_SYMLINKS = False
FOLLOW_MOUNTS = False


@dataclass()
class Search:
    roots: List[str]
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

        # Optionally filter files using YARA rules.
        if self.yara_rule_paths:
            rules = read_yara_rules(self.yara_rule_paths)
            paths = iter_files_matching_any_yara_ruleset(paths, rules)

        total = 0
        for path in paths:
            yield path
            total += 1

        logger.info(f"Found {total} matching files")

    def _walk(self) -> Iterator[str]:
        excluded_directories = self.excluded_directories
        follow_mounts = self.follow_mounts
        follow_symlinks = self.follow_symlinks
        min_file_size = self.min_file_size
        max_file_size = self.max_file_size

        for root in self.roots:
            if os.path.exists(root):
                yield root
                yield from walk(
                    path=root,
                    excluded_directories=excluded_directories,
                    follow_mounts=follow_mounts,
                    follow_symlinks=follow_symlinks,
                    min_file_size=min_file_size,
                    max_file_size=max_file_size,
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
        follow_mounts: bool = FOLLOW_MOUNTS,
        min_file_size: Optional[int] = None,
        max_file_size: Optional[int] = None) -> Iterator[str]:

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
                follow_mounts=follow_mounts,
                follow_symlinks=follow_symlinks,
                min_file_size=min_file_size,
                max_file_size=max_file_size
            )
        else:
            if min_file_size or max_file_size:
                try:
                    file_size = entry.stat(
                        follow_symlinks=follow_symlinks).st_size
                except (OSError, PermissionError) as e:
                    logger.debug(f"Unable to stat file: {entry.path} - {e}")
                    continue

                if min_file_size and file_size < min_file_size:
                    continue

                if max_file_size and file_size > max_file_size:
                    continue

            yield entry.path


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
