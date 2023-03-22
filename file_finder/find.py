from dataclasses import dataclass
import os
import sys
from typing import Iterable, Iterator, List, Optional, Union

from file_finder.search import Search, FOLLOW_MOUNTS, FOLLOW_SYMLINKS

import logging
import yara

logger = logging.getLogger(__name__)


@dataclass()
class Find(Search):
    roots: List[str]
    follow_mounts: bool = FOLLOW_MOUNTS
    follow_symlinks: bool = FOLLOW_SYMLINKS
    excluded_directories: Optional[List[str]] = None
    yara_rule_paths: Optional[List[str]] = None

    @property
    def search(self) -> Search:
        return Search(
            roots=self.roots,
            follow_mounts=self.follow_mounts,
            follow_symlinks=self.follow_symlinks,
            excluded_directories=self.excluded_directories,
        )

    def walk(self) -> Iterator[str]:
        paths = self.search

        # Optionally filter files using YARA rules.
        if self.yara_rule_paths:
            rules = read_yara_rules(self.yara_rule_paths)
            paths = iter_files_matching_any_yara_ruleset(paths, rules)

        total = 0
        for path in paths:
            yield path
            total += 1

        logger.info(f"Found {total} matching files")


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
