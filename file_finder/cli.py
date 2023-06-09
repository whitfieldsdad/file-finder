import os
import click
from typing import List, Optional
from file_finder.search import Search, FOLLOW_MOUNTS, FOLLOW_SYMLINKS

import file_finder.ux

import click
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_default_roots() -> List[str]:
    return [os.getcwd()]


@click.command('find')
@click.argument('roots', nargs=-1)
@click.option('--output-file', '-o')
@click.option('--filename-pattern', '-f', 'filename_patterns', multiple=True)
@click.option('--follow-mounts/--no-follow-mounts', is_flag=True, default=FOLLOW_MOUNTS, show_default=True)
@click.option('--follow-symlinks/--no-follow-symlinks', is_flag=True, default=FOLLOW_SYMLINKS, show_default=True)
@click.option('--exclude', 'excluded_directories', multiple=True)
@click.option('--yara-rules', 'yara_rule_paths', multiple=True)
@click.option('--min-file-size', type=file_finder.ux.parse_human_readable_number_of_bytes)
@click.option('--max-file-size', type=file_finder.ux.parse_human_readable_number_of_bytes)
def find_paths(
        roots: List[str],
        output_file: Optional[str],
        filename_patterns: List[str],
        follow_mounts: bool, follow_symlinks: bool,
        excluded_directories: List[str],
        yara_rule_paths: List[str],
        min_file_size: Optional[str],
        max_file_size: Optional[str]):
    """
    Search for files.
    """
    roots = roots or get_default_roots()

    search = Search(
        roots=roots,
        filename_patterns=filename_patterns,
        follow_mounts=follow_mounts,
        follow_symlinks=follow_symlinks,
        excluded_directories=excluded_directories,
        yara_rule_paths=yara_rule_paths,
        min_file_size=min_file_size,
        max_file_size=max_file_size,
    )
    if output_file:
        with open(output_file, 'w') as file:
            for path in search:
                file.write(f"{path}\n")
    else:
        for path in search:
            print(path)


def main():
    find_paths()


if __name__ == "__main__":
    main()
