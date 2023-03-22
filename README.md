# A simple file finder

The files that you're looking for can be surprisingly hard to find, so, I'm trying to make it easier.

## Pre-requisites

- Python <3.12,>=3.7
- Poetry

## Installation

```bash
make install
```

## Building executables

Cross-platform compilation is not supported, but yuou can build executables for your current platform:

If you're on Windows, you can build an executable like this:

```bash
make windows_executable
```

## Usage

### Searching for files

To search a directory:

```bash
poetry run find ~
```

To search one or more directories:

```bash
poetry run find ~ .
```

> ℹ️ By default, following mount points is disabled.

To enable it, use the `--follow-mounts` flag:

```bash
poetry run find ~ . --follow-mounts
```

> ℹ️ By default, following symbolic links is disabled.

To enable it, use the `--follow-symlinks` flag:

```bash
poetry run find ~ . --follow-symlinks
```

### Searching for files matching a set of YARA rules

As an example, let's search for all PE files on the system, including files located on mounted filesystems while following symbolic links and save the results to a file:

```bash
poetry run find / --follow-mounts --follow-symlinks --yara-rules=resources/yara/pe-files.yar -o pe-files.txt
```

### Counting matching files

To count the number of matching files, pipe the output to `wc` (**W**ord **C**ount):

```bash
poetry run find ~ | wc -l
```
