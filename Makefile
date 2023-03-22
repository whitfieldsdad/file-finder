test:
	poetry run pytest

install:
	poetry install

windows_executable:
	poetry run pyinstaller --onefile --name=file-search.exe file_finder/cli.py

.PHONY: install search find