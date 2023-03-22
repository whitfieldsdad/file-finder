# If the first argument is "find"...
ifeq (find,$(firstword $(MAKECMDGOALS)))
	# use the rest as arguments for "run"
	QUERY := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
	# ...and turn them into do-nothing targets
	$(eval $(QUERY):;@:)
endif

find:
	poetry run find $(QUERY)

install:
	poetry install

windows_executable:
		poetry run pyinstaller --onefile --name=file-search.exe file_finder/cli.py

.PHONY: run install search find
