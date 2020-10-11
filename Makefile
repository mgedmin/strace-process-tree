.PHONY: all
all:
	@echo "Nothing to build."

.PHONY: test
test:                           ##: run tests
	tox -p auto

.PHONY: coverage
coverage:                       ##: measure test coverage
	tox -e coverage

.PHONY: flake8
flake8:                         ##: check for style problems
	tox -e flake8


FILE_WITH_VERSION = strace_process_tree.py
include release.mk
