.PHONY: all
all:
	@echo "Nothing to build."


.PHONY: test check
test check:
	tox -p auto


.PHONY: coverage
coverage:
	tox -e coverage


.PHONY: flake8
flake8:
	tox -e flake8

include release.mk
