PYTHON ?= python3

.PHONY: install test scan-example

install:
	@echo "No Python packages required. Install Nmap separately."

test:
	$(PYTHON) -m unittest discover -s tests -v

scan-example:
	$(PYTHON) nmap_framework.py scanme.nmap.org --i-have-permission
