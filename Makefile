PYTHON ?= python

.PHONY: install test scan-example web

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

scan-example:
	$(PYTHON) -m nmapfw scan scanme.nmap.org --profile quick --i-have-permission

web:
	$(PYTHON) -m nmapfw.web.app
