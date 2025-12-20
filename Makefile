.PHONY: venv install scan analyze fmt

VENV=.venv
PY=$(VENV)/bin/python
PIP=$(VENV)/bin/pip

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

scan:
	$(PY) -m dockyard scan --write-latest

analyze:
	$(PY) -m dockyard analyze

fmt:
	@echo "No formatter configured yet."
