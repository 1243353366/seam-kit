PY ?= python3
NODE ?= node
PORT ?= 8787

.PHONY: test test-py test-api lab e2e api clean

test: test-py test-api

test-py:
	$(PY) -m unittest discover -s tests -q

test-api:
	$(NODE) --test api/test/*.test.ts

lab:
	$(PY) -m lab.experiment
	@echo "report: docs/lab-report.md"

e2e:
	bash tools/e2e.sh

api:
	PORT=$(PORT) SEAM_DB=$(PWD)/seam.db $(NODE) api/src/server.ts

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

case:  ## run the museum case and write the report
	python -m scenario.museum case-report
