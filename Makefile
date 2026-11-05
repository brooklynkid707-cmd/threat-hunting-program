PY ?= python3

.PHONY: help install data test demo report score clean

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-8s %s\n",$$1,$$2}'

install:  ## install dependencies (pyyaml, pytest)
	$(PY) -m pip install -r requirements.txt

data:  ## regenerate the synthetic 14-day dataset (deterministic, fixed seed)
	$(PY) scripts/generate_dataset.py

test:  ## run the test suite
	$(PY) -m pytest -q

demo:  ## list hunts, run H01, score all hunts, prove detections, regenerate reports
	$(PY) -m hunt list
	$(PY) -m hunt run H01 --top 5
	$(PY) -m hunt run-all --out output/
	$(PY) -m hunt score
	$(PY) -m hunt detect
	$(PY) -m hunt report

report:  ## regenerate hunts/*/results.md, program/program_report.md, examples/
	$(PY) -m hunt report

score:  ## score every hunt against ground truth
	$(PY) -m hunt score

clean:  ## remove ad-hoc output and caches (keeps committed data/ and examples/)
	rm -rf output/*.json .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
