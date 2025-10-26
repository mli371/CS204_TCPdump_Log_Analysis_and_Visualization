SHELL := /bin/bash
CONDA_ENV := CS204

.PHONY: init install mvp test

init:
	@echo "[init] Ensuring conda environment $(CONDA_ENV) matches environment.yml"
	@conda env update -f environment.yml --prune || conda env create -f environment.yml

install:
	@echo "Activate the environment with: conda activate $(CONDA_ENV)"

mvp:
	@echo "[mvp] Preparing demo artifacts"
	@mkdir -p artifacts/demo
	@touch samples/demo.pcap
	@echo "[mvp] Parsing sample capture"
	@PYTHONPATH=$(PWD)/.. conda run -n $(CONDA_ENV) python -m tcpviz.src.cli parse-pcap --in samples/demo.pcap
	@latest=$$(ls -1t artifacts/session_*/events.jsonl | head -n 1); \
		echo "[mvp] Rendering timeline from $$latest"; \
		PYTHONPATH=$(PWD)/.. conda run -n $(CONDA_ENV) python -m tcpviz.src.cli plot --in $$latest

test:
	@echo "[test] Running pytest"
	@PYTHONPATH=$(PWD)/.. conda run -n $(CONDA_ENV) pytest -q || true
