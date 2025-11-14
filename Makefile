SHELL := /bin/bash
CONDA_ENV := CS204
CONDARUN := conda run -n $(CONDA_ENV)
PCAP ?= samples/test.pcapng
WINDOW ?= 60
THRESHOLD ?= 10

.PHONY: init install parse plot summary monitor dashboard test

init:
	@echo "[init] Ensuring conda environment $(CONDA_ENV) matches environment.yml"
	@conda env update -f environment.yml --prune || conda env create -f environment.yml

install:
	@echo "Activate the environment with: conda activate $(CONDA_ENV)"

parse:
	@echo "[parse] Parsing $(PCAP)"
	@$(CONDARUN) python -m src.cli parse-pcap --in $(PCAP)

plot:
	@latest=$$(ls -1dt artifacts/session_* 2>/dev/null | head -n 1) && \
		echo "[plot] Rendering timeline for $$latest"; \
		$(CONDARUN) python -m src.cli plot --in $$latest/events.jsonl

summary:
	@latest=$$(ls -1dt artifacts/session_* 2>/dev/null | head -n 1) && \
		echo "[summary] Rendering summary for $$latest"; \
		$(CONDARUN) python -m src.cli summary --in $$latest/events.jsonl

monitor:
	@test -n "$(PCAP)" || (echo "Usage: make monitor PCAP=/path/to/rolling.pcapng" && exit 1)
	@echo "[monitor] Following $(PCAP) (window=$(WINDOW)s threshold=$(THRESHOLD))"
	@$(CONDARUN) python -m src.cli monitor --pcap-path $(PCAP) --window $(WINDOW) --threshold $(THRESHOLD)

dashboard:
	@test -n "$(PCAP)" || (echo "Usage: make dashboard PCAP=/path/to/capture.pcapng" && exit 1)
	@echo "[dashboard] Generating reports from $(PCAP)"
	@$(CONDARUN) scripts/generate_dashboard.sh $(PCAP)

test:
	@echo "[test] Running pytest"
	@$(CONDARUN) pytest -q
