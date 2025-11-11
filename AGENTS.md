# Repository Guidelines

## Project Structure & Module Organization
The `src/` directory houses the `tcpviz` package, with the CLI entry point in `src/cli.py` and supporting packages under `detectors/`, `parser/`, `realtime/`, and `viz/`. Tests live in `tests/`, using the same package layout to mirror production modules. Example inputs sit in `samples/`, while generated reports and logs belong in `artifacts/`; avoid committing those outputs. Configuration lives in `environment.yml` and reusable command shortcuts in the `Makefile`.

## Build, Test, and Development Commands
Provision the Conda toolchain with `conda env create -f environment.yml` on first setup or `conda env update -f environment.yml --prune` to refresh dependencies, then `conda activate CS204`. Use `make test` to execute the pytest suite inside the managed environment. To exercise the CLI end-to-end, parse a capture with `python -m src.cli parse-pcap --in samples/test.pcapng` and render outputs with `python -m src.cli plot --in artifacts/session_*/events.jsonl`.

## Coding Style & Naming Conventions
Follow Python 3.11 conventions with four-space indentation, type annotations, and docstrings for public functions. Use lower_snake_case for functions, methods, and module names; reserve UpperCamelCase for classes. Keep modules focused and factor reusable helpers into existing utilities or subpackages. Prefer ASCII output and logging patterns consistent with current Click commands and `logging_utils`.

## Testing Guidelines
Author unit tests alongside new functionality under `tests/`, using pytest’s `test_<feature>.py` naming scheme. Mock external packet captures where feasible; provide sample pcaps under `samples/` for integration scenarios. Aim to cover detectors, parsers, and CLI flows with assertions around emitted events and generated files. Run `make test` before submitting changes and note any session directories that the run generates.

## Commit & Pull Request Guidelines
Write commit subjects in the imperative mood (e.g., “Add retransmission detector regression test”) and keep them under 72 characters; explain context and validation details in the body when needed. Commits should be scoped to a cohesive change touching code and tests together. Pull requests must include a concise summary, linked issues, and any CLI output or artifact previews that help reviewers verify behaviour. List the commands you ran so reviewers can reproduce validation quickly.

## Security & Configuration Tips
Ensure `tshark` and `dumpcap` are installed when working with live captures and document any additional system capabilities you require. Avoid committing captures containing sensitive traffic—redact or synthesize samples under `samples/` instead. When adding new environment variables, prefix them with `TCPVIZ_` and document usage in the README to keep configuration discoverable.
