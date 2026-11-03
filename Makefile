# Forcecage — top-level targets.
#
# The cage code lands in src/cage (Python, stdlib only) and the tripwire in
# src/tripwire (TypeScript) as the extraction proceeds; `check` verifies
# whatever exists at each stage.

PYTHON ?= python3

.PHONY: check test

check:
	$(PYTHON) -m compileall -q .
	@if ls src/cage/*.py >/dev/null 2>&1; then $(PYTHON) -m unittest discover -s tests -v; fi

test: check
