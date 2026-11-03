# Forcecage — top-level targets.
#
# The cage code lands in src/cage (Python, stdlib only) and the tripwire in
# src/tripwire (TypeScript) as the extraction proceeds; `check` verifies
# whatever exists at each stage.

PYTHON ?= python3

.PHONY: check test install e2e

check:
	$(PYTHON) -m compileall -q .
	@if ls src/cage/*.py >/dev/null 2>&1; then $(PYTHON) -m unittest discover -s tests -v; fi

# Host-integration e2e (real sudo hop + bwrap + gate). Skips itself when the
# cage host-changes are absent, so it is green on hosts without them (and in
# CI, which has no `agent` user).
e2e:
	bash tests/forcecage-e2e.test.sh

# Install the `forcecage` console script into the current environment.
install:
	$(PYTHON) -m pip install -e .

test: check
