SENTRA=./sentra
EXAMPLES=$(wildcard examples/*.sn)
GREEN=\033[0;32m
RED=\033[0;31m
NC=\033[0m # No Color

.PHONY: test all sentra

sentra:
	go build -o sentra ./cmd/sentra

all: test

test:
	@pass=0; fail=0; \
	for f in $(EXAMPLES); do \
		echo "=== Running $$f ==="; \
		if $(SENTRA) run $$f > .test_out 2>&1; then \
			echo "$$f: ${GREEN}PASS${NC}"; \
			pass=$$((pass+1)); \
		else \
			echo "$$f: ${RED}FAIL${NC}"; \
			cat .test_out; \
			fail=$$((fail+1)); \
			break; \
		fi; \
		echo ""; \
	done; \
	rm -f .test_out; \
	echo "----------------------"; \
	echo "Total: $$((pass+fail)) | ${GREEN}Passed: $$pass${NC} | ${RED}Failed: $$fail${NC}"; \
	if [ $$fail -gt 0 ]; then exit 1; fi

