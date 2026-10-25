# Convenience wrapper around CMake, which remains the source of truth.
#
#   make           configure + build (Debug) in build/
#   make test      build + run unit tests
#   make release   optimized, fortified build + tests in build-release/
#   make asan      AddressSanitizer + UBSan build + tests in build-asan/
#   make integration  real mounts end to end, local and 3-node (Linux, root)
#   make dashboard-test  dashboard unit and headless UI tests (in .venv)
#   make clean     remove all build directories

BUILD_DIR  ?= build
BUILD_TYPE ?= Debug
CMAKE_ARGS ?=

.PHONY: all build test release asan integration dashboard-test clean

all: build

$(BUILD_DIR)/CMakeCache.txt:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(CMAKE_ARGS)

build: $(BUILD_DIR)/CMakeCache.txt
	cmake --build $(BUILD_DIR) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

release:
	$(MAKE) test BUILD_DIR=build-release BUILD_TYPE=Release

asan:
	$(MAKE) test BUILD_DIR=build-asan CMAKE_ARGS=-DKFS_SANITIZE=ON

integration: build
	tests/integration/fuse_smoke.sh $(BUILD_DIR)
	tests/integration/cluster_smoke.sh $(BUILD_DIR)

.venv/bin/pytest: dashboard/pyproject.toml
	python3 -m venv .venv
	.venv/bin/pip install -q -e "dashboard[test]"

dashboard-test: .venv/bin/pytest
	cd dashboard && ../.venv/bin/pytest -q

clean:
	rm -rf build build-release build-asan
