# Convenience wrapper around CMake, which remains the source of truth.
#
#   make           configure + build (Debug) in build/
#   make test      build + run unit tests
#   make release   optimized, fortified build + tests in build-release/
#   make asan      AddressSanitizer + UBSan build + tests in build-asan/
#   make clean     remove all build directories

BUILD_DIR  ?= build
BUILD_TYPE ?= Debug
CMAKE_ARGS ?=

.PHONY: all build test release asan clean

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

clean:
	rm -rf build build-release build-asan
