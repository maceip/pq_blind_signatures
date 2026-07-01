BUILD_SCRIPT_LOCATION := ../vole/
BUILD_SCRIPT_NAME := build_consv_bs_keccak_deg16.sh
FAEST_MESON_BUILD_DIR ?= build_debug_$(shell uname -s | tr '[:upper:]' '[:lower:]')_$(shell uname -m)
LIBRARY_FOLDER := ../vole/faest-cpp-tmp/$(FAEST_MESON_BUILD_DIR)

.PHONY: all

all:
	mkdir -p target/debug
	cd $(BUILD_SCRIPT_LOCATION) && FAEST_MESON_BUILD_DIR=$(FAEST_MESON_BUILD_DIR) ./$(BUILD_SCRIPT_NAME)
	cp $(LIBRARY_FOLDER)/libvolekeccak_deg16_then_mayo_bs.so target/debug
