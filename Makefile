.POSIX:

TARGET ?=
JOBS ?= 5
FUZZ_ARGS ?= -max_total_time=10

BIN := digestlookup
SOURCE := $(PWD)
BUILD := $(SOURCE)/build
BUILD_DEBUG := $(BUILD)/debug
BUILD_RELEASE := $(BUILD)/release

all: release

$(BUILD_RELEASE):
	@cmake -B $(BUILD_RELEASE) -DCMAKE_BUILD_TYPE=Release

$(BUILD_DEBUG):
	@cmake -B $(BUILD_DEBUG) -DCMAKE_BUILD_TYPE=Debug

release: $(BUILD_RELEASE)
	@cmake --build $(BUILD_RELEASE) -j $(JOBS) --target $(TARGET)
	@cp $(BUILD_RELEASE)/src/$(BIN) .

debug: $(BUILD_DEBUG)
	@cmake --build $(BUILD_DEBUG) -j $(JOBS) --target $(TARGET)
	@cp $(BUILD_DEBUG)/compile_commands.json .
	@utils/fix-clangd compile_commands.json

test-release: release
	@cd $(BUILD_RELEASE) && QA_FUZZ_ARGS=$(FUZZ_ARGS) \
		ctest --output-on-failure -j $(JOBS) -R $(TARGET)

test-debug: debug
	@cd $(BUILD_DEBUG) && QA_FUZZ_ARGS=$(FUZZ_ARGS) \
		ctest --output-on-failure -j $(JOBS) -R $(TARGET)

test: test-debug

coverage: test-debug
	@gcovr --use-gcov-files --keep --exclude '^tests/' --sort-percentage

check: coverage
	@cmake --build $(BUILD_DEBUG) --target check

clean:
	@rm -rf $(BUILD)

install: release
	@cmake --build $(BUILD_RELEASE) --target install

fix: $(BUILD_DEBUG)
	@cmake --build $(BUILD_DEBUG) --target fix

.PHONY: all release debug test-release test-debug test coverage check \
	clean install fix
