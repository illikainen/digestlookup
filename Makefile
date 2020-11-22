SOURCE := $(PWD)

BUILD ?= $(PWD)/build
BUILD_DEBUG ?= $(BUILD)/debug
BUILD_RELEASE ?= $(BUILD)/release

all: release

clean:
	@rm -rf $(BUILD)

debug:
	@mkdir -p $(BUILD_DEBUG)
	@cd $(BUILD_DEBUG) && \
		cmake $(SOURCE) -DCMAKE_BUILD_TYPE=Debug && make
	@cp $(BUILD_DEBUG)/compile_commands.json .
	@utils/fix-clangd compile_commands.json

release:
	@mkdir -p $(BUILD_RELEASE)
	@cd $(BUILD_RELEASE) && \
		cmake $(SOURCE) -DCMAKE_BUILD_TYPE=Release && make

install: release
	@cd $(BUILD_RELEASE) && make install

test: debug
	@find $(BUILD_DEBUG) \( -name "*.profraw" -o -name "profdata" \) \
		-exec rm "{}" \;
	@cd $(BUILD_DEBUG) && CTEST_OUTPUT_ON_FAILURE=1 make test

check: test
	@cd $(BUILD_DEBUG) && make check

fix: debug
	@cd $(BUILD_DEBUG) && make fix

.PHONY: all clean debug release install test check fix
