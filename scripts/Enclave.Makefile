
Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
BINDGEN_RAW_LINES := "\#![allow(dead_code)] use frame_types::*; use sgx_types::*;"
BINDGEN_CLANG_FLAGS := -I/opt/sgxsdk/include -I $(HOME)/sgx/edl
BINDGEN_FLAGS := --default-enum-style=rust --rust-target=nightly \
	--no-recursive-whitelist --use-array-pointers-in-arguments \
	--whitelist-function ocall_.*  --raw-line $(BINDGEN_RAW_LINES)
Rust_target_dir := debug
ENCLAVE_PATH := $(ANONIFY_ROOT_DIR)/$(ENCLAVE_DIR)
BINDGEN_OUTPUT_FILE := $(ANONIFY_ROOT_DIR)/core/enclave/src/bridges/auto_ffi.rs

all: bindgen $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
	@cd $(ENCLAVE_PATH) && RUST_LOG=debug cargo build $(CARGO_FLAGS) $(FEATURE_FLAGS)
	mkdir -p $(CUSTOM_LIBRARY_PATH)
	@cp $(ANONIFY_ROOT_DIR)/target/$(Rust_target_dir)/libanonifyenclave.a $(CUSTOM_LIBRARY_PATH)/libenclave.a

.PHONY: bindgen
bindgen: $(ANONIFY_BUILD_DIR)/$(T_H_FILE)
	@cd $(ANONIFY_ENCLAVE_DIR)
	bindgen $(ANONIFY_BUILD_DIR)/$(T_H_FILE) $(BINDGEN_FLAGS) -- $(BINDGEN_CLANG_FLAGS) > $(BINDGEN_OUTPUT_FILE)
	rustfmt $(BINDGEN_OUTPUT_FILE)
