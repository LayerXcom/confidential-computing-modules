
Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
BINDGEN_RAW_LINES := "\#![allow(dead_code)] use anonify_types::*; use sgx_types::*;"
BINDGEN_CLANG_FLAGS := -I/opt/sgxsdk/include -I $(HOME)/sgx/edl
BINDGEN_FLAGS := --default-enum-style=rust --rust-target=nightly \
	--no-recursive-whitelist --use-array-pointers-in-arguments \
	--whitelist-function ocall_.*  --raw-line $(BINDGEN_RAW_LINES)
Rust_target_dir := debug
ENCLAVE_DIR := ../example/erc20/enclave
BINDGEN_OUTPUT_FILE := $(ENCLAVE_DIR)/src/auto_ffi.rs

all: bindgen $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
	@cd $(ENCLAVE_DIR) && cargo build $(CARGO_FLAGS) $(FEATURE_FLAGS)
	mkdir -p $(CUSTOM_LIBRARY_PATH)
	@cp $(ENCLAVE_DIR)/target/$(Rust_target_dir)/libanonifyenclave.a $(CUSTOM_LIBRARY_PATH)/libenclave.a

.PHONY: bindgen
bindgen: $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.h
	@cd $(ANONIFY_ENCLAVE_DIR) && cargo build -p anonify-types
	bindgen $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.h $(BINDGEN_FLAGS) -- $(BINDGEN_CLANG_FLAGS) > $(BINDGEN_OUTPUT_FILE)
	rustfmt $(BINDGEN_OUTPUT_FILE)
