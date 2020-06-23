
Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
Rust_Target_Path := $(CURDIR)/../../../xargo
BINDGEN_OUTPUT_FILE := src/auto_ffi.rs
BINDGEN_RAW_LINES := "\#![allow(dead_code)] use anonify_types::*; use sgx_types::*;"
BINDGEN_CLANG_FLAGS := -I/opt/sgxsdk/include -I $(HOME)/sgx/edl
BINDGEN_FLAGS := --default-enum-style=rust --rust-target=nightly \
	--no-recursive-whitelist --use-array-pointers-in-arguments \
	--whitelist-function ocall_.*  --raw-line $(BINDGEN_RAW_LINES)

all: bindgen $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
ifeq ($(XARGO_SGX), 1)
	RUST_TARGET_PATH=$(Rust_Target_Path) xargo build --target x86_64-unknown-linux-sgx --release
	cp ./target/x86_64-unknown-linux-sgx/$(Rust_target_dir)/libanonifyenclave.a ../lib/libenclave.a
else
	cargo build $(CARGO_FLAGS) $(FEATURE_FLAGS)
	cp ./target/$(Rust_target_dir)/libanonifyenclave.a ../lib/libenclave.a
endif

.PHONY: bindgen
bindgen: Enclave_t.h
	cargo build -p anonify-types
	$(BINDGEN) Enclave_t.h $(BINDGEN_FLAGS) -- $(BINDGEN_CLANG_FLAGS) > $(BINDGEN_OUTPUT_FILE)
	$(RUSTFMT)  $(BINDGEN_OUTPUT_FILE)
