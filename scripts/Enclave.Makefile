
Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
Rust_target_dir := debug
ENCLAVE_PATH := $(ANONIFY_ROOT_DIR)/$(ENCLAVE_DIR)

all: $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
	@cd $(ENCLAVE_PATH) && RUST_LOG=debug cargo build $(CARGO_FLAGS) $(FEATURE_FLAGS)
	mkdir -p $(CUSTOM_LIBRARY_PATH)
	@cp $(ANONIFY_ROOT_DIR)/target/$(Rust_target_dir)/libanonifyenclave.a $(CUSTOM_LIBRARY_PATH)/libenclave.a
