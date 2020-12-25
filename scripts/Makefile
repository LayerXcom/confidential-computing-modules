SGX_SDK_RUST ?= $(HOME)/sgx
ANONIFY_ROOT_DIR := ..
ANONIFY_CORE_ROOT := $(ANONIFY_ROOT_DIR)/core
FRAME_ROOT := $(ANONIFY_ROOT_DIR)/frame
CONFIG_DIR := $(ANONIFY_ROOT_DIR)/config
ANONIFY_ENCLAVE_DIR := $(ANONIFY_CORE_ROOT)/enclave
ANONIFY_HOST_DIR := $(ANONIFY_CORE_ROOT)/host
ANONIFY_BIN_DIR := $(ANONIFY_ROOT_DIR)/.anonify
ANONIFY_EDL_DIR := $(ANONIFY_ROOT_DIR)/edl
ANONIFY_BUILD_DIR := $(ANONIFY_ROOT_DIR)/build

######## Settings for Circle CI ######
CARGO ?= cargo
BINDGEN ?= bindgen
RUSTFMT ?= rustfmt

######## SGX SDK Settings ########

SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(TEST), 1)
	EDL_FILE := Anonify_test.edl
	T_H_FILE := Anonify_test_t.h
	T_C_FILE := Anonify_test_t.c
	T_O_FILE := Anonify_test_t.o
	U_H_FILE := Anonify_test_u.h
	U_C_FILE := Anonify_test_u.c
	U_O_FILE := Anonify_test_u.o
else
	EDL_FILE := Anonify_common.edl
	T_H_FILE := Anonify_common_t.h
	T_C_FILE := Anonify_common_t.c
	T_O_FILE := Anonify_common_t.o
	U_H_FILE := Anonify_common_u.h
	U_C_FILE := Anonify_common_u.c
	U_O_FILE := Anonify_common_u.o
endif

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
	Rust_target_dir := debug
else
	SGX_COMMON_CFLAGS += -O2
	Host_Rust_Flags := --release
	Rust_target_dir := release
endif

Host_Rust_Flags += $(if $(JOBS),-j$(JOBS), )

######## CUSTOM Settings ########

CUSTOM_LIBRARY_PATH := $(ANONIFY_BUILD_DIR)/lib
CUSTOM_EDL_PATH := $(SGX_SDK_RUST)/edl
CUSTOM_COMMON_PATH := $(SGX_SDK_RUST)/common

######## EDL Settings ########

Enclave_EDL_Files := $(ANONIFY_ENCLAVE_DIR)/$(T_C_FILE) $(ANONIFY_ENCLAVE_DIR)/$(T_H_FILE) $(ANONIFY_HOST_DIR)/$(U_C_FILE) $(ANONIFY_HOST_DIR)/$(U_H_FILE)

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I $(ANONIFY_ENCLAVE_DIR) -I./include
RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -l$(ENCLAVE_PKG_NAME)enclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=$(CONFIG_DIR)/Enclave.lds

RustEnclave_Name := $(ANONIFY_BUILD_DIR)/$(ENCLAVE_PKG_NAME).enclave.so
Signed_RustEnclave_Name := $(ANONIFY_BIN_DIR)/$(ENCLAVE_PKG_NAME).signed.so
Rust_Enclave_Name := lib$(ENCLAVE_PKG_NAME)enclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)

.PHONY: all
all: $(Signed_RustEnclave_Name)

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) $(ANONIFY_EDL_DIR)/$(EDL_FILE)
	mkdir -p $(ANONIFY_BUILD_DIR)
	$(SGX_EDGER8R) --trusted $(ANONIFY_EDL_DIR)/$(EDL_FILE) --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir $(ANONIFY_BUILD_DIR)
	$(SGX_EDGER8R) --untrusted $(ANONIFY_EDL_DIR)/$(EDL_FILE) --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir $(ANONIFY_BUILD_DIR)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## Enclave Objects ########

$(ANONIFY_BUILD_DIR)/$(T_O_FILE): $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(ANONIFY_BUILD_DIR)/$(T_C_FILE) -o $(ANONIFY_BUILD_DIR)/$(T_O_FILE)
	@echo "CC   <=  $<"

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
	@echo "Rust_Enclave_Name <= $(PWD)"
	@cd $(ANONIFY_ROOT_DIR)/$(ENCLAVE_DIR) && RUST_LOG=debug cargo build $(CARGO_FLAGS) $(FEATURE_FLAGS)
	mkdir -p $(CUSTOM_LIBRARY_PATH)
	@cp $(ANONIFY_ROOT_DIR)/target/$(Rust_target_dir)/libanonifyenclave.a $(CUSTOM_LIBRARY_PATH)/lib$(ENCLAVE_PKG_NAME)enclave.a

$(RustEnclave_Name): $(Rust_Enclave_Name) $(ANONIFY_BUILD_DIR)/$(T_O_FILE)
	@$(CXX) $(ANONIFY_BUILD_DIR)/$(T_O_FILE) -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	mkdir -p $(ANONIFY_BIN_DIR)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(CONFIG_DIR)/test_enclave_signing.pem -enclave $(RustEnclave_Name) -out $@ -config $(CONFIG_DIR)/Enclave.config.xml
	@echo "SIGN =>  $@"
