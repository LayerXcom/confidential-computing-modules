SGX_SDK_RUST ?= $(HOME)/sgx
ANONIFY_CORE_ROOT := ../core
ANONIFY_ENCLAVE_DIR := $(ANONIFY_CORE_ROOT)/enclave
ANONIFY_HOST_DIR := $(ANONIFY_CORE_ROOT)/host
ANONIFY_BIN_DIR := $(HOME)/.anonify
ANONIFY_EDL_DIR := ../edl
EDL_FILE := Anonify_common.edl

######## Settings for Circle CI ######
CARGO ?= cargo
BINDGEN ?= bindgen
RUSTFMT ?= rustfmt

######## SGX SDK Settings ########

SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

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

CUSTOM_LIBRARY_PATH := $(ANONIFY_CORE_ROOT)/lib
CUSTOM_EDL_PATH := $(SGX_SDK_RUST)/edl
CUSTOM_COMMON_PATH := $(SGX_SDK_RUST)/common

######## EDL Settings ########

Enclave_EDL_Files := $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.c $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.h $(ANONIFY_HOST_DIR)/Anonify_common_u.c $(ANONIFY_HOST_DIR)/Anonify_common_u.h

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
RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=$(ANONIFY_ENCLAVE_DIR)/Enclave.lds

RustEnclave_Name := $(ANONIFY_ENCLAVE_DIR)/enclave.so
Signed_RustEnclave_Name := $(ANONIFY_BIN_DIR)/enclave.signed.so

.PHONY: all
all: $(Signed_RustEnclave_Name)

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) $(ANONIFY_EDL_DIR)/$(EDL_FILE)
	$(SGX_EDGER8R) --trusted $(ANONIFY_EDL_DIR)/$(EDL_FILE) --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir $(ANONIFY_ENCLAVE_DIR)
	$(SGX_EDGER8R) --untrusted $(ANONIFY_EDL_DIR)/$(EDL_FILE) --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir $(ANONIFY_HOST_DIR)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## Enclave Objects ########

$(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.o
	@$(CXX) $(ANONIFY_ENCLAVE_DIR)/Anonify_common_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ANONIFY_ENCLAVE_DIR)/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config $(ANONIFY_ENCLAVE_DIR)/Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave
enclave: $(Enclave_EDL_Files)
	$(MAKE) -f Enclave.Makefile CARGO_FLAGS=$(Host_Rust_Flags) Rust_target_dir=$(Rust_target_dir) CARGO=$(CARGO) BINDGEN=$(BINDGEN) RUSTFMT=$(RUSTFMT) ANONIFY_ENCLAVE_DIR=$(ANONIFY_ENCLAVE_DIR) CUSTOM_LIBRARY_PATH=$(CUSTOM_LIBRARY_PATH)
