# Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of Baidu, Inc., nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

SGX_SDK_RUST ?= $(HOME)/sgx

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

######## CUSTOM Settings ########

CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_EDL_PATH := $(SGX_SDK_RUST)/edl
CUSTOM_COMMON_PATH := $(SGX_SDK_RUST)/common

######## EDL Settings ########

Enclave_EDL_Files := enclave/Enclave_t.c enclave/Enclave_t.h host/Enclave_u.c host/Enclave_u.h

######## HOST Settings ########

Host_Rust_Flags += $(if $(JOBS),-j$(JOBS), )
Host_SRC_Files := $(shell find host/ -type f -name '*.rs') $(shell find host/ -type f -name 'Cargo.toml')
Host_Include_Paths := -I ./host -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
Host_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Host_Include_Paths)

Host_Rust_Path := ./host/target/$(Rust_target_dir)
Host_Enclave_u_Object :=host/libEnclave_u.a
Host_Name := anonify-host

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard ./enclave/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./enclave -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=enclave/Enclave.lds

RustEnclave_Name := enclave/enclave.so
Signed_RustEnclave_Name := $(CUSTOM_BIN_PATH)/enclave.signed.so

.PHONY: all
all: $(Host_Name) $(Signed_RustEnclave_Name)

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) enclave/Enclave.edl
	$(SGX_EDGER8R) --trusted enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir enclave
	$(SGX_EDGER8R) --untrusted enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir host
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## Host Objects ########

host/Enclave_u.o: $(Enclave_EDL_Files)
	@cd host && $(CARGO) build -p anonify-types
	@$(CC) $(Host_C_Flags) -c host/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(Host_Enclave_u_Object): host/Enclave_u.o
	$(AR) rcsD $@ $^
	mkdir -p lib
	cp $(Host_Enclave_u_Object) $(CUSTOM_LIBRARY_PATH)

$(Host_Name): $(Host_Enclave_u_Object) $(Host_SRC_Files)
	@cd host && SGX_SDK_RUST=$(SGX_SDK_RUST) SGX_SDK=$(SGX_SDK) $(CARGO) build $(Host_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p $(CUSTOM_BIN_PATH)

######## Enclave Objects ########

enclave/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c enclave/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave enclave/Enclave_t.o
	@$(CXX) enclave/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config enclave/Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave
enclave: $(Enclave_EDL_Files)
	mkdir -p $(CUSTOM_LIBRARY_PATH)
	$(MAKE) -C ./enclave/ CARGO_FLAGS=$(Host_Rust_Flags) Rust_target_dir=$(Rust_target_dir) CARGO=$(CARGO) BINDGEN=$(BINDGEN) RUSTFMT=$(RUSTFMT)

.PHONY: compiler-rt
compiler-rt:
	$(MAKE) -C $(SGX_SDK_RUST)/compiler-rt/ 2> /dev/null

.PHONY: test
test: all
	@cd host && $(CARGO) test $(Host_Rust_Flags)

.PHONY: clean
clean:
	@rm -f $(CUSTOM_BIN_PATH)/$(Host_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) enclave/*_t.* host/*_u.* $(CUSTOM_LIBRARY_PATH)/*.a
	# @rm -f $(Host_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) enclave/*_t.* host/*_u.* lib/*.a
	# @cd enclave && $(CARGO) clean && rm -f Cargo.lock
	# @cd host && $(CARGO) clean && rm -f Cargo.lock

.PHONY: full-clean
# Clean:
#	untrusted and trusted libraries and binaries
#	edgerator generation results
#	files generated by rust build scripts
#	rust target directories
#	Cargo.lock files
full-clean:
	@rm -f $(CUSTOM_BIN_PATH)/$(Host_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) enclave/*_t.* host/*_u.* $(CUSTOM_LIBRARY_PATH)/*.a
	@rm -rf enclave/anonify-types.h host/anonify-types.h
	@cd enclave && $(CARGO) clean && rm -f Cargo.lock
	@cd host && $(CARGO) clean && rm -f Cargo.lock
