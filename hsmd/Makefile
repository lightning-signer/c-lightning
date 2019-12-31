#! /usr/bin/make

# Designed to be run one level up
hsmd-wrongdir:
	$(MAKE) -C .. lightningd/hsm-all

default: hsmd-all

LIGHTNINGD_HSM_SRC := hsmd/hsmd.c	\
	hsmd/gen_hsm_wire.c \
	hsmd/api.pb.cc \
	hsmd/api.grpc.pb.cc \
	hsmd/proxy.cc
LIGHTNINGD_HSM_HEADERS := hsmd/gen_hsm_wire.h hsmd/api.pb.h hsmd/api.grpc.pb.h
LIGHTNINGD_HSM_CCOBJS := $(LIGHTNINGD_HSM_SRC:.cc=.o)
LIGHTNINGD_HSM_OBJS := $(LIGHTNINGD_HSM_CCOBJS:.c=.o)

HOST_SYSTEM = $(shell uname | cut -f 1 -d_)
SYSTEM ?= $(HOST_SYSTEM)
CXX = g++
CXXFLAGS += -std=c++11 -I. -Iccan -Iexternal/libwally-core/src/secp256k1/include
PROTOC = protoc
GRPC_CPP_PLUGIN = grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`
PROTOS_PATH = hsmd

# Common source we use.
HSMD_COMMON_OBJS :=				\
	common/amount.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/funding_tx.o			\
	common/gen_status_wire.o		\
	common/hash_u5.o			\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/permute_tx.o			\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/withdraw_tx.o

# For checking
LIGHTNINGD_HSM_ALLSRC_NOGEN := $(filter-out hsmd/gen_%, $(LIGHTNINGD_HSM_SRC) $(LIGHTNINGD_HSM_SRC))
LIGHTNINGD_HSM_ALLHEADERS_NOGEN := $(filter-out hsmd/gen_%, $(LIGHTNINGD_HSM_HEADERS))

$(LIGHTNINGD_HSM_OBJS): $(LIGHTNINGD_HEADERS)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_HSM_OBJS)
ALL_PROGRAMS += lightningd/lightning_hsmd
ALL_GEN_HEADERS += hsmd/gen_hsm_wire.h
ALL_GEN_HEADERS += hsmd/api.pb.h hsmd/api.grpc.pb.h

hsmd-all: lightningd/lightning_hsmd

lightningd/lightning_hsmd: $(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_LIB_OBJS) $(HSMD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

hsmd/api.grpc.pb.o hsmd/api.pb.o hsmd/proxy.o : CPPFLAGS += `pkg-config --cflags protobuf grpc`
lightningd/lightning_hsmd: LDLIBS += -L/usr/local/lib \
	`pkg-config --libs protobuf grpc++`\
	-pthread\
	-Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
	-ldl
lightningd/lightning_hsmd: LDLIBS += -lstdc++

hsmd/gen_hsm_wire.h: $(WIRE_GEN) hsmd/hsm_wire.csv
	$(WIRE_GEN) --page header $@ hsm_wire_type < hsmd/hsm_wire.csv > $@

hsmd/gen_hsm_wire.c: $(WIRE_GEN) hsmd/hsm_wire.csv
	$(WIRE_GEN) --page impl ${@:.c=.h} hsm_wire_type < hsmd/hsm_wire.csv > $@

check-source: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_HSM_SRC:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/hsm-clean

lightningd/hsm-clean:
	$(RM) $(LIGHTNINGD_HSM_OBJS) hsmd/gen_*
	$(RM) hsmd/*.pb.cc hsmd/*.pb.h

.PRECIOUS: %.grpc.pb.cc
%.grpc.pb.cc: %.proto
	$(PROTOC) -I $(PROTOS_PATH) --grpc_out=hsmd --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $<

.PRECIOUS: %.pb.cc
%.pb.cc: %.proto
	$(PROTOC) -I $(PROTOS_PATH) --cpp_out=hsmd $<

-include hsmd/test/Makefile
