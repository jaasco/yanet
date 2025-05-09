CXX = g++
CXXFLAGS = -g -std=c++17 -Wall -Wextra -pthread

INCLUDES = \
  -I.. \
  -I../build \
  -I../common \
  -I../controlplane \
  -I../controlplane/acl \
  -I../subprojects/json/include

FWPARSER_LIB = ../build/libfwparser/libyanet-fwparser.a
COMMON_LIB = ../build/common/libyanet-common.a

LDFLAGS += -L/usr/local/lib

CONTROLPLANE_OBJS = \
  ../build/controlplane/yanet-controlplane.p/acl.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_compiler.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_filter.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_network_table.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_total_table.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_transport.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_transport_table.cpp.o \
  ../build/controlplane/yanet-controlplane.p/acl_value.cpp.o \
  ../build/controlplane/yanet-controlplane.p/balancer.cpp.o \
  ../build/controlplane/yanet-controlplane.p/bus.cpp.o \
  ../build/controlplane/yanet-controlplane.p/configconverter.cpp.o \
  ../build/controlplane/yanet-controlplane.p/configparser.cpp.o \
  ../build/controlplane/yanet-controlplane.p/controlplane.cpp.o \
  ../build/controlplane/yanet-controlplane.p/dregress.cpp.o \
  ../build/controlplane/yanet-controlplane.p/durations.cpp.o \
  ../build/controlplane/yanet-controlplane.p/fqdn.cpp.o \
  ../build/controlplane/yanet-controlplane.p/isystem.cpp.o \
  ../build/controlplane/yanet-controlplane.p/memory_manager.cpp.o \
  ../build/controlplane/yanet-controlplane.p/module.cpp.o \
  ../build/controlplane/yanet-controlplane.p/nat46clat.cpp.o \
  ../build/controlplane/yanet-controlplane.p/nat64stateful.cpp.o \
  ../build/controlplane/yanet-controlplane.p/protobus.cpp.o \
  ../build/controlplane/yanet-controlplane.p/rib.cpp.o \
  ../build/controlplane/yanet-controlplane.p/route.cpp.o \
  ../build/controlplane/yanet-controlplane.p/telegraf.cpp.o \
  ../build/controlplane/yanet-controlplane.p/tun64.cpp.o \
  ../build/controlplane/yanet-controlplane.p/meson-generated_.._.._libfwparser_fw_parser.cpp.o \
  ../build/controlplane/yanet-controlplane.p/meson-generated_.._.._libfwparser_token.cpp.o \
  ../build/controlplane/yanet-controlplane.p/meson-generated_.._.._libprotobuf_controlplane.pb.cc.o \
  ../build/controlplane/yanet-controlplane.p/meson-generated_.._.._libprotobuf_meta.pb.cc.o

TARGET = unwind

all: $(TARGET)

$(TARGET): unwind.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(CONTROLPLANE_OBJS) $(FWPARSER_LIB) -lprotobuf

clean:
	rm -f $(TARGET)
