
MAINDIR=../../../../microbenchmarks
X86INSTALLDIR=$(MAINDIR)/protobuf-x86-install
RISCVINSTALLDIR=$(MAINDIR)/protobuf-riscv-install

HOST_GCC_INSTALL=$(MAINDIR)/host-gcc-install

PROTOC = $(X86INSTALLDIR)/bin/protoc
RVCPP = riscv64-unknown-linux-gnu-g++
RVSTRIP = riscv64-unknown-linux-gnu-strip
X86CPP = $(HOST_GCC_INSTALL)/bin/g++
X86STRIP = strip

# CPPFLAGS = -std=c++11 -O3 -g3 -D NDEBUG
# CPPFLAGS = -std=c++11 -O3 -static
# CPPFLAGS = -std=c++11 -g -static
CPPFLAGS = -std=c++11 -O3 -g3 -lpthread -D NDEBUG  -lrt

objectsx86 = benchmark.o.x86 benchmark.pb.o.x86 accellib.o.x86 vfio.o.x86
objectsriscv = benchmark.o.riscv benchmark.pb.o.riscv accellib.o.riscv

all: benchmark.x86

benchmark.pb.cc: benchmark.proto
	LD_LIBRARY_PATH=$(HOST_GCC_INSTALL)/lib64:$$LD_LIBRARY_PATH && $(PROTOC) $< --cpp_out=.

%.o.riscv : %.cc benchmark.pb.cc benchmark.inc
	$(RVCPP) $(CPPFLAGS) -I $(RISCVINSTALLDIR)/include -pthread -c $< -o $@

%.o.x86 : %.cc benchmark.pb.cc benchmark.inc.x86
	$(X86CPP) $(CPPFLAGS) -I $(X86INSTALLDIR)/include -pthread -c $< -o $@

benchmark.x86: $(objectsx86)
	$(X86CPP) $(CPPFLAGS)  $(objectsx86) -o $@ -pthread $(X86INSTALLDIR)/lib/libprotobuf.a
	# $(X86STRIP) $@

benchmark.riscv: $(objectsriscv)
	$(RVCPP) $(CPPFLAGS)  $(objectsriscv) -o $@ -pthread $(RISCVINSTALLDIR)/lib/libprotobuf.a
	$(RVSTRIP) $@

clean:
	rm benchmark.x86 benchmark.riscv $(objectsx86) $(objectsriscv) benchmark.pb.cc benchmark.pb.h
