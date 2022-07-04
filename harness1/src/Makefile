# udhcp makefile
BINDIR=$(realpath $(CURDIR)/../bin)

# Uncomment this for extra output and to compile with debugging symbols
DEBUG=1

# Uncomment this to output messages to syslog, otherwise, messages go to stdout
CFLAGS += -DSYSLOG

ifdef CC
LD = $(CC)
else
CC = afl-clang-fast
LD = afl-clang-fast
endif

VER := 0.9.8

OBJS_SHARED = options.o socket.o packet.o pidfile.o
DHCPD_OBJS = dhcpd.o arpping.o files.o leases.o serverpacket.o
DHCPC_OBJS = dhcpc.o clientpacket.o script.o

# objects for custom fuzzing binaries
FUZZ_DHCPD_OBJS = dhcpd-harness.o arpping.o files.o leases.o serverpacket.o
FUZZ_DHCPD_OBJS2 = dhcpd-mkt.o arpping.o files.o leases.o serverpacket.o
FUZZ_DHCPD_OBJS3 = dhcpd-repro.o arpping.o files.o leases.o serverpacket.o

EXEC1 = udhcpd
OBJS1 = $(DHCPD_OBJS) $(OBJS_SHARED)

EXEC2 = udhcpd-harness
OBJS2 = $(FUZZ_DHCPD_OBJS) $(OBJS_SHARED)

EXEC3 = udhcpd-mktestcase
OBJS3 = $(FUZZ_DHCPD_OBJS2) $(OBJS_SHARED)

EXEC4 = udhcpd-repro
OBJS4 = $(FUZZ_DHCPD_OBJS3) $(OBJS_SHARED)

ifdef SYSLOG
CFLAGS += -DSYSLOG
endif

ifdef AFL_USE_ASAN
ASAN_SUFFIX := _asan
EXEC1 = udhcpd$(ASAN_SUFFIX)
EXEC2 = udhcpd-harness$(ASAN_SUFFIX)
EXEC3 = udhcpd-mktestcase$(ASAN_SUFFIX)
EXEC4 = udhcpd-repro$(ASAN_SUFFIX)
LDFLAGS += 
CFLAGS += -W -Wall -Wstrict-prototypes -DVERSION='"$(VER)"'
else
ASAN_SUFFIX = 
LDFLAGS += -static
CFLAGS += -static -W -Wall -Wstrict-prototypes -DVERSION='"$(VER)"'
endif

FUZZ_BINS = $(EXEC1) $(EXEC2) $(EXEC3) $(EXEC4)

ifdef DEBUG
CFLAGS += -g -DDEBUG
STRIP=true
else
CFLAGS += -Os -fomit-frame-pointer
STRIP=$(CROSS_COMPILE)strip
endif

INSTALL = cp

all: $(EXEC1) $(EXEC2) $(EXEC3) $(EXEC4)
	$(STRIP) --remove-section=.note --remove-section=.comment $(EXEC1) $(EXEC2) $(EXEC3) $(EXEC4)

$(OBJS1) $(OBJS2) $(OBJS3) $(OBJS4): *.h Makefile
$(EXEC1) $(EXEC2) $(EXEC3) $(EXEC4): Makefile

.c.o:
	$(CC) -c $(CFLAGS) $<
	
$(EXEC1): $(OBJS1)
	$(LD) $(LDFLAGS) $(OBJS1) -o $(EXEC1)

$(EXEC2): $(OBJS2)
	$(LD) $(LDFLAGS) $(OBJS2) -o $(EXEC2)

$(EXEC3): $(OBJS3)
	$(LD) $(LDFLAGS) $(OBJS3) -o $(EXEC3)

$(EXEC4): $(OBJS4)
	$(LD) $(LDFLAGS) $(OBJS4) -o $(EXEC4)

install: all

	$(INSTALL) $(FUZZ_BINS) $(BINDIR)

clean:
	-rm -f $(FUZZ_BINS) dumpleases *.o core
	-rm -f $(EXEC1)_asan $(EXEC2)_asan $(EXEC3)_asan $(EXEC4)_asan

