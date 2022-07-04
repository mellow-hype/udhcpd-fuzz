# udhcp makefile

# Uncomment this for extra output and to compile with debugging symbols
DEBUG=1

# Uncomment this to output messages to syslog, otherwise, messages go to stdout
CFLAGS += -DSYSLOG

CC = gcc
LD = gcc
INSTALL = install

VER := 0.9.8

OBJS_SHARED = options.o socket.o packet.o pidfile.o
DHCPD_OBJS = dhcpd.o arpping.o files.o leases.o serverpacket.o
DHCPC_OBJS = dhcpc.o clientpacket.o script.o
DHCPC_OBJS2 = mk-testcases.o clientpacket.o script.o

EXEC1 = udhcpc
OBJS1 = $(DHCPC_OBJS) $(OBJS_SHARED)

EXEC2 = mk-testcases
OBJS2 = $(DHCPC_OBJS2) $(OBJS_SHARED)


BOOT_PROGRAMS = udhcpc
DAEMONS = udhcpd
COMMANDS = dumpleases

ifdef SYSLOG
CFLAGS += -DSYSLOG
endif

CFLAGS += -W -Wall -Wstrict-prototypes -DVERSION='"$(VER)"'

ifdef DEBUG
CFLAGS += -g -DDEBUG
STRIP=true
else
CFLAGS += -Os -fomit-frame-pointer
STRIP=$(CROSS_COMPILE)strip
endif

all: $(EXEC1) $(EXEC2)
	$(STRIP) --remove-section=.note --remove-section=.comment $(EXEC1) $(EXEC2)

$(OBJS1) $(OBJS2): *.h Makefile
$(EXEC1) $(EXEC2): Makefile

.c.o:
	$(CC) -c $(CFLAGS) $<
	
$(EXEC1): $(OBJS1)
	$(LD) $(LDFLAGS) $(OBJS1) -o $(EXEC1)

$(EXEC2): $(OBJS2)
	$(LD) $(LDFLAGS) $(OBJS2) -o $(EXEC2)

clean:
	-rm -f udhcpc mk-testcases dumpleases *.o core

