#ifndef _MKTESTCASE_H
#define _MKTESTCASE_H

#include "libbb_udhcp.h"
#include "clientpacket.h"
#include "dhcpc.h"

#define INIT_SELECTING	0
#define REQUESTING	1
#define BOUND		2
#define RENEWING	3
#define REBINDING	4
#define INIT_REBOOT	5
#define RENEW_REQUESTED 6
#define RELEASED	7


struct client_config_t {
	char foreground;		/* Do not fork */
	char quit_after_lease;		/* Quit after obtaining lease */
	char abort_if_no_lease;		/* Abort if no lease */
	char background_if_no_lease;	/* Fork to background if no lease */
	char *interface;		/* The name of the interface to use */
	char *pidfile;			/* Optionally store the process ID */
	char *script;			/* User script to run at dhcp events */
	unsigned char *clientid;	/* Optional client id to use */
	unsigned char *hostname;	/* Optional hostname to use */
	int ifindex;			/* Index number of the interface to use */
	unsigned char arp[6];		/* Our arp address */
};

extern struct client_config_t client_config;

static void init_packet_long_vendor_str(struct dhcpMessage *packet, char type, unsigned int fuzz_length);
static void add_custom_vendor_id(struct dhcpMessage *packet, char *vendor_str, unsigned int str_length);
static void init_packet_fuzz(struct dhcpMessage *packet, char type, char *vendor_str);
static void add_requests_fz(struct dhcpMessage *packet);
static void make_discover(struct dhcpMessage *packet, unsigned long xid, unsigned long requested);
static void make_selecting(struct dhcpMessage *packet, unsigned long xid, unsigned long server, unsigned long requested);
static void make_renew(struct dhcpMessage *packet, unsigned long xid, unsigned long server, unsigned long ciaddr);
static void make_release(struct dhcpMessage *packet, unsigned long server, unsigned long ciaddr);
static void create_fuzz_client_config(char *hostname, char *interface, char *client_id);
int write_packet_to_testcase_file(struct dhcpMessage *packet, char *type_prefix);

#endif
