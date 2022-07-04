#include <string.h>
#include <sys/socket.h>
#include <features.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "dhcpd.h"
#include "packet.h"
#include "options.h"
#include "dhcpc.h"
#include "debug.h"
#include "clientpacket.h"

static int state;
static unsigned long requested_ip; /* = 0 */
static unsigned long server_addr;
static unsigned long timeout;
static int packet_num; /* = 0 */
static int fd;
static int signal_pipe[2];

#define LISTEN_NONE 0
#define LISTEN_KERNEL 1
#define LISTEN_RAW 2
static int listen_mode;

#define DEFAULT_SCRIPT	"/usr/share/udhcpc/default.script"

 struct client_config_t client_config = {
 	/* Default options. */
 	abort_if_no_lease: 0,
 	foreground: 0,
 	quit_after_lease: 0,
 	background_if_no_lease: 0,
 	interface: "eth0",
 	pidfile: NULL,
 	script: DEFAULT_SCRIPT,
 	clientid: NULL,
 	hostname: NULL,
 	ifindex: 0,
 	arp: "\0\0\0\0\0\0",		/* appease gcc-3.0 */
 };

/* Exit and cleanup */
static void exit_client(int retval)
{
	pidfile_delete(client_config.pidfile);
	CLOSE_LOG();
	exit(retval);
}


static void init_packet_long_vendor_str(struct dhcpMessage *packet, char type, unsigned int fuzz_length)
{
	struct vendor  {
		char vendor, length;
		char str[sizeof("udhcp")];
	} vendor_id = { DHCP_VENDOR,  (sizeof("A") * fuzz_length) - 1, "udhcp"};
	
	init_header(packet, type);
	memcpy(packet->chaddr, client_config.arp, 6);
	add_option_string(packet->options, client_config.clientid);
	if (client_config.hostname) add_option_string(packet->options, client_config.hostname);
	add_option_string(packet->options, (unsigned char *) &vendor_id);
}

static void add_custom_vendor_id(struct dhcpMessage *packet, char *vendor_str, unsigned int fuzz_length)
{
	struct vendor  {
		char vendor, length;
		char str[sizeof(vendor_str)];
	} vendor_id = { DHCP_VENDOR,  (fuzz_length) - 1, vendor_str};
	add_option_string(packet->options, (unsigned char *) &vendor_id);
}

/* initialize a packet with the proper defaults */
static void init_packet_fuzz(struct dhcpMessage *packet, char type)
{
	struct vendor  {
		char vendor, length;
		char str[sizeof("udhcp "VERSION)];
	} vendor_id = { DHCP_VENDOR,  sizeof("udhcp "VERSION) - 1, "udhcp "VERSION};
	
	init_header(packet, type);
	memcpy(packet->chaddr, client_config.arp, 6);
	add_option_string(packet->options, client_config.clientid);
	if (client_config.hostname) add_option_string(packet->options, client_config.hostname);
	add_option_string(packet->options, (unsigned char *) &vendor_id);
}


/* Add a paramater request list for stubborn DHCP servers. Pull the data
 * from the struct in options.c. Don't do bounds checking here because it
 * goes towards the head of the packet. */
static void add_requests_fz(struct dhcpMessage *packet)
{
	printf("debug - add_request_fz\n");
	int end = end_option(packet->options);
	int i, len = 0;

	packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
	for (i = 0; options[i].code; i++)
		if (options[i].flags & OPTION_REQ)
			packet->options[end + OPT_DATA + len++] = options[i].code;
	packet->options[end + OPT_LEN] = len;
	packet->options[end + OPT_DATA + len] = DHCP_END;
}


/* Broadcast a DHCP discover packet to the network, with an optionally requested IP */
static void make_discover(struct dhcpMessage *packet, unsigned long xid, unsigned long requested)
{

	printf("debug - discover start\n");
	init_packet_fuzz(packet, DHCPDISCOVER);
	printf("debug - finished init\n");
	packet->xid = xid;
	if (requested)
		printf("requested met\n");
		add_simple_option(packet->options, DHCP_REQUESTED_IP, requested);

	add_requests_fz(packet);
	printf("debug - add_req finished\n");
}

/* Broadcasts a DHCP request message */
static void make_selecting(struct dhcpMessage *packet, unsigned long xid, unsigned long server, unsigned long requested)
{
	
	init_packet_fuzz(packet, DHCPREQUEST);
	packet->xid = xid;

	add_simple_option(packet->options, DHCP_REQUESTED_IP, requested);
	add_simple_option(packet->options, DHCP_SERVER_ID, server);
	
	add_requests_fz(packet);
}


/* Unicasts or broadcasts a DHCP renew message */
static void make_renew(struct dhcpMessage *packet, unsigned long xid, unsigned long server, unsigned long ciaddr)
{
	init_packet_fuzz(packet, DHCPREQUEST);
	packet->xid = xid;
	packet->ciaddr = ciaddr;
	add_requests_fz(packet);
}	


/* Unicasts a DHCP release message */
static void make_release(struct dhcpMessage *packet, unsigned long server, unsigned long ciaddr)
{
	init_packet_fuzz(packet, DHCPRELEASE);
	packet->xid = random_xid();
	packet->ciaddr = ciaddr;
	
	add_simple_option(packet->options, DHCP_REQUESTED_IP, ciaddr);
	add_simple_option(packet->options, DHCP_SERVER_ID, server);
}


static void create_fuzz_client_config(char *hostname, char *interface, char *client_id)
{
    int len = strlen(client_id) > 255 ? 255 : strlen(client_id);
    if (client_config.clientid) free(client_config.clientid);
    client_config.clientid = xmalloc(len + 2);
    client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
    client_config.clientid[OPT_LEN] = len;
    client_config.clientid[OPT_DATA] = '\0';
    strncpy(client_config.clientid + OPT_DATA, client_id, len);

    len = 0;
    len = strlen(hostname) > 255 ? 255 : strlen(hostname);
    if (client_config.hostname) free(client_config.hostname);
    client_config.hostname = xmalloc(len + 2);
    client_config.hostname[OPT_CODE] = DHCP_HOST_NAME;
    client_config.hostname[OPT_LEN] = len;
    strncpy(client_config.hostname + 2, hostname, len);

    client_config.interface = interface;


}

int write_packet_to_testcase_file(struct dhcpMessage *packet, char *type_prefix) {
    FILE *fd;
    char *outname = (char *) malloc(24 * sizeof(char));
    sprintf(outname, "./%s_%ld", type_prefix, time(0));
    fd = fopen(outname, "wb");
    int res = fwrite(&packet, sizeof(struct dhcpMessage), 1, fd);
    printf("wrote packet data to file: '%s'\n", outname);
    fclose(fd); 
    free(outname);
    return res;
}

int main() {
	unsigned char *temp, *message;
	unsigned long t1 = 0, t2 = 0, xid = 0;
	unsigned long start = 0, lease;
	int retval;
	struct timeval tv;
	int c, len;
	struct dhcpMessage packet;
	struct in_addr temp_addr;
	int pid_fd;
	time_t now;

    create_fuzz_client_config("HOSTNAME0HYPER", "eth0", "CLIENTID0HYPER");

	if (read_interface(client_config.interface, &client_config.ifindex, 
			   NULL, client_config.arp) < 0)
		exit_client(1);
		
	if (!client_config.clientid) {
		client_config.clientid = xmalloc(6 + 3);
		client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
		client_config.clientid[OPT_LEN] = 7;
		client_config.clientid[OPT_DATA] = 1;
		memcpy(client_config.clientid + 3, client_config.arp, 6);
	}

	// normal discover
	struct dhcpMessage discover_1;
    printf("[+] creating testcase: discover 1\n");
    make_discover(&discover_1, random_xid(), requested_ip);
    write_packet_to_testcase_file(&discover_1, "discover_1");

	// discover with long vendor_id
	struct dhcpMessage discover_long_vendor;
    printf("[+] creating testcase: discover long\n");
    init_packet_long_vendor_str(&discover_long_vendor, DHCPDISCOVER, 255);
    write_packet_to_testcase_file(&discover_long_vendor, "discover_long");

	// discover with tweaked vendor_id
	struct dhcpMessage discover_mut;
    printf("[+] creating testcase: discover custom vendor\n");
    make_discover(&discover_long_vendor, random_xid(), requested_ip);
    add_custom_vendor_id(&discover_mut, "AAAAAAAAAAAAAAAA", 40);
    write_packet_to_testcase_file(&discover_mut, "discover_cvendor");

	// mess with the configured hostname
    char fuzzy_hostname[255];
    memset(fuzzy_hostname, 0x41, sizeof(fuzzy_hostname));
    if (client_config.hostname) free(client_config.hostname);
    client_config.hostname = xmalloc(len + 2);
    client_config.hostname[OPT_CODE] = DHCP_HOST_NAME;
    client_config.hostname[OPT_LEN] = len;
    strncpy(client_config.hostname + 2, fuzzy_hostname, strlen(fuzzy_hostname));
    printf("[+] creating testcase: discover hostname\n");
	struct dhcpMessage discover_2;
    make_discover(&discover_2, random_xid(), requested_ip);
    write_packet_to_testcase_file(&discover_2, "discover_2");

	// normal request
	struct dhcpMessage request_1;
    printf("[+] creating testcase: request 1\n");
    make_selecting(&request_1, random_xid(), inet_addr("172.17.0.2"), requested_ip);
    write_packet_to_testcase_file(&request_1, "request");

	// request with tweaked clientid len
	struct dhcpMessage request_2;
    printf("[+] creating testcase: request long clientid\n");
    client_config.clientid[OPT_LEN] = client_config.clientid[OPT_LEN] * 4;
    make_selecting(&request_2, random_xid(), inet_addr("172.17.0.2"), requested_ip);
    write_packet_to_testcase_file(&request_2, "request_cid_mod4");

	// request with tweaked clientid len
    memset(&request_2, 0, sizeof(struct dhcpMessage));
    printf("[+] creating testcase: request long clientid 2\n");
    client_config.clientid[OPT_LEN] = client_config.clientid[OPT_LEN] * 32;
    make_selecting(&request_2, random_xid(), inet_addr("172.17.0.2"), requested_ip);
    write_packet_to_testcase_file(&request_2, "request_cid_mod32");

    printf("DONE\n");
    exit_client(1);
	return 1;
}

