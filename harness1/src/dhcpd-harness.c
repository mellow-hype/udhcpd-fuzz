/* dhcpd.c
 *
 * udhcp Server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>

#include "debug.h"
#include "dhcpd.h"
#include "arpping.h"
#include "socket.h"
#include "options.h"
#include "files.h"
#include "leases.h"
#include "packet.h"
#include "serverpacket.h"
#include "pidfile.h"

/* this lets the source compile without afl-clang-fast/lto */
#ifndef __AFL_FUZZ_TESTCASE_LEN

ssize_t       fuzz_len;
unsigned char fuzz_buf[1024000];

  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) \
	    ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()

#endif

__AFL_FUZZ_INIT();

/* To ensure checks are not optimized out it is recommended to disable
 *    code optimization for the fuzzer harness main() */
#pragma clang optimize off
#pragma GCC            optimize("O0")


/* globals */
struct dhcpOfferedAddr *leases;
struct server_config_t server_config;
static int signal_pipe[2];
extern unsigned char g_src_addr[6];


/* Exit and cleanup */
static void exit_server(int retval)
{
	pidfile_delete(server_config.pidfile);
	CLOSE_LOG();
	exit(retval);
}

static char *ether_etoa(char *e, char *a)
{
	static char hexbuf[] = "0123456789ABCDEF";

	int i, k;

	for (k = 0, i = 0; i < 6; i++) {
		a[k++] = hexbuf[(e[i] >> 4) & 0xF];
		a[k++] = hexbuf[(e[i]) & 0xF];
		a[k++]=':';
	}

	a[--k] = 0;

	return a;
}

/* Signal handler */
static void signal_handler(int sig)
{
	if (send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT) < 0) {
		LOG(LOG_ERR, "Could not send signal: %s", 
			strerror(errno));
	}
}


int main(int argc, char *argv[])
{	
	fd_set rfds;
	struct timeval tv;
	int server_socket = -1;
	int bytes, retval;
	struct dhcpMessage packet;
	unsigned char *state;
	unsigned char *server_id, *requested;
	u_int32_t server_id_align, requested_align;
	unsigned long timeout_end;
	struct option_set *option;
	struct dhcpOfferedAddr *lease;
	int pid_fd;
	int max_sock;
	int sig;

	OPEN_LOG("udhcpd");
	// initialize config from file
	memset(&server_config, 0, sizeof(struct server_config_t));
	read_config("./test-udhcpd.conf");

	pid_fd = pidfile_acquire(server_config.pidfile);
	pidfile_write_release(pid_fd);

	// set dhcp lease time
	if ((option = find_option(server_config.options, DHCP_LEASE_TIME))) {
		memcpy(&server_config.lease, option->data + 2, 4);
		server_config.lease = ntohl(server_config.lease);
	}
	else server_config.lease = LEASE_TIME;
	
	// malloc memory for leases and read from lease file
	leases = malloc(sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	memset(leases, 0, sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	read_leases(server_config.lease_file);

	// make sure we can read the server interface defined in config
	if (read_interface(server_config.interface, &server_config.ifindex,
			   &server_config.server, server_config.arp) < 0)
		return 1;

	// START AFL LOOP
// #ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
// #endif
	unsigned char *aflbuf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(10000000)) {
		// Reset leases values at the start of each run (memory is still malloc'd)
		memset(leases, 0, sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
		read_leases(server_config.lease_file);

		// Check size is sane
		ssize_t afllen = __AFL_FUZZ_TESTCASE_LEN;
		if (afllen > sizeof(struct dhcpMessage)) continue;

		// Copy testcase data to dhcpMessage struct
		struct dhcpMessage fuzz_packet;
		memset(&fuzz_packet, 0, sizeof(struct dhcpMessage));
		memcpy(&fuzz_packet, aflbuf, sizeof(struct dhcpMessage));

		// Bail to next run if we got an invalid message type
		if ((state = get_option(&fuzz_packet, DHCP_MESSAGE_TYPE)) == NULL) {
			continue;
		}

		lease = find_lease_by_chaddr(fuzz_packet.chaddr);
		switch (state[0]) {
			case DHCPDISCOVER:
				if (sendOffer(&fuzz_packet) < 0) {
					printf("send OFFER failed");
				}
				// exit_server(0);
				// return 0;
				break;
			case DHCPREQUEST:

				requested = get_option(&fuzz_packet, DHCP_REQUESTED_IP);
				server_id = get_option(&fuzz_packet, DHCP_SERVER_ID);

				if (requested) memcpy(&requested_align, requested, 4);
				if (server_id) memcpy(&server_id_align, server_id, 4);
				// break;
				// return 0;
				if (lease) { /*ADDME: or static lease */
					if (server_id) {
						/* SELECTING State */
						DEBUG(LOG_INFO, "server_id = %08x", ntohl(server_id_align));
						if (server_id_align == server_config.server && requested && 
							requested_align == lease->yiaddr) {
							sendACK(&fuzz_packet, lease->yiaddr);
						}
					} else {
						if (requested) {
							/* INIT-REBOOT State */
							if (lease->yiaddr == requested_align)
								sendACK(&fuzz_packet, lease->yiaddr);
							else sendNAK(&fuzz_packet);
						} else {
							/* RENEWING or REBINDING State */
							if (lease->yiaddr == fuzz_packet.ciaddr)
								sendACK(&fuzz_packet, lease->yiaddr);
							else {
								/* don't know what to do!!!! */
								sendNAK(&fuzz_packet);
							}
						}						
					}
			
				/* what to do if we have no record of the client */
				} 
				else if (server_id) {
					/* SELECTING State */

				} else if (requested) {
					/* INIT-REBOOT State */
					if ((lease = find_lease_by_yiaddr(requested_align))) {
						if (lease_expired(lease)) {
							/* probably best if we drop this lease */
							memset(lease->chaddr, 0, 16);
						/* make some contention for this address */
						} else sendNAK(&fuzz_packet);
					} else if (requested_align < server_config.start || 
						requested_align > server_config.end) {
						sendNAK(&fuzz_packet);
					} /* else remain silent */

				} else {
					/* RENEWING or REBINDING State */
				}
				// exit_server(0);
				break;
				// return 0;
				// continue;
			default:
				LOG(LOG_WARNING, "unsupported DHCP message (%02x) -- ignoring", state[0]);
				continue;
		}
	}
	// exit_server(0);
	return 0;
}

