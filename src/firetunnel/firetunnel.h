/*
 * Copyright (C) 2018 Firetunnel Authors
 *
 * This file is part of firetunnel project
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifndef OVERLAY_H
#define OVERLAY_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <net/if.h>

#define errExit(msg)    do { char msgout[500]; sprintf(msgout, "Error %s: %s:%d %s", msg, __FILE__, __LINE__, __FUNCTION__); perror(msgout); exit(1);} while (0)

// macro to print ip addresses in a printf statement
#define PRINT_IP(A) \
	((int) (((A) >> 24) & 0xFF)),  ((int) (((A) >> 16) & 0xFF)), ((int) (((A) >> 8) & 0xFF)), ((int) ( (A) & 0xFF))

// macro to print a mac addresses in a printf statement
#define PRINT_MAC(A) \
	((unsigned) (*(A)) & 0xff), ((unsigned) (*((A) + 1) & 0xff)), ((unsigned) (*((A) + 2) & 0xff)), \
	((unsigned) (*((A) + 3)) & 0xff), ((unsigned) (*((A) + 4) & 0xff)), ((unsigned) (*((A) + 5)) & 0xff)

// read an IPv4 address and convert it to uint32_t (host format)
inline static int atoip(const char *str, uint32_t *ip) {
	unsigned a, b, c, d;

	if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
		return 1;

	*ip = a * 0x1000000 + b * 0x10000 + c * 0x100 + d;
	return 0;
}

// the number of bits in a network mask
static inline uint8_t mask2bits(uint32_t mask) {
	uint32_t tmp = 0x80000000;
	int i;
	uint8_t rv = 0;

	for (i = 0; i < 32; i++, tmp >>= 1) {
		if (tmp & mask)
			rv++;
		else
			break;
	}
	return rv;
}

static inline uint32_t diff_uint32(uint32_t val1, uint32_t val2) {
	uint32_t a;
	uint32_t b;
	if (val1 > val2) {
		a = val1;
		b = val2;
	}
	else {
		a = val2;
		b = val1;
	}

	uint32_t delta1 = a - b;
	uint32_t delta2 = 0xffffffff - a + b;
	if (delta1 < delta2)
		return delta1;
	return delta2;
}

static inline void dbg_memory(void *ptr, int len) {
	const uint8_t *ptr2 = (uint8_t *) ptr;
	int i;
	for ( i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%04x: ", i);
		if ((i + 8) % 16 == 0)
			printf("- ");
		printf("%02x ", ptr2[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

extern int arg_debug;
extern int arg_debug_compress;
static inline void dbg_printf(char *fmt, ...) {
	if (!arg_debug)
		return;

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}


//****************************************************
// Packet format
//****************************************************
// Connection
// - the session is connected on the first HELLO message received
// - sending HELLO messages every TIMEOUT seconds
//       This is relevant for NAT traversal. By default NAT mapping expiration
//       time is 30 seconds for UDP on Linux:
//       $ cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout
//       30
// - if we don't receive CONNECT_TTL HELLO messages in a row, we disconnect the session
//       The current disconnect time is TIMEOUT * CONNECT_TTL
#define TIMEOUT  10	// timeout in seconds for hello message retransmission, select loop etc.
#define CONNECT_TTL 3	// the connection is dropped if we are missing this many HELLO packets

// Timestamp
// - time since Epoch, as returned by time() function
// - the server and the client must have the time synchronized
// - a drift of TIMESTAMP_DELTA_MAX is acceptable; this should also cover the packet trip
#define TIMESTAMP_DELTA_MAX (TIMEOUT) // client/server maximum timestamp delta for accepting packets

// BLAKE2 configuration
#define SECRET_FILE (SYSCONFDIR "/firetunnel.secret")	// use this file to generate a huge (KEY_MAX) list of keys
#define KEY_LEN 16		// BLAKE2-128 (16 byte key/result)
// this is equivalent to a regular HMAC-MD5/HMAC-SHA1, but faster and  cryptographically stronger
#define KEY_MAX 8192	// maximum number of keys  in the list

// udp packet structure:    | ip/udp transport | tunnel header | Ethernet frame | padding | BLACKE2 hash (16/32/64 bytes) |
typedef struct packet_header_t {
// opcode
#define O_HELLO 0
#define O_MESSAGE 1
#define O_DATA  2
#define O_DATA_COMPRESSED_L2  3
#define O_DATA_COMPRESSED_L3  4
#define O_DATA_COMPRESSED_L4  5
#define O_MAX 6 // the last one

// flags
#define F_SYNC 1 	//  a node in disconnected state sends this flag in hello packet;
		// the node receiving this flag set clear its compression table

#if BYTE_ORDER == BIG_ENDIAN
	uint8_t opcode: 4;
	uint8_t flags: 4;
#elif BYTE_ORDER == LITTLE_ENDIAN
	uint8_t flags: 4;
	uint8_t opcode: 4;
#endif

	uint8_t sid;		// header compression session id  for opcode O_DATA_COMPRESSED_L2 or O_DATA_COMPRESSED_L3
			// the sid is the hash value for the Connection array

	uint16_t seq;	// packet sequence number
			// - it is incremented every time a packet is sent
			// - it is reseted when the session is disconnected

	uint32_t timestamp;	// epoch timestamp
} __attribute__((__packed__)) PacketHeader;	// 8 bytes

typedef struct udp_frame_t {
	PacketHeader header;	// 8 bytes
	uint8_t eth[2000];	// enough room to fit a 1500 eth packet in
} UdpFrame;

typedef struct packet_mem_t {
	uint32_t header_expansion[32];
	UdpFrame f;
} PacketMem;



//****************************************************
// Tunnel structure
//****************************************************
typedef enum connection_state_t {
	S_DISCONNECTED,
	S_CONNECTED,
} ConnectionState;

// tunnel statistics
typedef struct tstats_t {
	unsigned udp_tx_pkt;
	unsigned udp_rx_pkt;
	unsigned udp_rx_drop_pkt;
	unsigned udp_rx_drop_timestamp_pkt;
	unsigned udp_rx_drop_seq_pkt;
	unsigned udp_rx_drop_addr_pkt;
	unsigned udp_rx_drop_blake2_pkt;
	unsigned eth_rx_dns;
	unsigned eth_rx_arp;

	// header compression
	unsigned compress_hash_total_l2; // total number of entries ever sotred in the table
	unsigned compress_hash_collision_l2; // total number of collisions
	unsigned compress_hash_cnt_l2;	// current number of active entries in the hash table

	unsigned compress_hash_total_l3;
	unsigned compress_hash_collision_l3;
	unsigned compress_hash_cnt_l3;

	unsigned compress_hash_total_l4;
	unsigned compress_hash_collision_l4;
	unsigned compress_hash_cnt_l4;

	unsigned udp_tx_compressed_pkt;
} TStats;

static inline float collision_ratio(unsigned total, unsigned collisions) {
	if (total == 0)
		return 0;
	return ((float) collisions / (float) total) * 100;
}


typedef struct toverlay_t {
	uint32_t netaddr;	// network address - default 10.10.20.0
	uint32_t netmask;	// network mask - default 255.255.255.0
	uint32_t defaultgw;	// default gateway - default 10.10.20.1
	uint32_t mtu;
	uint32_t dns1;
	uint32_t dns2;
	uint32_t dns3;
} TOverlay;

typedef struct tunnel_t {
	// descriptors etc.
	int udpfd;
	int tapfd;
	char tap_device_name[IFNAMSIZ + 1];
	char bridge_device_name[IFNAMSIZ + 1];

	// connection
	ConnectionState state;
	int connect_ttl;
	struct sockaddr_in remote_sock_addr;
	uint16_t seq;

	// network overlay - the configuration takes place on the server side
	TOverlay overlay;

	// tunnel statistics
	TStats stats;
} Tunnel;

inline static void reset_stats(Tunnel *t) {
	memset(&t->stats, 0, sizeof(TStats));
}


// main.c
#define RUN_DIR "/run/firetunnel"
#define RUN_DIR_CHROOT (RUN_DIR "/chroot")
#define RUN_DEV_DIR (RUN_DIR "/chroot/dev")
#define RUN_DEVLOG_FILE (RUN_DIR "/chroot/dev/log")
#define DEFAULT_PROFILE (SYSCONFDIR "/default.profile")

extern int have_syslog;
extern Tunnel tunnel;
extern int arg_server;		// run this tunnel end as a server
#define DEFAULT_PORT_NUMBER 1119 // This is the port number for battle.net Blizzard's chat/game protocol
extern int arg_port;		// server UDP port; configured on both client and server
extern uint32_t arg_remote_addr;	// server UDP address; only configured on the client side of the tunnel
extern int arg_noscrambling;	// no scrambling
extern int arg_nonat;		// no NAT
extern int arg_daemonize;	// run as a daemon
extern int arg_noseccomp;

// packet.c
static inline int pkt_is_ipv6(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame
	if (nbytes < (14 + 40))	// mac + ipv6 header
		return 0;
	if (*(pkt + 12) == 0x86 && *(pkt + 13) == 0xdd) // ipv6 protocol in eth header
		return 1;
	return 0;
}

static inline int pkt_is_arp(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame
	if (nbytes != (14 + 28))	// mac + arp
		return 0;
	if (*(pkt + 12) == 0x08 && *(pkt + 13) == 0x06) // arp protocol in eth header
		return 1;
	return 0;
}

static inline int pkt_is_ip(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame
	if (nbytes <= 14)	// mac
		return 0;
	if (*(pkt + 12) == 0x08 && *(pkt + 13) == 0x00) // ip protocol in eth header
		return 1;
	return 0;
}
static inline int pkt_is_dns(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame
	if (nbytes < (14 + 20 + 8 + 12)) // mac + ip + udp + dns
		return 0;
	if (*(pkt + 12) == 0x08 && *(pkt + 13) == 0 && // ip protocol
	    * (pkt + 23) == 0x11 && // udp protocol
	    ((*(pkt + 34) == 0 && *(pkt + 35) == 0x35) || (*(pkt + 36) == 0 && *(pkt + 37) == 0x35))) // dns port
		return 1;

	return 0;
}


static inline int pkt_is_dns_AAAA(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame

	if (nbytes < (14 + 20 + 8 + 12 + 1)) // mac + ip + udp + dns + 1 byte dns queries
		return 0;
	if (*(pkt + 12) == 0x08 && *(pkt + 13) == 0 && // ip protocol
	    * (pkt + 23) == 0x11 && // udp protocol
	    ((*(pkt + 34) == 0 && *(pkt + 35) == 0x35) || (*(pkt + 36) == 0 && *(pkt + 37) == 0x35)) && // dns port
	    ((*(pkt + 45) & 0x80) == 0)) { // DNS query
	    	uint8_t *ptr = pkt + 54;
	    	int sz = 54;
	    	int i;
	    	for (i = 0; i < 4; i++) {
	    		if (*ptr == 0)
	    			break;
	    		sz += *ptr + 1;
	    		if (nbytes < sz)
	    			return 0;
	    		ptr += *ptr + 1;
	    	}

	    	if (*ptr != 0 || nbytes < (sz + 2))
	    		return 0;
	    	if (*(ptr + 1) == 0 && *(ptr + 2) == 0x1c)
	    		return 1;

	    	return 0;
	}

	return 0;
}


static inline int pkt_is_tcp(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame
	if (nbytes < (14 + 20 + 20))	// mac + ip  + tcp
		return 0;
	if (*(pkt + 12) == 0x08 && *(pkt + 13) == 0 && // ip protocol
	    * (pkt + 23) == 6) // tcp
		return 1;

	return 0;
}

static inline int pkt_is_udp(uint8_t *pkt, int nbytes) { // pkt - start of the Ethernet frame
	if (nbytes < (14 + 20 + 8))// mac + ip + udp
		return 0;
	if (*(pkt + 12) == 0x08 && *(pkt + 13) == 0 && // ip protocol
	    * (pkt + 23) == 0x11) // udp
		return 1;

	return 0;
}


void pkt_set_header(PacketHeader *header, uint8_t opcode, uint32_t seq) ;
int pkt_check_header(UdpFrame *pkt, unsigned len, struct sockaddr_in *client_addr);
void pkt_send_hello(UdpFrame *frame, int udpfd);
void pkt_print_stats(UdpFrame *frame, int udpfd);

// log.c
#define LOG_MSGS_MAX_TIMEOUT 10	// don't allow not more then 10 messages per TIMEOUT interval
extern int logcnt;
void logmsg(char *fmt, ...);
void print_timestamp(void);

// blake2-ref.c
int blake2( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

// secret.c
void init_keys(uint16_t port);
uint8_t *get_hash(uint8_t *in, unsigned inlen, uint32_t timestamp, uint32_t seq);

// scramble.c
void scramble(uint8_t *ptr, int len, PacketHeader *hdr);
void descramble(uint8_t *ptr, int len, PacketHeader *hdr);

// usage.c
void usage(void);

// network.c
void net_if_up(const char *ifname);
void net_if_ip(const char *ifname, uint32_t ip, uint32_t mask, int mtu);
void net_set_mtu(const char *ifname, int mtu);
int net_get_mtu(const char *ifname);
int net_add_bridge(const char *ifname);
void net_bridge_add_interface(const char *bridge, const char *dev);
int net_tap_open(char *devname);
int net_udp_server(int port);
int net_udp_client(void);
void net_ipforward(void);
char *net_get_nat_if(void);
void net_set_netfilter(char *ifname);

// security.c
void daemonize(void);
void seccomp(const char *id, const char *str);
void chroot_drop_privs(const char *username);

// child.c
void child(int socket);

// profile.c
extern uint32_t profile_netaddr;
extern uint32_t profile_netmask;
extern uint32_t profile_defaultgw;
extern uint32_t profile_mtu;
extern char *profile_child_seccomp;
extern char *profile_parent_seccomp;
void profile_load(const char *fname);
void profile_save(const char *fname, TOverlay *o);

// dns.c
void dns_set_tunnel(const char *dns_ip);

// The following frames on a new connection are sent uncompressed:
//       1, 2, 3, 5, 10, 15, 20, 40, 60, 80...
static inline int compress_shaper(int cnt) {
	int rv = 0;

	if (cnt > 20 && cnt % 20)
		rv = 1;
	else if (cnt > 3 && cnt % 5)
		rv = 1;
	return rv;
}


typedef enum {
	S2C = 0, // server to client
	C2S
} Direction;

int compress_l3_size(void);
void compress_l3_init(void);
void print_compress_l3_table(int direction);
void update_compress_l3_stats(void);
int classify_l3(uint8_t *pkt, uint8_t *sid, int directin);
int compress_l3(uint8_t *pkt, int nbytes, uint8_t sid, int direction);
int decompress_l3(uint8_t *pkt, int nbytes, uint8_t sid, int direction);

// compress_l2.c
int compress_l2_size(void);
void compress_l2_init(void);
void print_compress_l2_table(int direction);
void update_compress_l2_stats(void);
int classify_l2(uint8_t *pkt, uint8_t *sid, int direction);
int compress_l2(uint8_t *pkt, int nbytes, uint8_t sid, int direction);
int decompress_l2(uint8_t *pkt, int nbytes, uint8_t sid, int direction);

// compress_l4.c
int compress_l4_size(void);
void compress_l4_init(void);
void print_compress_l4_table(int direction);
void update_compress_l4_stats(void);
int classify_l4(uint8_t *pkt, uint8_t *sid, int direction);
int compress_l4(uint8_t *pkt, int nbytes, uint8_t sid, int direction);
int decompress_l4(uint8_t *pkt, int nbytes, uint8_t sid, int direction);


#endif
