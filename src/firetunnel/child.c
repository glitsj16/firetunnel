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
#include "firetunnel.h"

#define STATS_TIMEOUT_MAX 6	// print stats every STATS_TIMEOUT_MAX * TIMEOUT
static int statscnt = 0;
#define COMPRESS_TIMEOUT_MAX (STATS_TIMEOUT_MAX)
static int compresscnt = 0;

static void send_config(int socket) {
	char msg[10 + sizeof(TOverlay)];
	strcpy(msg, "config ");
	memcpy(msg + 7, &tunnel.overlay, sizeof(TOverlay));

	// send tunnel configuration to the parent
	int rv = write(socket, msg, 7 + sizeof(TOverlay));
	if (rv == -1)
		errExit("write");
}


void child(int socket) {
	// init select loop
	struct timeval timeout;
	timeout.tv_sec = TIMEOUT;
	timeout.tv_usec = 0;

	// init packet storage
	// rx
	PacketMem *pktmem = malloc(sizeof(PacketMem));
	if (!pktmem)
		errExit("malloc");
	memset(pktmem, 0, sizeof(PacketMem));
	UdpFrame *udpframe = &pktmem->f;
	int hlen = sizeof(PacketHeader);

	// tx - used for hello, stats  and messages; for data, the rx packet is reused
	PacketMem *txpktmem = malloc(sizeof(PacketMem));
	if (!pktmem)
		errExit("malloc");
	memset(txpktmem, 0, sizeof(PacketMem));
	UdpFrame *txudpframe = &txpktmem->f;

	if (!arg_server) {
		pkt_send_hello(txudpframe, tunnel.udpfd);
		printf("Connecting..."); fflush(0);
		timeout.tv_sec = 2;
	}

	// select loop
	while (1) {
		fd_set set;
		FD_ZERO (&set);
		int nfds = 0;
		FD_SET(tunnel.tapfd, &set);
		nfds = (tunnel.tapfd > nfds) ? tunnel.tapfd : nfds;
		FD_SET(tunnel.udpfd, &set);
		nfds = (tunnel.udpfd > nfds) ? tunnel.udpfd : nfds;

		int rv;
		if ((rv = select(nfds + 1, &set, NULL, NULL, &timeout)) < 0)
			errExit("select");

		if (rv == 0) {
			timeout.tv_sec = TIMEOUT;
			// a disconnected client tries every 2 seconds
			if (!arg_server && tunnel.state == S_DISCONNECTED) {
				timeout.tv_sec = 2;
				printf("."); fflush(0);
			}
			timeout.tv_usec = 0;
			logcnt = 0;

			// send HELLO packet
			// the client always sends it, regardless of the connection status
			if (tunnel.state == S_CONNECTED || !arg_server) {
				dbg_printf("\ntunnel tx hello ");
				pkt_send_hello(txudpframe, tunnel.udpfd);
				dbg_printf("\n");
			}

			// check connect ttl
			if (--tunnel.connect_ttl < 1) {
				tunnel.state = S_DISCONNECTED;
				tunnel.seq = 0;
				if (tunnel.connect_ttl == 0) {
					logmsg("%d.%d.%d.%d:%d disconnected\n",
					       PRINT_IP(ntohl(tunnel.remote_sock_addr.sin_addr.s_addr)),
					       ntohs(tunnel.remote_sock_addr.sin_port));
					if (arg_server)
						memset(&tunnel.remote_sock_addr, 0, sizeof(tunnel.remote_sock_addr));
					compress_l2_init();
					compress_l3_init();
					compress_l4_init();
				}

				tunnel.connect_ttl = 0;
			}

			// print stats
			if (++statscnt >= STATS_TIMEOUT_MAX) {
				statscnt = 0;
				update_compress_l2_stats();
				update_compress_l3_stats();
				update_compress_l4_stats();
				pkt_print_stats(txudpframe, tunnel.udpfd);
			}

			if (++compresscnt >= COMPRESS_TIMEOUT_MAX) {
				compresscnt = 0;
				if (arg_debug || arg_debug_compress) {
					int direction = (arg_server)? S2C: C2S;
					print_compress_l2_table(direction);
					print_compress_l3_table(direction);
					print_compress_l4_table(direction);
					printf("\n");
				}
			}

			continue;
		}

		// tap (ethernet)
		if (FD_ISSET (tunnel.tapfd, &set)) {
			int nbytes;

			// get data from tap device
			nbytes = read(tunnel.tapfd, udpframe->eth, sizeof(UdpFrame) - hlen);
			if (nbytes == -1)
				perror("read");
			dbg_printf("\ntap rx %d ", nbytes);

			// eth header size of 14
			if (nbytes <=14)
				dbg_printf("error < 14\n");
			else if (tunnel.state != S_CONNECTED)
				dbg_printf("error not connected\n");
			else if (pkt_is_ipv6(udpframe->eth, nbytes))
				dbg_printf("ipv6 drop\n");
			else if (pkt_is_dns_AAAA(udpframe->eth, nbytes))
				dbg_printf("DNS AAAA drop\n");
			else {
				int compression_l2 = 0;
				int compression_l3 = 0;
				int compression_l4 = 0;
				uint8_t sid;	// session id if compression is set

				int is_dns = 0; 	// force DNS in L3 compression instead of L4 compression
						// DNS uses a random UDP port number for each request
						// it will mess up L4 compression table
				if (pkt_is_dns(udpframe->eth, nbytes)) {
					dbg_printf("DNS ");
					tunnel.stats.eth_rx_dns++;
					is_dns = 1;
				}
				int direction = (arg_server)? S2C: C2S;
				if (!is_dns && (pkt_is_tcp(udpframe->eth, nbytes) || pkt_is_udp(udpframe->eth, nbytes))) {
					dbg_printf("L4 ");
					compression_l4 = classify_l4(udpframe->eth, &sid, direction);
				}
				else if (pkt_is_ip(udpframe->eth, nbytes)) { // dns goes here
					dbg_printf("L3 ");
					compression_l3 = classify_l3(udpframe->eth, &sid, direction);
				}
				else { // arp goes here
					if (pkt_is_arp(udpframe->eth, nbytes))
						tunnel.stats.eth_rx_arp++;
					dbg_printf("L2 ");
					compression_l2 = classify_l2(udpframe->eth, &sid, direction);
				}

				// set header
				tunnel.seq++;
				PacketHeader hdr;
				memset(&hdr, 0, sizeof(hdr));
				uint8_t *ethptr = udpframe->eth;
				if (compression_l4) {
					dbg_printf("compL4 ");
					int rv = compress_l4(udpframe->eth, nbytes, sid, direction);
					nbytes -= rv;
					ethptr += rv;
					pkt_set_header(&hdr, O_DATA_COMPRESSED_L4, tunnel.seq);
					hdr.sid = sid;
				}
				else if (compression_l3) {
					dbg_printf("compL3 ");
					int rv = compress_l3(udpframe->eth, nbytes, sid, direction);
					nbytes -= rv;
					ethptr += rv;
					pkt_set_header(&hdr, O_DATA_COMPRESSED_L3, tunnel.seq);
					hdr.sid = sid;
				}
				else if (compression_l2) {
					dbg_printf("compL2 ");
					int rv = compress_l2(udpframe->eth, nbytes, sid, direction);
					nbytes -= rv;
					ethptr += rv;
					pkt_set_header(&hdr, O_DATA_COMPRESSED_L2, tunnel.seq);
					hdr.sid = sid;
				}
				else
					pkt_set_header(&hdr, O_DATA, tunnel.seq);

				scramble(ethptr, nbytes, &hdr);
				memcpy(ethptr - hlen, &hdr, hlen);

				// add BLAKE2 authentication
				uint8_t *hash = get_hash(ethptr - hlen, nbytes + hlen,
							 ntohl(hdr.timestamp), tunnel.seq);
				memcpy(ethptr + nbytes, hash, KEY_LEN);

				rv = sendto(tunnel.udpfd, ethptr - hlen, nbytes + hlen + KEY_LEN, 0,
					    (const struct sockaddr *) &tunnel.remote_sock_addr,
					    sizeof(struct sockaddr_in));
				dbg_printf("sent tunnel %d\n", rv);
				if (rv == -1)
					perror("sendto");

				tunnel.stats.udp_tx_pkt++;
			}
		}

		// udp
		if (FD_ISSET (tunnel.udpfd, &set)) {
			int nbytes;
			struct sockaddr_in client_addr;
			unsigned socklen = sizeof(client_addr);

			// get data from udp socket
			nbytes = recvfrom(tunnel.udpfd, udpframe, sizeof(UdpFrame), 0,
					  (struct sockaddr *) &client_addr, &socklen);
			if (nbytes == -1)
				perror("recvfrom");

			// update stats
			tunnel.stats.udp_rx_pkt++;
			dbg_printf("\ntunnel rx %d ", nbytes);

			if (pkt_check_header(udpframe, nbytes, &client_addr)) { // also does BLAKE2 authentication
				if (tunnel.state == S_CONNECTED)
					tunnel.connect_ttl = CONNECT_TTL;

				if (udpframe->header.flags & F_SYNC) {
					logmsg("sync requested by %d.%d.%d.%d:%d\n",
					       PRINT_IP(ntohl(client_addr.sin_addr.s_addr)),
					       ntohs(client_addr.sin_port));
					compress_l2_init();
					compress_l3_init();
					compress_l4_init();
				}

				uint8_t opcode = udpframe->header.opcode;
				if (opcode == O_DATA || opcode == O_DATA_COMPRESSED_L4 ||
				    opcode == O_DATA_COMPRESSED_L3 || opcode == O_DATA_COMPRESSED_L2) {
					// descramble
					descramble(udpframe->eth, nbytes - hlen - KEY_LEN, &udpframe->header);
					nbytes -= hlen + KEY_LEN;
					int direction = (arg_server)? C2S: S2C;
					uint8_t *ethstart = udpframe->eth;
					if (opcode == O_DATA_COMPRESSED_L4) {
						dbg_printf("decompL4 ");
						rv = decompress_l4(ethstart, nbytes, udpframe->header.sid, direction);
						ethstart -= rv;
						nbytes += rv;
					}
					if (opcode == O_DATA_COMPRESSED_L3) {
						dbg_printf("decompL3 ");
						rv = decompress_l3(ethstart, nbytes, udpframe->header.sid, direction);
						ethstart -= rv;
						nbytes += rv;
					}
					else if (opcode == O_DATA_COMPRESSED_L2) {
						dbg_printf("decompL2 ");
						rv = decompress_l2(ethstart, nbytes, udpframe->header.sid, direction);
						ethstart -= rv;
						nbytes += rv;
					}

					int is_dns = 0;
					if (pkt_is_dns(ethstart, nbytes)) {
						dbg_printf("DNS ");
						is_dns = 1;
					}

					if (!is_dns && (pkt_is_tcp(ethstart, nbytes) || pkt_is_udp(ethstart, nbytes)))
						classify_l4(ethstart, NULL, direction);
					else if (pkt_is_ip(ethstart, nbytes))
						classify_l3(ethstart, NULL, direction);
					else
						classify_l2(ethstart, NULL, direction);

					// write to tap device
					dbg_printf("send tap ");
					rv = write(tunnel.tapfd, ethstart, nbytes);
					dbg_printf("%d\n", rv);
					if (rv == -1)
						perror("write");
				}

				else if (opcode == O_HELLO) {
					dbg_printf("hello ");
					if (tunnel.state == S_DISCONNECTED) {
						tunnel.seq = 0;
						// update remote data
						if (arg_server) {
							memcpy(&tunnel.remote_sock_addr, &client_addr, sizeof(struct sockaddr_in));
							timeout.tv_sec = 0;
							timeout.tv_usec = 0;
						}
						else
							printf("\n");

						// respond with a hello
						pkt_send_hello(txudpframe, tunnel.udpfd);
						// actually send two of them...
						pkt_send_hello(txudpframe, tunnel.udpfd);

						tunnel.state = S_CONNECTED;
						logmsg("%d.%d.%d.%d:%d connected\n",
						       PRINT_IP(ntohl(tunnel.remote_sock_addr.sin_addr.s_addr)),
						       ntohs(tunnel.remote_sock_addr.sin_port));

						compress_l2_init();
						compress_l3_init();
						compress_l4_init();
					}
					tunnel.connect_ttl = CONNECT_TTL;

					// update overlay data if we are the client
					if (!arg_server) {
						descramble(udpframe->eth, 7 * sizeof(uint32_t), &udpframe->header);

						uint32_t *ptr = (uint32_t *) &udpframe->eth[0];
						TOverlay o;
						o.netaddr = ntohl(*ptr++);
						o.netmask = ntohl(*ptr++);
						o.defaultgw = ntohl(*ptr++);
						o.mtu = ntohl(*ptr++);
						o.dns1 = ntohl(*ptr++);
						o.dns2 = ntohl(*ptr++);
						o.dns3 = ntohl(*ptr++);

						if (memcmp(&tunnel.overlay, &o, sizeof(TOverlay))) {
							memcpy(&tunnel.overlay, &o, sizeof(TOverlay));
							logmsg("Tunnel: %d.%d.%d.%d/%d, default gw %d.%d.%d.%d, mtu %d\n",
							       PRINT_IP(tunnel.overlay.netaddr), mask2bits(tunnel.overlay.netmask),
							       PRINT_IP(tunnel.overlay.defaultgw), tunnel.overlay.mtu);
							logmsg("Tunnel: DNS %d.%d.%d.%d, %d.%d.%d.%d, %d.%d.%d.%d\n",
							       PRINT_IP(tunnel.overlay.dns1), PRINT_IP(tunnel.overlay.dns2), PRINT_IP(tunnel.overlay.dns3));

							// send tunnel configuration to the parent
							send_config(socket);
						}
					}
					dbg_printf("\n");
				}

				else if (opcode == O_MESSAGE) {
					dbg_printf("message\n");
					if (tunnel.state == S_DISCONNECTED || arg_server) {
						// quietly drop the packet, it could be a very old one
					}
					else {
						printf("%s\n", (char *) udpframe->eth);
					}
				}
			}
			else {
				dbg_printf("drop\n");
				tunnel.stats.udp_rx_drop_pkt++;
			}
		}
	}
}
