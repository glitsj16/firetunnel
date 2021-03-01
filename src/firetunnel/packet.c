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
#include <time.h>
#include <arpa/inet.h>

void pkt_set_header(PacketHeader *header, uint8_t opcode, uint32_t seq)  {
	assert(header);
	memset(header, 0, sizeof(PacketHeader));
	header->opcode = opcode;
	header->seq = htons(seq);
	header->timestamp = htonl(time(NULL));
}

// return 1 if header is good, 0 if bad
int pkt_check_header(UdpFrame *pkt, unsigned len, struct sockaddr_in *client_addr) {
	assert(pkt);
	PacketHeader *header = &pkt->header;

	// check packet length
	if (len < sizeof(PacketHeader) + KEY_LEN)
		return 0;

	// check opcode
	if (header->opcode >= O_MAX)
		return 0;

	// check ip:port
	if (tunnel.remote_sock_addr.sin_port != 0 &&
	    tunnel.remote_sock_addr.sin_addr.s_addr != 0) {
		if (tunnel.remote_sock_addr.sin_addr.s_addr != client_addr->sin_addr.s_addr ||
		    tunnel.remote_sock_addr.sin_port != client_addr->sin_port) {
		    	tunnel.stats.udp_rx_drop_addr_pkt++;

		    	logmsg("Address mismatch %d.%d.%d.%d:%d\n",
				PRINT_IP(ntohl(client_addr->sin_addr.s_addr)),
				ntohs(client_addr->sin_port));

		    	return 0;
		}
	}

	// check timestamp
	uint32_t current_timestamp = time(NULL);
	uint32_t timestamp = ntohl(header->timestamp);
	uint32_t delta = diff_uint32(current_timestamp, timestamp);
	if (delta > TIMESTAMP_DELTA_MAX) {
		fprintf(stderr, "Warning: timestamp drop, delta %u\n",  delta);
		tunnel.stats.udp_rx_drop_timestamp_pkt++;
		return 0;
	}

	// check blake2
	uint8_t *hash = get_hash((uint8_t *)pkt, len - KEY_LEN,
		ntohl(header->timestamp), ntohs(header->seq));

	if (memcmp((uint8_t *) pkt + len - KEY_LEN, hash, KEY_LEN)) {
		tunnel.stats.udp_rx_drop_blake2_pkt++;
	    	logmsg("Hash mismatch %d.%d.%d.%d:%d\n",
			PRINT_IP(ntohl(client_addr->sin_addr.s_addr)),
			ntohs(client_addr->sin_port));
		return 0;
	}

	return 1;
}


void pkt_send_hello(UdpFrame *frame, int udpfd) {
	// set header
	tunnel.seq++;
	pkt_set_header(&frame->header, O_HELLO,  tunnel.seq);
	if (tunnel.state == S_DISCONNECTED)
		frame->header.flags |= F_SYNC;
	int nbytes = sizeof(PacketHeader);

	// send overlay data if we are the server
	if (arg_server) {
		uint32_t *ptr = (uint32_t *) &frame->eth;
		*ptr++ = htonl(tunnel.overlay.netaddr);
		*ptr++ = htonl(tunnel.overlay.netmask);
		*ptr++ = htonl(tunnel.overlay.defaultgw);
		*ptr++ = htonl(tunnel.overlay.mtu);
		*ptr++ = htonl(tunnel.overlay.dns1);
		*ptr++ = htonl(tunnel.overlay.dns2);
		*ptr++ = htonl(tunnel.overlay.dns3);
		scramble((uint8_t *) &frame->eth, 7 * sizeof(uint32_t), &frame->header);
		nbytes += 7 * sizeof(uint32_t);
	}

	// add hash
	uint8_t *hash = get_hash((uint8_t *)frame, nbytes,
		ntohl(frame->header.timestamp), tunnel.seq);
	memcpy((uint8_t *) frame + nbytes, hash, KEY_LEN);

	// send
	int rv = sendto(udpfd, frame, nbytes + KEY_LEN, 0,
			(const struct sockaddr *) &tunnel.remote_sock_addr,
			sizeof(struct sockaddr_in));
	if (rv == -1)
		perror("sendto");
	tunnel.stats.udp_tx_pkt++;
}

void pkt_print_stats(UdpFrame *frame, int udpfd) {
	if (tunnel.state == S_DISCONNECTED)
		return;

	// build the stats message
	char buf[1024];
	char *ptr = buf;
	char *type = "Client";
	if (arg_server)
		type = "Server";
	int compressed = 0;
	if (tunnel.stats.udp_tx_pkt)
		compressed = (int) (100 * ((float) tunnel.stats.udp_tx_compressed_pkt / (float) tunnel.stats.udp_tx_pkt));
	sprintf(ptr, "%s: tun tx/comp/drop %u/%d%%/%d; DNS %u; ARP %u",
		type,
		tunnel.stats.udp_tx_pkt,
		compressed,
		tunnel.stats.udp_rx_drop_pkt,

		tunnel.stats.eth_rx_dns,
		tunnel.stats.eth_rx_arp);
	ptr += strlen(ptr);

	// print stats message on console
	printf("%s\n", buf);

	// clean stats
	tunnel.stats.udp_tx_pkt = 0;
	tunnel.stats.udp_tx_compressed_pkt = 0;
	tunnel.stats.udp_rx_pkt = 0;
	tunnel.stats.eth_rx_dns = 0;
	tunnel.stats.eth_rx_arp = 0;

	// send the message to the client
	if (arg_server && tunnel.state == S_CONNECTED) {
		// set header
		tunnel.seq++;
		pkt_set_header(&frame->header, O_MESSAGE,  tunnel.seq);
		int nbytes = sizeof(PacketHeader);

		// copy the message
		strcpy(((char *) frame) + nbytes, buf);
		nbytes += strlen(buf) + 1;

		// add hash
		uint8_t *hash = get_hash((uint8_t *)frame, nbytes,
			ntohl(frame->header.timestamp), tunnel.seq);
		memcpy((uint8_t *) frame + nbytes, hash, KEY_LEN);

		// send
		int rv = sendto(udpfd, frame, nbytes + KEY_LEN, 0,
				(const struct sockaddr *) &tunnel.remote_sock_addr,
				sizeof(struct sockaddr_in));
		if (rv == -1)
			perror("sendto");
		tunnel.stats.udp_tx_pkt++;
	}
}
