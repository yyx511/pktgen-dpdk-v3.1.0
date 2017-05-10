/*-
 * Copyright (c) <2010>, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Copyright (c) <2010-2014>, Wind River Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3) Neither the name of Wind River Systems nor the names of its contributors may be
 * used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * 4) The screens displayed by the application must contain the copyright notice as defined
 * above and can not be removed without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Created 2010 by Keith Wiles @ windriver.com */

#include "pktgen.h"
#include "pktgen-tcp.h"
#include "pktgen-udp.h"

// Allocated the pktgen structure for global use
extern pktgen_t pktgen;

/**************************************************************************//**
*
* pktgen_udp_hdr_ctor - UDP header constructor routine.
*
* DESCRIPTION
* Construct the UDP header in a packer buffer.
*
* RETURNS: N/A
*
* SEE ALSO:
*/

void
pktgen_udp_hdr_ctor(pkt_seq_t *pkt, udpip_t *uip, __attribute__ ((unused)) int type)
{
	uint16_t tlen;
	// Zero out the header space
	memset((char *)uip, 0, sizeof(udpip_t));
	ipHdr_t *ip = (ipHdr_t *)&(uip->ip);
	ip->ttl = 64;

	// Create the UDP header
	uip->ip.src = htonl(pkt->ip_src_addr);
	uip->ip.dst = htonl(pkt->ip_dst_addr);
	tlen = pkt->pktSize - (pkt->ether_hdr_size + sizeof(ipHdr_t));

	uip->ip.len = htons(tlen);
	uip->ip.proto = pkt->ipProto;

	uip->udp.len = htons(tlen);
	uip->udp.sport = htons(pkt->sport);
	uip->udp.dport = htons(pkt->dport);

	// Includes the pseudo header information
	tlen = pkt->pktSize - pkt->ether_hdr_size;
	uip->udp.cksum = cksum(uip, tlen, 0);
	if (uip->udp.cksum == 0)
		uip->udp.cksum = 0xFFFF;
}


void pkt_reset_src_dst_udp(struct rte_mbuf *mbuf, range_info_t *range, port_info_t *info)
{
	pkt_seq_t *pkt = &info->seq_pkt[RANGE_PKT];
	struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	udpip_t *uip = (udpip_t *)&eth[1];
	
	uint16_t sport = range->src_port;
	uint32_t p = range->src_ip;
	if (sport > range->src_port_max || sport >= 65535) {
		sport = range->src_port_min;
		p += range->src_ip_inc;
		if (p < range->src_ip_min)
			p = range->src_ip_max;
		else if (p > range->src_ip_max)
			p = range->src_ip_min;
	} else if (sport < range->src_port_min) {
		sport = range->src_port_max;
	} else {
		sport += range->src_port_inc;
	}
	range->src_port = sport;
	range->src_ip = p;
	
	uip->ip.src = htonl(p);
	uip->udp.sport = htons(sport);
	ipHdr_t *ip = (ipHdr_t *)&(uip->ip);
	ip->ttl = 64;
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	uint32_t tlen;
	tlen = mbuf->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	udp_add_cksum(uip, ip, tlen);
}

void udp_add_cksum(udpip_t *uip, ipHdr_t *ip, uint16_t tlen)
{
	uip->udp.cksum = 0;
	char buf[64 + tlen];
	tcp_fake_head tcpfh;
	tcpfh.src_ip = ip->src;
	tcpfh.dst_ip = ip->dst;
	tcpfh.mbz = 0;
	tcpfh.protocol_type = PG_IPPROTO_UDP;
	tcpfh.tcp_head_len = htons(tlen);
	memset(buf, 0, sizeof(tcp_fake_head)+tlen);
	memcpy(buf, &tcpfh, sizeof(tcp_fake_head));
	memcpy(buf+sizeof(tcp_fake_head), &uip->udp, tlen);
	uip->udp.cksum = cksum(buf, sizeof(tcp_fake_head) + tlen, 0);
}

