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

// Allocated the pktgen structure for global use
extern    pktgen_t        pktgen;

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
pktgen_udp_hdr_ctor(pkt_seq_t * pkt, udpip_t * uip, __attribute__ ((unused)) int type)
{
	uint16_t		tlen;

    // Zero out the header space
    memset((char *)uip, 0, sizeof(udpip_t));
	ipHdr_t       * ip 	= (ipHdr_t *)&(uip->ip);
	ip->ttl				= 64;
    // Create the UDP header
    uip->ip.src         = htonl(pkt->ip_src_addr);
    uip->ip.dst         = htonl(pkt->ip_dst_addr);
    tlen                = pkt->pktSize - (pkt->ether_hdr_size + sizeof(ipHdr_t));

    uip->ip.len         = htons(tlen);
    uip->ip.proto       = pkt->ipProto;

	uip->udp.len		= htons(tlen);
    uip->udp.sport      = htons(pkt->sport);
    uip->udp.dport      = htons(pkt->dport);

	// Includes the pseudo header information
    tlen                = pkt->pktSize - pkt->ether_hdr_size;

    uip->udp.cksum      = cksum(uip, tlen, 0);
    if ( uip->udp.cksum == 0 )
        uip->udp.cksum = 0xFFFF;
}

struct rte_mbuf * pktgen_process_udp(struct rte_mbuf * m, uint32_t pid, uint32_t qid){
	port_info_t   * info = &pktgen.info[pid];
	struct rte_mbuf   * resp_buf = m;
    struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
    udpip_t       * uip = (udpip_t *)&eth[1];
	ipHdr_t       * ip = (ipHdr_t *)&(uip->ip);
	ip->ttl				= 64;
	
	/*
	resp_buf->pkt.pkt_len = sizeof(struct ether_hdr) + sizeof(udpip_t) ;
	resp_buf->pkt.data_len = resp_buf->pkt.pkt_len;
	*/
	
	uint16Swap(&uip->udp.sport, &uip->udp.dport );
	inetAddrSwap(&ip->src, &ip->dst);
    ip->proto       = PG_IPPROTO_UDP;
	ethAddrSwap(&eth->d_addr, &eth->s_addr);
	pktgen_send_mbuf(resp_buf, pid, qid);
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);
	
	/*
	char		src_ip_buff[64];
	char		dst_ip_buff[64];
	char		src_mac_buff[64];
	char		dst_mac_buff[64];
	printf("udp : s_addr:%s;s_mac:%s;d_addr:%s;d_mac:%s done\n", inet_ntop4(src_ip_buff, sizeof(src_ip_buff), ip->src, 0xFFFFFFFF), inet_mtoa(src_mac_buff, sizeof(src_mac_buff), &eth->s_addr), inet_ntop4(dst_ip_buff, sizeof(dst_ip_buff), ip->dst, 0xFFFFFFFF), inet_mtoa(dst_mac_buff, sizeof(dst_mac_buff), &eth->d_addr));
	*/
	return ;
}














