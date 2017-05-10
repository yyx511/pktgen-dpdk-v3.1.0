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
#include <rte_lcore.h>
#include <math.h>
#include <rte_byteorder.h>
#include <rte_ip.h>

#define HTTP_GET "GET /index.html HTTP/1.1\r\nHOST: %s:%d\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: close\r\n\r\n"

#define HTTP_RESP_HEADER "HTTP/1.1 200 OK\r\nContent-Length:%d\r\nConnection: keep-alive\r\n\r\n%s"

#define HTTP_RESP_BODY   "<html><body>pktgen server</body></html>"

// Allocated the pktgen structure for global use
extern pktgen_t pktgen;

/**************************************************************************//**
*
* pktgen_tcp_hdr_ctor - TCP header constructor routine.
*
* DESCRIPTION
* Construct a TCP header in the packet buffer provided.
*
* RETURNS: N/A
*
* SEE ALSO:
*/

void
pktgen_tcp_hdr_ctor(pkt_seq_t *pkt, tcpip_t *tip, __attribute__ ((unused)) int type)
{
	uint16_t tlen;
	pkt->pktSize = pkt->ether_hdr_size + sizeof(tcpip_t);
    	// Zero out the header space
    	memset((char *)tip, 0, sizeof(tcpip_t));
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;

	// Create the TCP header
	tip->ip.src = htonl(pkt->ip_src_addr);
	tip->ip.dst = htonl(pkt->ip_dst_addr);
	tlen = pkt->pktSize - (pkt->ether_hdr_size + sizeof(ipHdr_t));
	//printf("ip tlen:%d;", tlen);

	tip->ip.len = htons(tlen);
	tip->ip.proto = pkt->ipProto;
	tip->tcp.sport = htons(pkt->sport);
	tip->tcp.dport = htons(pkt->dport);
	tip->tcp.seq = htonl(DEFAULT_PKT_NUMBER);

	tip->tcp.ack = htonl(DEFAULT_ACK_NUMBER);
	tip->tcp.offset = ((sizeof(tcpHdr_t)/sizeof(uint32_t)) << 4);   /* Offset in words */

	tip->tcp.flags = SYN_FLAG; 	//ACK_FLAG;     /* ACK */
	tip->tcp.window = htons(DEFAULT_WND_SIZE);//
	tip->tcp.urgent = 0;
	tlen = pkt->pktSize - pkt->ether_hdr_size;
	tip->tcp.cksum = cksum(tip, tlen, 0);
}

static seq_t get_tcp_next_seq(tcpip_t * tip)
{
	return ntohl(tip->tcp.ack);
}

static seq_t get_tcp_next_ack(tcpip_t *tip, ipHdr_t *ip, uint8_t is_syn_ack)
{
	seq_t pre_seq;
	pre_seq = ntohl(tip->tcp.seq);
	seq_t next_ack;
	uint32_t ip_total_len = ntohs(ip->tlen);
	uint16_t ip_header_len = ((ip->vl & 15) * 4);
	uint16_t tcp_header_len = ((tip->tcp.offset >> 4) * 4);
	uint32_t tcp_body_len = ip_total_len - ip_header_len - tcp_header_len;
	if (tcp_body_len == 0 || is_syn_ack == 1) {
		next_ack		= pre_seq+1;
	} else {
		next_ack = pre_seq + tcp_body_len;
	}
	return next_ack;
}

static void pkt_add_ts_opt(struct rte_mbuf *resp_buf, tcpip_t *tip)
{
	int tsv = 0, tsev = 0;
	uint16_t tcp_option_len = ((tip->tcp.offset >> 4) * 4) - sizeof(tcpHdr_t);
	resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + TS_TOT_LEN;
	resp_buf->data_len = resp_buf->pkt_len;
	char *tcp_opt = (char *)&tip[1];
	
	while (tcp_option_len > 0) {
		int opcode = *tcp_opt++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			goto _add_ts;
		case TCPOPT_NOP:
			tcp_option_len--;
			continue;
		default:
			opsize = *tcp_opt++;
			if (opsize < 2 || opsize > tcp_option_len) {
				//printf("TCP OPT ERR\n");
				goto _add_ts;
			}
			switch (opcode) {
			case TCPOPT_TIMESTAMP:
				if (opsize == TCPOLEN_TIMESTAMP) {
					tsv = *(int *)tcp_opt;
					tsev = *(int *)(tcp_opt + 4);
					goto _add_ts;
				}
			}
			tcp_opt += opsize - 2;
			tcp_option_len -= opsize;
		}
	}
	
_add_ts:
	tcp_opt = (char *)&tip[1];
	if (pktgen.nop_head == 1) {
		*tcp_opt = TCPOPT_NOP;
		tcp_opt++;
		*tcp_opt = TCPOPT_NOP;
		tcp_opt++;
		*tcp_opt = TCPOPT_TIMESTAMP;
		tcp_opt++;
		*tcp_opt = TCPOLEN_TIMESTAMP;
		tcp_opt++;
		if (tsev == 0) {
			tsev = rand();
		}
		*(int *)tcp_opt = tsev + 1;
		tcp_opt += 4;
		if (tsv == 0) {
			tsv = rand();
		}
		*(int *)tcp_opt = tsv;
	} else {
		*tcp_opt = TCPOPT_TIMESTAMP;
		tcp_opt++;
		*tcp_opt = TCPOLEN_TIMESTAMP;
		tcp_opt++;
		if (tsev == 0) {
			tsev = rand();
		}
		*(int *)tcp_opt = tsev + 1;
		tcp_opt += 4;
		if (tsv == 0) {
			tsv = rand();
		}
		*(int *)tcp_opt = tsv;
		tcp_opt += 4;
		*tcp_opt = TCPOPT_NOP;
		tcp_opt++;
		*tcp_opt = TCPOPT_NOP;
	}
}

void add_cksum(tcpip_t * tip, ipHdr_t * ip, uint16_t tlen)
{
	tip->tcp.cksum = 0;
	char buf[64 + tlen];
	tcp_fake_head tcpfh;
	tcpfh.src_ip = ip->src; 
	tcpfh.dst_ip = ip->dst; 
	tcpfh.mbz = 0;
	tcpfh.protocol_type = PG_IPPROTO_TCP;
	tcpfh.tcp_head_len = htons(tlen);
	memset(buf, 0, sizeof(tcp_fake_head)+tlen);
	rte_memcpy(buf, &tcpfh, sizeof(tcp_fake_head));
	rte_memcpy((char*)buf+sizeof(tcp_fake_head), &tip->tcp, tlen);
	tip->tcp.cksum = cksum(buf, sizeof(tcp_fake_head) + tlen, 0);
}

static inline uint16_t get_16b_sum(uint16_t *ptr16, uint32_t nr)
{
	uint32_t sum = 0;
	while (nr > 1)
	{
		sum +=*ptr16;
		nr -= sizeof(uint16_t);
		ptr16++;
		if (sum > UINT16_MAX)
			sum -= UINT16_MAX;
	}

	/* If length is in odd bytes */
	if (nr)
		sum += *((uint8_t*)ptr16);

	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum &= 0x0ffff;
	return (uint16_t)sum;
}

static inline uint16_t get_ipv4_psd_sum (struct ipHdr_s *ip_hdr)
{
	/* Pseudo Header for IPv4/UDP/TCP checksum */
	union ipv4_psd_header {
		struct {
			uint32_t src_addr; /* IP address of source host. */
			uint32_t dst_addr; /* IP address of destination host(s). */
			uint8_t  zero;     /* zero. */
			uint8_t  proto;    /* L4 protocol type. */
			uint16_t len;      /* L4 length. */
		} __attribute__((__packed__));
		uint16_t u16_arr[0];
	} psd_hdr;

	psd_hdr.src_addr = ip_hdr->src;
	psd_hdr.dst_addr = ip_hdr->dst;
	psd_hdr.zero = 0;
	psd_hdr.proto = ip_hdr->proto;
	psd_hdr.len = rte_cpu_to_be_16((uint16_t)(rte_be_to_cpu_16(ip_hdr->tlen)
				- sizeof(struct ipHdr_s)));
	return get_16b_sum(psd_hdr.u16_arr, sizeof(psd_hdr));
}

static inline uint16_t get_psd_sum(struct ipHdr_s *ip_hdr)
{
	/* Pseudo Header for IPv4/UDP/TCP checksum */
	struct ipv4_psd_header {
		uint32_t src_addr; /* IP address of source host. */
		uint32_t dst_addr; /* IP address of destination host(s). */
		uint8_t zero;     /* zero. */
		uint8_t proto;    /* L4 protocol type. */
		uint16_t len;      /* L4 length. */
	} psd_hdr;

	psd_hdr.src_addr = ip_hdr->src;
	psd_hdr.dst_addr = ip_hdr->dst;
	psd_hdr.zero = 0;
	psd_hdr.proto = ip_hdr->proto;
	psd_hdr.len = rte_cpu_to_be_16((uint16_t)(rte_be_to_cpu_16(ip_hdr->tlen)
				- sizeof(struct ipHdr_s)));
	return rte_raw_cksum(&psd_hdr, sizeof(psd_hdr));
}

void pkt_sport_reset_tcp( struct rte_mbuf *m, range_info_t *range)
{
	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	
	uint16_t sport = range->src_port;
	uint32_t p = range->src_ip;
	if ( sport > range->src_port_max || sport >= 65535){
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
	range->src_ip   = p;
	
	tip->ip.src = htonl(p);
	tip->tcp.sport = htons(sport);
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	uint32_t  tlen = m->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
}


static struct rte_mbuf *gen_ack(struct rte_mbuf *m)
{
	uint16_t l2_len, l3_len, l4_len;
	uint64_t ol_flags = 0;
	seq_t next_seq, next_ack;
	
	struct rte_mbuf *resp_buf = m;
      struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
      tcpip_t *tip = (tcpip_t *)&eth[1];
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	
	if (pktgen.add_tcp_ts == 1) {
		pkt_add_ts_opt(resp_buf, tip);
	} else {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) ;
		resp_buf->data_len = resp_buf->pkt_len;
	}
	uint16Swap(&tip->tcp.sport, &tip->tcp.dport);
	next_seq = get_tcp_next_seq(tip);
	next_ack	= get_tcp_next_ack(tip, ip, 0);
      tip->tcp.seq = htonl(next_seq);
      tip->tcp.ack = htonl(next_ack);
	tip->tcp.flags = ACK_FLAG;
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset = (sizeof(tcpHdr_t) + TS_TOT_LEN) /sizeof(uint32_t) << 4;   /* Offset in words */
		l4_len = sizeof(tcpHdr_t) + TS_TOT_LEN;
	} else {
      		tip->tcp.offset = ((sizeof(tcpHdr_t)/sizeof(uint32_t)) << 4);   /* Offset in words */
		l4_len = sizeof(tcpHdr_t);
	}
      tip->tcp.urgent = 0;
	tip->tcp.window = htons(DEFAULT_WND_SIZE);
	inetAddrSwap(&ip->src, &ip->dst);
	ip->ttl = 64;
      ip->proto = PG_IPPROTO_TCP;
      ip->tlen = htons(resp_buf->pkt_len - (sizeof(struct ether_hdr)));
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
    	tlen = resp_buf->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	resp_buf->l2_len = l2_len;
	resp_buf->l3_len = l3_len;
	resp_buf->l4_len = l4_len;
	resp_buf->ol_flags = ol_flags;
#endif
	// Swap the MAC addresses
	ethAddrSwap(&eth->d_addr, &eth->s_addr);
	return resp_buf;
}

static __inline__ void fill_pattern(uint8_t *p, uint32_t len, uint32_t type)
{
	uint32_t    i;
	switch(type) {
	case 1:                 // Byte wide ASCII pattern
		for (i = 0; i < len; i++)
			p[i] = "abcdefghijklmnopqrstuvwxyz012345"[i & 0x1f];
		break;
	default: 
		memset(p, 'a', len);
		break;
	}
}

static struct rte_mbuf *process_tcp_push_2(struct rte_mbuf *m_ack, 
								uint32_t *pkt_left_len, uint32_t id, 
								uint16_t len, uint32_t unit_pkt_len, 
								struct rte_mbuf *resp_buf, seq_t init_seq) 
{
	uint16_t l2_len, l3_len, l4_len;
	uint64_t ol_flags = 0;
	
	rte_memcpy((uint8_t *)resp_buf->buf_addr + resp_buf->data_off, (uint8_t *)m_ack->buf_addr + m_ack->data_off, m_ack->pkt_len);
	resp_buf->data_len = m_ack->data_len;
	resp_buf->pkt_len = m_ack->pkt_len;
	resp_buf->buf_len = m_ack->buf_len;
	
	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);	
      tcpip_t *tip = (tcpip_t *)&eth[1];	
	//set tcp flags
	tip->tcp.flags = ACK_FLAG | PSH_FLAG;
	
	uint32_t header_len = 0;
	uint32_t pkt_len = 0;
	char *pt = (char *)&tip[1];
	if (pktgen.add_tcp_ts == 1) {
		pt += TS_TOT_LEN;
	}
	
	uint8_t tcp_opt_len = 0;
	if (len - 1 > id) {
		tcp_opt_len = tcp_opt_253_len;
		uint8_t tcp_opt_kind = 253;
		*pt = tcp_opt_kind;
		pt++;
		*pt = tcp_opt_len;	
		pt++;
		*pt = 100;
		pt++;
		*pt = 100;
		pt++;
	}		
	
	uint32_t body_len = unit_pkt_len;
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset = ((sizeof(tcpHdr_t) + TS_TOT_LEN + tcp_opt_len)/sizeof(uint32_t)) << 4;
		l4_len = sizeof(tcpHdr_t) + TS_TOT_LEN + tcp_opt_len;
	} else {
		tip->tcp.offset = ((sizeof(tcpHdr_t) + tcp_opt_len)/sizeof(uint32_t)) << 4;
		l4_len = sizeof(tcpHdr_t) + tcp_opt_len;
	}
	tip->tcp.seq = htonl(init_seq + id * unit_pkt_len);
	
	if (body_len > (*pkt_left_len)) {
		body_len = (*pkt_left_len);
	}
	
	if (id == 0) {
		char http_header[256] = {0};
		sprintf(http_header, HTTP_RESP_HEADER, pktgen.resp_pkt_size, "");
		header_len = strlen(http_header);
		rte_memcpy(pt, http_header, header_len);
		pt += header_len;
		body_len -= header_len;
	}
	
	if (body_len > (*pkt_left_len)) {
		body_len = (*pkt_left_len);
	}
	
	pkt_len = body_len + header_len;
	if (body_len > 0) {
		//fill_pattern(pt, body_len, 0);
		memset(pt, 'a', body_len);
	}
	(*pkt_left_len) -= body_len;
	if (*pkt_left_len <= 0) {
		(*pkt_left_len) = 0;
	}
	
	if (pktgen.add_tcp_ts == 1) {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_len + pkt_len + TS_TOT_LEN;
	} else {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_len + pkt_len;
	}
	resp_buf->data_len = resp_buf->pkt_len;
	
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	uint32_t tlen = resp_buf->pkt_len - (sizeof(struct ether_hdr));
	ip->ttl = 64;
	ip->tlen = htons(tlen);

	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	resp_buf->ol_flags = ol_flags;
	resp_buf->l2_len = l2_len;
	resp_buf->l3_len = l3_len;
	resp_buf->l4_len = l4_len;
	
	return resp_buf;
}

static struct rte_mbuf *process_tcp_push(struct rte_mbuf *m_ack, uint32_t pid, 
								uint32_t qid, uint32_t *pkt_left_len, uint32_t id, 
								uint8_t resp_type, uint16_t len, 
								uint32_t unit_pkt_max)
{
	uint64_t ol_flags = 0;
	uint16_t l2_len, l3_len, l4_len;
	
	struct rte_mbuf *resp_buf = NULL;
	port_info_t *info = &pktgen.info[pid];
	resp_buf = rte_pktmbuf_alloc(info->q[qid].resp_mp);
	if (unlikely(resp_buf == NULL)) {
		printf("warning: process_tcp_push rte_pktmbuf_alloc return NULL\n");
		return NULL;
	}
	
	rte_memcpy((uint8_t *)resp_buf->buf_addr + resp_buf->data_off, 
					(uint8_t *)m_ack->buf_addr + resp_buf->data_off, 
					m_ack->pkt_len);
	resp_buf->data_len = m_ack->data_len;
	resp_buf->pkt_len = m_ack->pkt_len;
	resp_buf->buf_len = m_ack->buf_len;
	
	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
      tcpip_t *tip = (tcpip_t *)&eth[1];
	  
	struct ether_hdr *o_eth = rte_pktmbuf_mtod(m_ack, struct ether_hdr *);
	tcpip_t *o_tip = (tcpip_t *)&o_eth[1];
	
	//set tcp flags
	tip->tcp.flags = ACK_FLAG | PSH_FLAG;
	
	uint32_t header_len = 0;
	uint32_t pkt_len = 0;
	char *pt = (char *)&tip[1];
	if (pktgen.add_tcp_ts == 1) {
		pt += TS_TOT_LEN;
	}
	
	uint8_t tcp_opt_len = 0;
	if (resp_type == SMALL_PKT) {
		if (pktgen.is_forward == 1) {
			rte_memcpy(pt, "y", 1);
		} else {
			char tcp_data[256] = {0};
			sprintf(tcp_data, HTTP_RESP_HEADER, strlen(HTTP_RESP_BODY), HTTP_RESP_BODY);
			pkt_len = strlen(tcp_data);
			rte_memcpy(pt, tcp_data, pkt_len);
		}
	} else {
		if (len - 1 > id) {
			tcp_opt_len = tcp_opt_253_len;
			uint8_t tcp_opt_kind = 253;
			*pt = tcp_opt_kind;
			pt++;
			*pt = tcp_opt_len;	
			pt++;
			*pt = 100;
			pt++;
			*pt = 100;
			pt++;
		}		
		
		uint32_t body_len = unit_pkt_max;
		if (pktgen.add_tcp_ts == 1) {
			tip->tcp.offset = ((sizeof(tcpHdr_t) + TS_TOT_LEN + tcp_opt_len)/sizeof(uint32_t)) << 4;
			l4_len = sizeof(tcpHdr_t) + TS_TOT_LEN + tcp_opt_len;
		} else {
			tip->tcp.offset = ((sizeof(tcpHdr_t) + tcp_opt_len)/sizeof(uint32_t)) << 4;
			l4_len = sizeof(tcpHdr_t) + tcp_opt_len;
		}
		tip->tcp.seq = htonl(ntohl(o_tip->tcp.seq) + id * unit_pkt_max);
		
		if (body_len > (*pkt_left_len)) {
			body_len = (*pkt_left_len);
		}
		
		if (id == 0) {
			char http_header[256] = {0};
			sprintf(http_header, HTTP_RESP_HEADER, pktgen.resp_pkt_size, "");
			header_len = strlen(http_header);
			rte_memcpy(pt, http_header, header_len);
			pt += header_len;
			body_len -= header_len;
		}
		
		if (body_len > (*pkt_left_len)) {
			body_len = (*pkt_left_len);
		}
		
		pkt_len = body_len + header_len;
		if (body_len > 0) {
			fill_pattern(pt, body_len, 0);
		}
		(*pkt_left_len) -= body_len;
		if (*pkt_left_len <= 0) {
			(*pkt_left_len) = 0;
		}
	}
	
	if (pktgen.add_tcp_ts == 1) {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_len + pkt_len + TS_TOT_LEN;
	} else {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_len + pkt_len;
	}
	
	resp_buf->data_len = resp_buf->pkt_len;
	
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	uint32_t tlen = resp_buf->pkt_len - (sizeof(struct ether_hdr));
	ip->ttl = 64;
	ip->tlen = htons(tlen);
	
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);	
	add_cksum(tip, ip, tlen - sizeof(ipHdr_t));
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	resp_buf->ol_flags = ol_flags;
	resp_buf->l2_len = l2_len;
	resp_buf->l3_len = l3_len;
	resp_buf->l4_len = l4_len;
#endif
	return resp_buf;
}

void process_http_request(struct rte_mbuf *m, uint32_t pid, uint32_t qid)
{
	uint32_t tmp = pktgen.resp_pkt_size;
	uint16_t len = 1;
	uint32_t unit_pkt_max = 0;
	uint16_t i = 0, j = 0;
	port_info_t *info = &pktgen.info[pid];
	struct rte_mbuf *m_ack = NULL, *m_push = NULL;
	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	
	//ack
	m_ack = gen_ack(m);	
	if (pktgen.add_tcp_ts == 1) {
		unit_pkt_max = pktgen.mtu - (sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_253_len + TS_TOT_LEN);
	} else {
		unit_pkt_max = pktgen.mtu - (sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_253_len);
	}
	
	if (pktgen.resp_type == BIG_PKT) {		
		len = ceil(((float)tmp) / unit_pkt_max);
	}
	struct rte_mbuf *resp_list[len + 1];
	resp_list[i] = m_ack;
	
	if (pktgen.resp_type == BIG_PKT) {
#if 0
		struct rte_mbuf *m_table[DEFAULT_PKT_BURST];
		int ret = pg_pktmbuf_alloc_bulk(info->q[qid].resp_mp, m_table, len);
		if (unlikely(ret != 0)) {
			printf(" process_tcp_push-> pg_pktmbuf_alloc_bulk fail ret:%d\n", ret);
			goto _send;
		}
		struct ether_hdr *o_eth = rte_pktmbuf_mtod(m_ack, struct ether_hdr *);
		tcpip_t *o_tip = (tcpip_t *)&o_eth[1];
		seq_t init_seq = ntohl(o_tip->tcp.seq);
		uint32_t id = 0;
		while (tmp > 0) {
			m_push = process_tcp_push_2(m_ack, &tmp, id,  len, unit_pkt_max, m_table[id], init_seq);
			id++;
			i++;
			resp_list[i] = m_push;
		}
#else
		uint32_t id = 0;
		while (tmp > 0) {
			m_push = process_tcp_push(m_ack, pid, qid, &tmp, id, BIG_PKT, len, unit_pkt_max);
			if (!m_push) {
				printf("! process_tcp_push\n");
				goto _send;
			}
			id++;
			i++;
			resp_list[i] = m_push;
		}
#endif
	} else {
		tmp = 0;
		m_push = process_tcp_push(m_ack, pid, qid, &tmp, 0, SMALL_PKT, len, unit_pkt_max);	
		if (!m_push) {
			printf("! process_tcp_push\n");
			goto _send;
		}
		i++;
		resp_list[i] = m_push;
	}

_send:
	for (j = 0; j <= i; j++) {
		m_push = resp_list[j];
		pktgen_send_mbuf(m_push, pid, qid);
	}
	
	uint8_t lid = rte_lcore_id(); 
	((struct CORE_TCP_INFO*)pktgen.core_tcp_info[lid])->response_count++;
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);
}


static uint8_t is_more_pkt(struct rte_mbuf *mbuf)
{
	struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
   	tcpip_t *tip = (tcpip_t *)&eth[1];
	uint16_t tcp_option_len = (tip->tcp.offset >> 2) - sizeof(tcpHdr_t);
	if (tcp_option_len == 0) {
		return 0;
	}

	unsigned char *tcp_opt = (unsigned char *)&tip[1];
	while (tcp_option_len > 0) {
		uint8_t opcode = *tcp_opt++;
		uint8_t opsize;
		switch (opcode) {
		case TCPOPT_EOL:
			return 0;
		case TCPOPT_NOP:
			tcp_option_len--;
			continue;
		default:
			opsize = *tcp_opt++;
			if (opsize < 2 || opsize > tcp_option_len) {
				return 0;
			}
			switch (opcode) {
			case 253:
				if (opsize == 4) {
					return 1;
				}
				break;
			}
			tcp_opt += opsize - 2;
			tcp_option_len -= opsize;
		}
	}
	return 0;
}

void pktgen_process_tcp(struct rte_mbuf *m, uint32_t pid, uint32_t vlan, uint32_t qid)
{
	port_info_t *info = &pktgen.info[pid];
	uint8_t lid = rte_lcore_id();
	struct CORE_TCP_INFO *cti;
	uint64_t ol_flags = 0;
	uint16_t l2_len, l3_len, l4_len;
	seq_t next_seq, next_ack;

	cti = pktgen.core_tcp_info[lid];
	
	struct rte_mbuf *resp_buf = m;
	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	if (unlikely(!ip)) {
		printf("!IP");
		return;
	}
	if (unlikely(!tip)) {
		printf("!TIP,");
		return;
	}
	if (unlikely(! &(tip->tcp))) {
		printf("!TCP,");
		return;
	}
	if (unlikely(! &(tip->tcp.flags))) {
		printf("!TCPFLAGS,");
		return;
	}
	uint8_t is_syn_ack = 0;
	uint8_t req_flags = tip->tcp.flags;
#if 0
	char sdip_port[512] = {0};
	char sip_buff[64] = {0};
	char dip_buff[64] = {0};
	sprintf(sdip_port, "lid:%d,rcv:%s:%d->%s:%d,flag:%x", lid, 
		inet_ntop4(sip_buff, sizeof(sip_buff), (ip->src), 0xFFFFFFFF), 
		ntohs(tip->tcp.sport), 
		inet_ntop4(dip_buff, sizeof(dip_buff), (ip->dst), 0xFFFFFFFF), 
		ntohs(tip->tcp.dport),
		req_flags);
	pktgen_log_info("%s", sdip_port);
#endif
	do {
		if (req_flags == SYN_FLAG) {
			is_syn_ack = 1;
			tip->tcp.flags = SYN_FLAG | ACK_FLAG;
			cti->syn_count++;
			cti->syn_ack_count++;
			break;
		} else if (req_flags == ACK_FLAG) {
			return;		
		} else if (req_flags == (PSH_FLAG | ACK_FLAG)) {
			uint8_t not_end = is_more_pkt(m);
			if (not_end == 1) {
				tip->tcp.flags = ACK_FLAG;
				break;
			} else {
				cti->request_count++;
				process_http_request(resp_buf, pid, qid);
				return;
			}
		} else if (req_flags == (ACK_FLAG | FIN_FLAG)) {
			tip->tcp.flags = ACK_FLAG | FIN_FLAG;
			break;
		} else if (req_flags == FIN_FLAG) {
			tip->tcp.flags = ACK_FLAG;
			break;
		} else if (req_flags == RST_FLAG) {
			return;
		} else if (req_flags == (ACK_FLAG | RST_FLAG)) {
			return;
		} else {
#if 0
			char sdip_port[512] = {0};
			char sip_buff[64] = {0};
			char dip_buff[64] = {0};
			sprintf(sdip_port, "lid:%d,%s:%d->%s:%d", lid, 
					inet_ntop4(sip_buff, sizeof(sip_buff), (ip->src), 0xFFFFFFFF), 
					ntohs(tip->tcp.sport), 
					inet_ntop4(dip_buff, sizeof(dip_buff), (ip->dst), 0xFFFFFFFF), 
					ntohs(tip->tcp.dport));
			printf("rx_mp_cnt:%d,tcpflags:%x,%d,%s, tcp.win:%d\n", rte_mempool_count(info->q[qid].rx_mp), req_flags, req_flags, sdip_port, ntohs(tip->tcp.window));
#endif
			return;
		}
	} while (0);

	if (pktgen.add_tcp_ts == 1) {
		pkt_add_ts_opt(resp_buf, tip);
	} else {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t);
		resp_buf->data_len = resp_buf->pkt_len;
	}
	uint16Swap(&tip->tcp.sport, &tip->tcp.dport);

	next_seq = get_tcp_next_seq(tip);
	next_ack = get_tcp_next_ack(tip, ip, is_syn_ack);
	tip->tcp.seq = htonl(next_seq);
	tip->tcp.ack = htonl(next_ack);	
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset = (sizeof(tcpHdr_t) + TS_TOT_LEN) /sizeof(uint32_t) << 4;   /* Offset in words */
		l4_len = sizeof(tcpHdr_t) + TS_TOT_LEN;
	} else { 
		tip->tcp.offset = (sizeof(tcpHdr_t)/sizeof(uint32_t)) << 4;   /* Offset in words */
		l4_len = sizeof(tcpHdr_t);
	}
	tip->tcp.urgent = 0;
	tip->tcp.window = htons(5840);//DEFAULT_WND_SIZE
	inetAddrSwap(&ip->src, &ip->dst);
	
	ip->proto = PG_IPPROTO_TCP;
	ip->ttl = 64;
	ip->tlen = htons(resp_buf->pkt_len - (sizeof(struct ether_hdr)));

	// Swap the MAC addresses
	ethAddrSwap(&eth->d_addr, &eth->s_addr);
	
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	int tlen = resp_buf->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);

	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	resp_buf->l2_len = l2_len;
	resp_buf->l3_len = l3_len;
	resp_buf->l4_len = l4_len;
	resp_buf->ol_flags = ol_flags;
#endif
	
	pktgen_send_mbuf(resp_buf, pid,qid);
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);
	return;
}


// init tcp conn map
void init_tcp_info_container(struct CORE_TCP_INFO* cti)
{
	cti->request_count = 0;
	cti->response_count = 0;
	cti->syn_count = 0;
	cti->syn_ack_count = 0;
}

