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

#define HTTP_GET "GET /index.html?a=01234567890 HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: %s\r\n\r\n"
static char *HTTP_GET_CLOSE="GET /index.html?a=01234567890 HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: close\r\n\r\n";
static char *HTTP_UCID_CLOSE="GET /index.html?ucid=%s HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: close\r\n\r\n";
static char *HTTP_GET_KEEP="GET /index.html?a=01234567890 HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n";
static char *HTTP_UCID_KEEP="GET /index.html?ucid=%s HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n";

#define HTTP_REQ_HEADER_POST "POST /index HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n"
#define HTTP_SPLIT_POST "POST /?%sucid=%s HTTP/1.1\r\nUser-Agent: pktgen\r\nAccept: text/html\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n"
#define CONN_KEEP_ALIVE "keep-alive"
#define CONN_CLOSE "close"


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
static __inline__ void fill_pattern(uint8_t *p, uint32_t len, uint32_t type)
{
	uint32_t    i;
	switch(type) {
	case 1:                 // Byte wide ASCII pattern
		for(i = 0; i < len; i++)
			p[i] = "abcdefghijklmnopqrstuvwxyz012345"[i & 0x1f];
		break;
	default:
		memset(p, 0, len);
		break;
	}
}

void
pktgen_tcp_hdr_ctor(pkt_seq_t *pkt, tcpip_t *tip, __attribute__ ((unused)) int type)
{
	uint16_t	tlen;
	char *tcp_opt = NULL;
		
	if (pktgen.add_tcp_ts == 1) {
		pkt->pktSize 	= pkt->ether_hdr_size + sizeof(tcpip_t) + TS_TOT_LEN;
		memset((char *)tip, 0, sizeof(tcpip_t) + TS_TOT_LEN);
	} else {
		pkt->pktSize = pkt->ether_hdr_size + sizeof(tcpip_t);
		memset((char *)tip, 0, sizeof(tcpip_t));
	}
	
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;
	// Create the TCP header
	tip->ip.src = htonl(pkt->ip_src_addr);
	tip->ip.dst = htonl(pkt->ip_dst_addr);
	
	tlen = pkt->pktSize - (pkt->ether_hdr_size + sizeof(ipHdr_t));

	tip->ip.len = htons(tlen);
	tip->ip.proto = pkt->ipProto;

	tip->tcp.sport = htons(pkt->sport);
	tip->tcp.dport = htons(pkt->dport);
	uint32_t	seq = rand();
	tip->tcp.seq = htonl(seq);//DEFAULT_PKT_NUMBER
	tip->tcp.ack = htonl(seq);//DEFAULT_ACK_NUMBER
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset = ((sizeof(tcpHdr_t) + TS_TOT_LEN)/sizeof(uint32_t)) << 4; /* Offset in words */
	} else {
		tip->tcp.offset= (sizeof(tcpHdr_t)/sizeof(uint32_t)) << 4;   /* Offset in words */
	}
	tip->tcp.flags = SYN_FLAG;
	switch (pktgen.client_type) {
		case SYN_FLOOD:
			tip->tcp.flags	  	= SYN_FLAG; 
			break;
		case ACK_FLOOD:
			tip->tcp.flags	  	= ACK_FLAG; 
			break;
		case RST_FLOOD:
			tip->tcp.flags	  	= RST_FLAG; 
			break;
		case FIN_FLOOD:
			tip->tcp.flags	  	= FIN_FLAG; 
			break;
		default:
			tip->tcp.flags	  	= SYN_FLAG; 
			break;
	}
	
	tip->tcp.window	 	= htons(DEFAULT_WND_SIZE);
	tip->tcp.urgent	 	= 0;
	if (pktgen.add_tcp_ts == 1) {
		char *tcp_opt = (char *)&tip[1];
		if (pktgen.nop_head == 1) {
			*tcp_opt = TCPOPT_NOP;
			tcp_opt++;
			*tcp_opt = TCPOPT_NOP;
			tcp_opt++;
			*tcp_opt = TCPOPT_TIMESTAMP;
			tcp_opt++;
			*tcp_opt = TCPOLEN_TIMESTAMP;
			tcp_opt++;
			*(int *)tcp_opt = seq;
			tcp_opt += 4;
			*(int *)tcp_opt = 0;
		} else {
			*tcp_opt = TCPOPT_TIMESTAMP;
			tcp_opt++;
			*tcp_opt = TCPOLEN_TIMESTAMP;
			tcp_opt++;
			*(int *)tcp_opt = seq;
			tcp_opt += 4;
			*(int *)tcp_opt = 0;
			tcp_opt += 4;
			*tcp_opt = TCPOPT_NOP;
			tcp_opt++;
			*tcp_opt = TCPOPT_NOP;
		}
	}

	//tlen		 		= pkt->pktSize - pkt->ether_hdr_size;
	tip->tcp.cksum	  	= 0;//cksum(tip, tlen, 0);
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


void
pktgen_tcp_hdr_ctor_push_ack(pkt_seq_t *pkt, tcpip_t *tip)
{
	uint16_t		tlen;
	if (pktgen.add_tcp_ts == 1) {
		pkt->pktSize 		= pkt->ether_hdr_size + sizeof(tcpip_t) + TS_TOT_LEN;
	} else {
		pkt->pktSize 		= pkt->ether_hdr_size + sizeof(tcpip_t);
	}
	// Zero out the header space
	memset((char *)tip, 0, sizeof(tcpip_t));
	ipHdr_t      *ip    = (ipHdr_t *)&(tip->ip);
	ip->ttl                = 64;
	// Create the TCP header
	tip->ip.src		= htonl(pkt->ip_src_addr);
	tip->ip.dst		= htonl(pkt->ip_dst_addr);

	tip->ip.len		= htons(tlen);
	tip->ip.proto	   	= pkt->ipProto;

	tip->tcp.sport	= htons(pkt->sport);
	tip->tcp.dport	= htons(pkt->dport);
	uint32_t	seq		= rand();
	tip->tcp.seq		= htonl(seq);//DEFAULT_PKT_NUMBER
	tip->tcp.ack		= htonl(seq);//DEFAULT_ACK_NUMBER
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset 	= ((sizeof(tcpHdr_t) + TS_TOT_LEN)/sizeof(uint32_t)) << 4;   /* Offset in words */
	} else {
		tip->tcp.offset 	= ((sizeof(tcpHdr_t)/sizeof(uint32_t)) << 4);   /* Offset in words */
	}
	tip->tcp.flags	  	= ACK_FLAG|PSH_FLAG; 	//ACK_FLAG;	 /* ACK */
	tip->tcp.window	 = htons(DEFAULT_WND_SIZE);
	tip->tcp.urgent	 = 0;

	//tlen 				= pkt->pktSize - pkt->ether_hdr_size;
	tip->tcp.cksum	= 0;//cksum(tip, tlen, 0);
	if (pktgen.add_tcp_ts == 1) {
		char *tcp_opt = (char *)&tip[1];
		if (pktgen.nop_head == 1) {
			*tcp_opt = TCPOPT_NOP;
			tcp_opt++;
			*tcp_opt = TCPOPT_NOP;
			tcp_opt++;
			*tcp_opt = TCPOPT_TIMESTAMP;
			tcp_opt++;
			*tcp_opt = TCPOLEN_TIMESTAMP;
			tcp_opt++;
			*(int *)tcp_opt = seq;
			tcp_opt += 4;
			*(int *)tcp_opt = seq;
		} else {
			*tcp_opt = TCPOPT_TIMESTAMP;
			tcp_opt++;
			*tcp_opt = TCPOLEN_TIMESTAMP;
			tcp_opt++;
			*(int *)tcp_opt = seq;
			tcp_opt += 4;
			*(int *)tcp_opt = seq;
			tcp_opt += 4;
			*tcp_opt = TCPOPT_NOP;
			tcp_opt++;
			*tcp_opt = TCPOPT_NOP;
		}
	}
}


void add_cksum(tcpip_t *tip, ipHdr_t *ip, uint16_t tlen)
{
	tip->tcp.cksum = 0;
	char buf[64+tlen];
	tcp_fake_head tcpfh;
	tcpfh.src_ip   			= ip->src;
	tcpfh.dst_ip   			= ip->dst;
	tcpfh.mbz   			= 0;
	tcpfh.protocol_type 	= PG_IPPROTO_TCP;
	tcpfh.tcp_head_len 	= htons(tlen);
	memset(buf, 0, sizeof(tcp_fake_head)+tlen);
	rte_memcpy(buf, &tcpfh, sizeof(tcp_fake_head));
	rte_memcpy(buf+sizeof(tcp_fake_head), &tip->tcp, tlen);
	tip->tcp.cksum = cksum(buf, sizeof(tcp_fake_head) + tlen, 0);
}

void forward_pkt_reset_src_dst_tcp(struct rte_mbuf *mbuf, \
							range_info_t *range, port_info_t *info, uint8_t qid)
{
	uint16_t l2_len, l3_len, l4_len;
	uint64_t ol_flags = 0;
	
	struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	uint16_t sport = range->src_port;
	uint32_t p = range->src_ip;
	uint32_t dip = range->dst_ip;
	
	dip += range->dst_ip_inc;
	if (dip > range->dst_ip_max) {
		dip = range->dst_ip_min;
		sport += range->src_port_inc;
		if (sport > range->src_port_max || sport > 65535) {
			sport = range->src_port_min;
			p += range->src_ip_inc;
			if (p > range->src_ip_max) {
				p = range->src_ip_min;
			} else if (p < range->src_ip_min) {
				p = range->src_ip_max;
			}
		} else if (sport < range->src_port_min) {
			sport = range->src_port_max;
		}
	} else if (dip < range->dst_ip_min) {
		dip = range->dst_ip_max;
	}
	range->dst_ip = dip;
	tip->ip.dst = htonl(dip);

	range->src_port = sport;
	range->src_ip = p;
	tip->ip.src = htonl(p);
	tip->tcp.sport = htons(sport);
	tip->tcp.flags = PSH_FLAG|ACK_FLAG;
	
	if (pktgen.settings_file) {
		tip->ip.dst = htonl(pktgen.dst_vhost->ip_val);
		tip->tcp.dport = htons(pktgen.dst_vhost->port);
		pktgen.dst_vhost = pktgen.dst_vhost->next;
	}
	
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	uint32_t tlen = mbuf->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	l4_len = ((tip->tcp.offset & 0xf0) >> 4) * 4;
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	mbuf->ol_flags = ol_flags;
	mbuf->l2_len = l2_len;
	mbuf->l3_len = l3_len;
	mbuf->l4_len = l4_len;
#endif
}

void pkt_reset_src_dst_tcp(struct rte_mbuf *mbuf, range_info_t *range, port_info_t *info, uint8_t qid)
{
	char sbuff[128] = {0};
	char dbuff[128] = {0};
	uint16_t l2_len, l3_len, l4_len;
	uint64_t ol_flags = 0;
	
	struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	
	uint16_t sport = range->src_port;
	uint32_t p = range->src_ip;	
	if (pktgen.client_type != FORWARD_TEST) {
		sport += range->src_port_inc;
		if (sport > range->src_port_max || sport >= 65535) {
			sport = range->src_port_min;
			p += range->src_ip_inc;
			if (p < range->src_ip_min)
				p = range->src_ip_max;
			else if (p > range->src_ip_max)
				p = range->src_ip_min;
		} else if (sport < range->src_port_min) {
			sport = range->src_port_max;
		}
	} else {
		uint32_t dip = range->dst_ip;
		dip += range->dst_ip_inc;
		if (dip > range->dst_ip_max) {
			dip = range->dst_ip_min;
			sport += range->src_port_inc;
			if (sport > range->src_port_max || sport > 65535) {
				sport = range->src_port_min;
				p += range->src_ip_inc;
				if (p > range->src_ip_max) {
					p = range->src_ip_min;
				} else if (p < range->src_ip_min) {
					p = range->src_ip_max;
				}
			} else if (sport < range->src_port_min) {
				sport = range->src_port_max;
			}
		} else if (dip < range->dst_ip_min) {
			dip = range->dst_ip_max;
		}
		range->dst_ip = dip;
		tip->ip.dst = htonl(dip);
	}
	range->src_port = sport;
	range->src_ip = p;
	
	tip->ip.src = htonl(p);
	tip->tcp.sport = htons(sport);
	
	if (pktgen.settings_file) {
		tip->ip.dst = htonl(pktgen.dst_vhost->ip_val);
		tip->tcp.dport = htons(pktgen.dst_vhost->port);
		pktgen.dst_vhost = pktgen.dst_vhost->next;
	}
	
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;
#if 1
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	uint32_t tlen = mbuf->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	l4_len = (tip->tcp.offset >> 4) << 2;
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	mbuf->ol_flags = ol_flags;
	mbuf->l2_len = l2_len;
	mbuf->l3_len = l3_len;
	mbuf->l4_len = l4_len;
#endif
}

static struct rte_mbuf *tcp_process_conn_rst(struct rte_mbuf *m_ack, uint32_t pid, uint32_t qid)
{
	struct rte_mbuf *m;
	uint16_t l2_len, l3_len, l4_len;
	uint64_t ol_flags = 0;
	
	port_info_t *info = &pktgen.info[pid];
	m = rte_pktmbuf_alloc(info->q[qid].resp_mp);
	if (m == NULL) {
		printf("WARNING: tcp_process_conn_rst rte_pktmbuf_alloc_noreset return NULL\n");
		return NULL;
	}
	rte_memcpy((uint8_t *)m->buf_addr + m->data_off, (uint8_t *)m_ack->buf_addr + m_ack->data_off, m_ack->pkt_len);
	m->data_len = m_ack->data_len;
	m->pkt_len = m_ack->pkt_len;
	m->buf_len = m_ack->buf_len;
	
	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	tip->tcp.flags = RST_FLAG; 
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	uint32_t tlen = m->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	l4_len = ((tip->tcp.offset & 0xf0) >> 4) * 4;
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = get_psd_sum(ip);
	m->ol_flags = ol_flags;
	m->l2_len = l2_len;
	m->l3_len = l3_len;
	m->l4_len = l4_len;
#endif
	return m;
}

static seq_t get_tcp_next_seq(tcpip_t *tip)
{
	return ntohl(tip->tcp.ack);
}

static seq_t get_tcp_next_ack(tcpip_t *tip, ipHdr_t *ip, uint8_t is_syn_ack)
{
	seq_t pre_seq;
	
	seq_t next_ack;
	
	pre_seq = ntohl(tip->tcp.seq);
	uint32_t ip_total_len = ntohs(ip->tlen);
	uint16_t ip_header_len = (ip->vl & 15) << 2;
	uint16_t tcp_header_len = (tip->tcp.offset >> 4) << 2;
	uint32_t tcp_body_len = ip_total_len - ip_header_len - tcp_header_len;
	if (tcp_body_len == 0 || is_syn_ack == 1) {
		next_ack	= pre_seq + 1;
	} else {
		next_ack = pre_seq + tcp_body_len;
	}
	
	return next_ack;
}

static void pkt_add_ts_opt(struct rte_mbuf *m, tcpip_t *tip)
{
	int tsv = 0, tsev = 0;
	m->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + TS_TOT_LEN;
	m->data_len = m->pkt_len;
	uint16_t tcp_option_len = ((tip->tcp.offset >> 4) << 2) - sizeof(tcpHdr_t);
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

static void set_tcp_common_attr(struct rte_mbuf *mbuf, struct ether_hdr *eth, tcpip_t *tip, ipHdr_t *ip, uint16_t flags, uint8_t is_syn_ack)
{
	mbuf->data_len = mbuf->pkt_len;
	uint16_t tlen;
	seq_t next_seq;
	seq_t next_ack;
	uint64_t ol_flags = 0;
	uint16_t l2_len, l3_len, l4_len;
	
	next_seq = get_tcp_next_seq(tip);
	next_ack = get_tcp_next_ack(tip, ip, is_syn_ack);
	tip->tcp.seq = htonl(next_seq);
	tip->tcp.ack = htonl(next_ack);
	tip->tcp.flags = flags;
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset = ((sizeof(tcpHdr_t) + TS_TOT_LEN) / sizeof(uint32_t)) << 4;   /* Offset in words */
		l4_len = sizeof(tcpHdr_t) + TS_TOT_LEN;
	} else {
		tip->tcp.offset = (sizeof(tcpHdr_t) / sizeof(uint32_t)) << 4;   /* Offset in words */
		l4_len = sizeof(tcpHdr_t);
	}
	tip->tcp.urgent = 0;
	tip->tcp.window = htons(DEFAULT_WND_SIZE);
	uint16Swap(&tip->tcp.sport, &tip->tcp.dport);
	inetAddrSwap(&ip->src, &ip->dst);
	ip->ttl = 64;
	ip->proto = PG_IPPROTO_TCP;
	ip->tlen = htons(mbuf->pkt_len - (sizeof(struct ether_hdr)));
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);
	tlen = mbuf->pkt_len - (sizeof(struct ether_hdr) + sizeof(ipOverlay_t));
	add_cksum(tip, ip, tlen);
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	
	ip->cksum = 0;
	ol_flags |= PKT_TX_IPV4;
	ol_flags |= PKT_TX_IP_CKSUM;
	ol_flags |= PKT_TX_TCP_CKSUM;
	tip->tcp.cksum = 0;
	tip->tcp.cksum = get_psd_sum(ip);
	mbuf->ol_flags = ol_flags;
	mbuf->l2_len = l2_len;
	mbuf->l3_len = l3_len;
	mbuf->l4_len = l4_len;
#endif
	//Swap the MAC addresses
	ethAddrSwap(&eth->d_addr, &eth->s_addr);
}

void process_pack(struct rte_mbuf *m, uint32_t pid, uint32_t qid)
{
	switch (pktgen.client_type) {
	case NEW_CONN_TEST:
		tcp_process_conn(m, pid, qid); 
		break;
	case SHORT_REQ_TEST:
	case LONG_REQ_TEST:
	case FORWARD_TEST:
		pktgen_process_tcp(m, pid, qid);
		break;
	default:
		//printf("process_pack pktgen.client_type unvalid\n");
		return;
	}
}

void tcp_process_conn(struct rte_mbuf *mbuf, uint32_t pid, uint32_t qid)
{
	struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	if (tip->tcp.flags != (SYN_FLAG | ACK_FLAG)) {
		return;
	}
	
	uint8_t lid = rte_lcore_id();
	struct CORE_TCP_INFO *cti = pktgen.core_tcp_info[lid];
	cti->socket_tot_count++;
	cti->syn_ack_count++;
	struct rte_mbuf *m_ack, *m_rst;
	m_ack = send_tcp_ack(mbuf, 1);
	m_rst = tcp_process_conn_rst(m_ack, pid, qid);
	pktgen_send_mbuf(m_ack, pid, qid);
	if (m_rst) {
		pktgen_send_mbuf(m_rst, pid, qid);
	}
	port_info_t *info = &pktgen.info[pid];
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);
}

static struct rte_mbuf *send_tcp_ack(struct rte_mbuf *m, uint8_t is_syn_ack)
{
	struct rte_mbuf *resp_buf = m;
	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	if (pktgen.add_tcp_ts == 1) {
		pkt_add_ts_opt(resp_buf, tip);
	} else {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t);
		resp_buf->data_len = resp_buf->pkt_len;
	}
	set_tcp_common_attr(resp_buf, eth, tip, ip, ACK_FLAG, is_syn_ack);
	return resp_buf;
}

static struct rte_mbuf *gen_fin(struct rte_mbuf *m_ack, uint32_t pid, uint32_t qid)
{
	struct rte_mbuf *resp_buf;
	uint16_t l2_len, l3_len, l4_len;
	uint64_t ol_flags = 0;
	
	port_info_t *info = &pktgen.info[pid];
	resp_buf = rte_pktmbuf_alloc(info->q[qid].resp_mp);
	if (resp_buf == NULL) {
		printf("WARNING: gen_fin rte_pktmbuf_alloc_noreset returnl NULL\n");
		return NULL;
	}
	rte_memcpy((uint8_t *)resp_buf->buf_addr + resp_buf->data_off, 
				(uint8_t *)m_ack->buf_addr + m_ack->data_off, 
				m_ack->pkt_len);
	resp_buf->data_len = m_ack->data_len;
	resp_buf->pkt_len = m_ack->pkt_len;
	resp_buf->buf_len = m_ack->buf_len;
	
	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	// check tcp flags
	tip->tcp.flags = FIN_FLAG | ACK_FLAG;
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	ip->ttl = 64;
	uint32_t	tlen = resp_buf->pkt_len - (sizeof(struct ether_hdr));
	ip->tlen = htons(tlen);
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);	
	add_cksum(tip, ip, tlen - sizeof(ipHdr_t));
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	l4_len = sizeof(tcpHdr_t);
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
	return resp_buf;
}

static struct rte_mbuf *gen_req_get(struct rte_mbuf *m_ack, uint32_t pid, uint32_t qid)
{
	struct rte_mbuf *resp_buf = NULL;
	uint64_t ol_flags = 0;
	uint16_t l2_len, l3_len, l4_len;
	
	port_info_t *info = &pktgen.info[pid];
	resp_buf = rte_pktmbuf_alloc(info->q[qid].resp_mp);
	if (resp_buf == NULL) {
		printf("WARNING: gen_req_get rte_pktmbuf_alloc return NULL\n");
		return NULL;
	}
	rte_memcpy((uint8_t *)resp_buf->buf_addr + resp_buf->data_off,
				(uint8_t *)m_ack->buf_addr + m_ack->data_off,
				m_ack->pkt_len);
	resp_buf->data_len = m_ack->data_len;
	resp_buf->pkt_len  = m_ack->pkt_len;
	resp_buf->buf_len = m_ack->buf_len;

	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	// check tcp flags
	tip->tcp.flags = ACK_FLAG | PSH_FLAG;
	tip->tcp.urgent = 0;
	gen_http_req_data(tip, resp_buf, 0);
	
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	uint32_t tlen = resp_buf->pkt_len - (sizeof(struct ether_hdr));
	ip->tlen = htons(tlen);
	ip->ttl = 64;
#if 0
	ip->cksum = 0;
	ip->cksum = cksum(ip, sizeof(ipHdr_t), 0);	
	add_cksum(tip, ip, tlen - sizeof(ipHdr_t));
#else
	l2_len = sizeof(struct ether_hdr);
	l3_len = sizeof(ipHdr_t);
	l4_len = ((tip->tcp.offset & 0xf0) >> 4) << 2;
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

static uint8_t is_more_pkt(struct rte_mbuf *mbuf)
{
	struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    	tcpip_t *tip = (tcpip_t *)&eth[1];
	uint16_t tcp_option_len = ((tip->tcp.offset >> 4) * 4) - sizeof(tcpHdr_t);
	if (tcp_option_len == 0) {
		return 0;
	}

	unsigned char *tcp_opt = (char *)&tip[1];
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
			//printf("opcode:%u, size:%u\n", opcode, opsize);
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


static struct rte_mbuf *gen_req_tcp_http_post(struct rte_mbuf *m_ack, 
				uint32_t pid, uint32_t qid, uint32_t *post_left_len, 
				uint32_t cur_pkt_idx, uint16_t pkt_num, uint32_t single_body_len,
				char *http_req_header, uint32_t http_head_total_len, 
				uint32_t *http_head_left_len)
{
	struct rte_mbuf *req_buf;
	uint64_t ol_flags = 0;
	uint16_t l2_len, l3_len, l4_len;

	port_info_t *info = &pktgen.info[pid];
	req_buf = rte_pktmbuf_alloc(info->q[qid].resp_mp);
	if (req_buf == NULL) { 
		printf("warning: tcp_process_conn_rst rte_pktmbuf_alloc return NULL\n");
		return NULL;
	}
	rte_memcpy((uint8_t *)req_buf->buf_addr + req_buf->data_off,
				(uint8_t *)m_ack->buf_addr + m_ack->data_off,
				m_ack->pkt_len);
	req_buf->data_len = m_ack->data_len;
	req_buf->pkt_len = m_ack->pkt_len;
	req_buf->buf_len = m_ack->buf_len;

	struct ether_hdr *eth = rte_pktmbuf_mtod(req_buf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	struct ether_hdr *eth2	= rte_pktmbuf_mtod(m_ack, struct ether_hdr *);
	tcpip_t *tip2	= (tcpip_t *)&eth2[1];
	
	//check tcp flags
	tip->tcp.flags = ACK_FLAG | PSH_FLAG;
	uint8_t tcp_opt_len = 0;
	char *pt = (char*)&tip[1];
	if (pktgen.add_tcp_ts == 1) {
		pt += TS_TOT_LEN;
	}

	//add tcp option except the last packet
	if (pkt_num - 1 > cur_pkt_idx) {
		tcp_opt_len = TCP_OPT_253_LEN;
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
	
	uint32_t single_need_len = single_body_len;
	uint32_t single_real_len = 0;
	tip->tcp.seq = htonl(ntohl(tip2->tcp.seq) + cur_pkt_idx * single_body_len);
	//tcp offset + tcp_opt_len
	if (pktgen.add_tcp_ts == 1) {
		tip->tcp.offset = ((sizeof(tcpHdr_t) + TS_TOT_LEN + tcp_opt_len)/sizeof(uint32_t)) << 4;
		l4_len = sizeof(tcpHdr_t) + TS_TOT_LEN + tcp_opt_len;
	} else {
		tip->tcp.offset = ((sizeof(tcpHdr_t) + tcp_opt_len)/sizeof(uint32_t)) << 4;
		l4_len = sizeof(tcpHdr_t) + tcp_opt_len;
	}

      if ((*post_left_len) > single_body_len) {
	  	single_real_len = single_body_len;
	  	//http req header
	  	if ((*http_head_left_len) >= single_real_len) {
			rte_memcpy(pt, 
				http_req_header+(http_head_total_len - (*http_head_left_len)), 
				single_real_len);
			single_need_len -= single_real_len;
			pt += single_real_len;
			(*http_head_left_len) -= single_real_len;
			if ((*http_head_left_len) <= 0) {
				(*http_head_left_len) = 0;
			}
	  	} else {
		  	if ((*http_head_left_len) > 0) {
				rte_memcpy(pt, 
					http_req_header+(http_head_total_len - (*http_head_left_len)), 
					(*http_head_left_len));
				single_need_len -= (*http_head_left_len);
				pt += (*http_head_left_len);
				(*http_head_left_len) = 0;
		  	}
	  	}
      } else {
	      single_real_len = (*post_left_len);
		if ((*http_head_left_len) > 0) {
			rte_memcpy(pt, 
				http_req_header+(http_head_total_len - (*http_head_left_len)), 
				(*http_head_left_len));
			single_need_len -= (*http_head_left_len);
			pt += (*http_head_left_len);
			(*http_head_left_len) = 0;
		}
      }

	if (single_need_len) {
		//fill_pattern(pt, single_need_len, 1);
		memset(pt, 'c', single_need_len);
	}
	
	(*post_left_len) -= single_real_len;
	if (*post_left_len <= 0) {
		(*post_left_len) = 0;
	} 
	
	if (pktgen.add_tcp_ts == 1) {
		req_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_len + TS_TOT_LEN + single_real_len;
	} else {
		req_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + tcp_opt_len + single_real_len;
	}
	req_buf->data_len = req_buf->pkt_len; 
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	uint32_t tlen = req_buf->pkt_len - (sizeof(struct ether_hdr));
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
	req_buf->l2_len = l2_len;
	req_buf->l3_len = l3_len;
	req_buf->l4_len = l4_len;
	req_buf->ol_flags = ol_flags;
#endif
	return req_buf;
}


void fin_req(struct rte_mbuf *mbuf, uint32_t pid, uint32_t qid)
{
	/*ack*/
	struct rte_mbuf *m_ack, *m_fin;
	m_ack = send_tcp_ack(mbuf, 0);
	m_fin = gen_fin(m_ack, pid, qid);
	pktgen_send_mbuf(m_ack, pid, qid);
	if (m_fin) {
		pktgen_send_mbuf(m_fin, pid, qid);
	}
	port_info_t *info = &pktgen.info[pid];
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);	
}


void http_get_req(struct rte_mbuf *mbuf, tcpip_t *tip, ipHdr_t *ip, uint32_t pid, uint32_t qid)
{
	struct rte_mbuf *m_ack, *m_push;
	m_ack = send_tcp_ack(mbuf, 0);
	m_push = gen_req_get(m_ack, pid, qid);
	pktgen_send_mbuf(m_ack, pid, qid);
	if (m_push) {
		pktgen_send_mbuf(m_push, pid, qid);
	}
	uint8_t lid = rte_lcore_id();
	struct CORE_TCP_INFO *cti = pktgen.core_tcp_info[lid];
	cti->request_count++;
	port_info_t *info = &pktgen.info[pid];
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);	
}


void resp_ack_next_push(struct rte_mbuf *mbuf, tcpip_t *tip, ipHdr_t *ip, uint32_t pid, uint32_t qid)
{
	if (pktgen.req_method == METHOD_POST) {
		http_req_post(mbuf, tip, ip, pid, qid);
	} else {
		http_get_req(mbuf, tip, ip, pid, qid);
	}
}


void http_req_post(struct rte_mbuf *mbuf, tcpip_t *tip, ipHdr_t *ip, uint32_t pid, uint32_t qid)
{
	/*ack*/
	struct rte_mbuf *m_ack, *m_push;
	uint32_t i = 0;
	char http_req_header[1024] = {0};
	uint32_t cur_pkt_idx = 0;
	if (pktgen.gen_ucid) {
		char http_req_fake[256] = {0};
		char key_value[32] = {0};
		char tmp_str[128] = {0};
		
		sprintf(tmp_str, "%d", rand());
		int len = strlen(tmp_str);
		int total_len = 25;
		int need_len = total_len / len;
		int left_len = total_len % len;
		for (i = 0; i < need_len; i++) {
			rte_memcpy(key_value + i * len, tmp_str, len);
		}
		rte_memcpy(key_value + i * len, tmp_str, left_len);

		if (pktgen.gen_pad_len) {
			for (i = 0; i < pktgen.gen_pad_len - 1; i++) {
				http_req_fake[i] = 'a';
			}
			http_req_fake[i++] = '&';
		}
		sprintf(http_req_header, HTTP_SPLIT_POST, http_req_fake, key_value, pktgen.req_pkt_size);
	} else {
		sprintf(http_req_header, HTTP_REQ_HEADER_POST, pktgen.req_pkt_size);
	}	
	
	uint32_t http_header_total_len = strlen(http_req_header);
	uint32_t http_header_left_len = http_header_total_len;
	if (pktgen.req_pkt_size < http_header_total_len) {
		pktgen.req_pkt_size = http_header_total_len;
	}
	uint32_t post_total_len = pktgen.req_pkt_size;
	uint32_t post_left_len = post_total_len;
	uint32_t single_body_len = 0;
	if (pktgen.add_tcp_ts == 1) {
		single_body_len = pktgen.mtu - (sizeof(struct ether_hdr) + sizeof(tcpip_t) + TS_TOT_LEN + TCP_OPT_253_LEN);
	} else {
		single_body_len = pktgen.mtu - (sizeof(struct ether_hdr) + sizeof(tcpip_t) + TCP_OPT_253_LEN);
	}
	uint16_t pkt_num = ceil(((float)(post_total_len))/single_body_len);
	struct rte_mbuf *resp_list[1 + pkt_num];
	m_ack = send_tcp_ack(mbuf, 0);
	resp_list[cur_pkt_idx] = m_ack;
	
	while (post_left_len > 0) {
		m_push = gen_req_tcp_http_post(m_ack, pid, qid, &post_left_len, cur_pkt_idx, pkt_num, 
			single_body_len, http_req_header, http_header_total_len, &http_header_left_len);
		if (unlikely(m_push == NULL)) {
			printf("! gen_req_tcp_http_post\n");
			break;
		}
		cur_pkt_idx++;
		resp_list[cur_pkt_idx] = m_push;
	}

      if (pktgen.req_disorder) {
		pktgen_send_mbuf(resp_list[0], pid, qid);
		for (i = cur_pkt_idx; i > 0; i--) {
			pktgen_send_mbuf(resp_list[i], pid, qid);
		}
      } else {
	  	for (i = 0; i <= cur_pkt_idx; i++) {
			pktgen_send_mbuf(resp_list[i], pid, qid);
		}
      }

	uint8_t lid = rte_lcore_id();
	struct CORE_TCP_INFO *cti = pktgen.core_tcp_info[lid];
	cti->request_count++;
	port_info_t *info = &pktgen.info[pid];
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);	
}

uint16_t gen_http_req_data(tcpip_t *tip, struct rte_mbuf *mbuf, uint8_t keep_alive)
{
	uint16_t http_len = 0;
	char key_value[32] = {0};
	char data[1024] = {0};
	int i;
	char *pt = (char *)&tip[1];
	
	if (pktgen.gen_ucid) {
		char tmp_str[128] = {0};
		sprintf(tmp_str, "%d", rand());
		int len = strlen(tmp_str);
		int total_len = 25;
		int need_len = total_len / len;
		int left_len = total_len % len;
		for (i = 0; i < need_len; i++) {
			rte_memcpy(key_value + i * len, tmp_str, len);
		}
		rte_memcpy(key_value + i * len, tmp_str, left_len);
	}

	if (pktgen.add_tcp_ts == 1) {
		pt += TS_TOT_LEN;
	}
	
	if (keep_alive == 0) {
		if (pktgen.gen_ucid) {
			sprintf(data, HTTP_UCID_CLOSE, key_value);
			http_len = strlen(data);
			rte_memcpy(pt, data, http_len);
		} else {
			http_len = strlen(HTTP_GET_CLOSE);
			rte_memcpy(pt, HTTP_GET_CLOSE, http_len);
		}
	} else {
		if (pktgen.gen_ucid) {
			sprintf(data, HTTP_UCID_KEEP, key_value);
			http_len = strlen(data);
			rte_memcpy(pt, data, http_len);
		} else {
			http_len = strlen(HTTP_GET_KEEP);
			rte_memcpy(pt, HTTP_GET_KEEP, http_len);
		}
	}
	if (pktgen.add_tcp_ts == 1) {
		mbuf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + TS_TOT_LEN + http_len;
	} else {
		mbuf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t) + http_len;
	}
	mbuf->data_len = mbuf->pkt_len;
	pktgen.conn_crt += 1;
	return http_len;
}

void pktgen_process_tcp(struct rte_mbuf *m, uint32_t pid, uint32_t qid)
{
	port_info_t *info = &pktgen.info[pid];
	struct rte_mbuf *resp_buf = m;
	struct ether_hdr *eth = rte_pktmbuf_mtod(resp_buf, struct ether_hdr *);
	tcpip_t *tip = (tcpip_t *)&eth[1];
	ipHdr_t *ip = (ipHdr_t *)&(tip->ip);
	uint32_t flags;
	uint8_t lid = rte_lcore_id(); 
	struct CORE_TCP_INFO *cti	= pktgen.core_tcp_info[lid];
	
	// check tcp flags
	int req_flags 	= (int)(tip->tcp.flags);
	uint8_t is_syn_ack = 0;
#if 0
	char sip_buff[64] = {0}, dip_buff[64] = {0};
	char sdip_port[256] = {0};
	sprintf(sdip_port, "lid:%d,rcv:%s:%d->%s:%d, flags:%x", lid, 
		inet_ntop4(sip_buff, sizeof(sip_buff), (ip->src), 0xFFFFFFFF), 
		ntohs(tip->tcp.sport), 
		inet_ntop4(dip_buff, sizeof(dip_buff), (ip->dst), 0xFFFFFFFF), 
		ntohs(tip->tcp.dport), req_flags);
	pktgen_log_info("%s", sdip_port);
#endif
	do {
		if (req_flags == SYN_FLAG) {
			is_syn_ack = 1;
			flags	  = SYN_FLAG | ACK_FLAG;  
			break;
		} else if (req_flags == SYN_ACK) {
			is_syn_ack = 1;
			cti->socket_tot_count++;
			cti->syn_ack_count++;
			if (pktgen.client_type == FORWARD_TEST) {
				cti->socket_cur_count++;
			}
			resp_ack_next_push(m, tip, ip, pid, qid);
			return;
		} else if (req_flags == PUSH_ACK) {
			cti->response_count++;
			uint8_t not_end = is_more_pkt(m);
			if (not_end == 1) {
				flags	 = ACK_FLAG;
				break;
			} else {
				if (pktgen.client_type != FORWARD_TEST) {
					return fin_req(m, pid, qid);
				} else {					
#if 0
					char sip_buff[64] = {0}, dip_buff[64] = {0};
					char sdip_port[256] = {0};
					
					sprintf(sdip_port, "lid:%d,%s:%d->%s:%d", lid, 
							inet_ntop4(sip_buff, sizeof(sip_buff), (ip->src), 0xFFFFFFFF), 
							ntohs(tip->tcp.sport), 
							inet_ntop4(dip_buff, sizeof(dip_buff), (ip->dst), 0xFFFFFFFF), 
							ntohs(tip->tcp.dport));
					printf("resp_ack_next_push:%s, cur_count:%ld\n", sdip_port, cti->socket_cur_count);
#endif
					return resp_ack_next_push(m, tip, ip, pid, qid);
				}
				return;
			}
			break;
		} else if (req_flags == FIN_ACK) {
			flags = ACK_FLAG;
			break; 
		} else if (req_flags == FIN_FLAG) {
			flags = ACK_FLAG;
			break; 
		} else if (req_flags == ACK_FLAG) {
			return;
		} else if (req_flags == (RST_FLAG | ACK_FLAG)) {
			return;
		} else if (req_flags == RST_FLAG) {
			if (pktgen.client_type == FORWARD_TEST) {
				cti->socket_cur_count--;
				if (cti->socket_cur_count <  0) {
					cti->socket_cur_count = 0;
				}
			}
			return;
		} else {
			char sdip_port[512] = {0};
			char sip_buff[64] = {0};
			char dip_buff[64] = {0};
			sprintf(sdip_port, "lid:%d,%s:%d->%s:%d", lid, 
					inet_ntop4(sip_buff, sizeof(sip_buff), (ip->src), 0xFFFFFFFF), 
					ntohs(tip->tcp.sport), 
					inet_ntop4(dip_buff, sizeof(dip_buff), (ip->dst), 0xFFFFFFFF), 
					ntohs(tip->tcp.dport));
			printf("req_falgs:%x,%d=>%s\n", req_flags, req_flags, sdip_port);
			flags = RST_FLAG;
			break;
		}
	}while(0);

	if (pktgen.add_tcp_ts == 1) {
		pkt_add_ts_opt(resp_buf, tip);
	} else {
		resp_buf->pkt_len = sizeof(struct ether_hdr) + sizeof(tcpip_t);
		resp_buf->data_len = resp_buf->pkt_len;
	}
	set_tcp_common_attr(resp_buf, eth, tip, ip, flags, is_syn_ack);	
	pktgen_send_mbuf(resp_buf, pid, qid);
	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);
	return;
}

// init tcp conn map
void init_tcp_info_container(struct CORE_TCP_INFO* cti)
{
	uint8_t lid = rte_lcore_id();
	uint32_t i;
	
	for (i = 0; i < CONN_MAX; i++) {
		cti->tcp_info_list[i] = NULL;
	}
	cti->socket_cur_count = 0;
	cti->socket_tot_count = 0;
	cti->request_count = 0;
	cti->response_count = 0;
	
	gettimeofday(&(cti->start_time), NULL);
	gettimeofday(&(cti->latest_check_time), NULL);
	gettimeofday(&(cti->latest_req_time), NULL);
	
	cti->act_queue_tail = NULL;
	cti->act_queue_head = NULL;
	cti->syn_count = 0;
	cti->syn_ack_count = 0;
}

