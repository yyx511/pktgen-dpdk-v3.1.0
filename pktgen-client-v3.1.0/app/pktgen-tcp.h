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

#ifndef _PKTGEN_TCP_H_
#define _PKTGEN_TCP_H_

#include "inet.h"

#include "pktgen-seq.h"
#include "jhash.h"
#include "pktgen-range.h"
#include "pktgen-port-cfg.h"

#define CONN_MAX 10000000
#define U_HASHKEY 1234567890

typedef struct TCP_Fake_Head
{
	uint32_t  src_ip;
	uint32_t  dst_ip;
	uint8_t  mbz;
	uint8_t  protocol_type;
	uint16_t  tcp_head_len;
} __attribute__((__packed__)) tcp_fake_head;


enum { 
	FIN_ACK  = FIN_FLAG | ACK_FLAG,
	PUSH_ACK  = PSH_FLAG | ACK_FLAG,
	SYN_ACK  = SYN_FLAG | ACK_FLAG
};

/*
 *      TCP State Values
 */
enum {
	S_NONE = 0,
	S_ESTABLISHED,
	S_SYN_SENT,
	S_SYN_RECV,
	S_FIN_WAIT,
	S_TIME_WAIT,
	S_CLOSE,
	S_CLOSE_WAIT,
	S_LAST_ACK,
	S_LISTEN,
	S_SYNACK,
	S_LAST
};

enum {
	VALID  = 0,
	INVALID,
	OVER_LIMIT_SOCKET,
	OVER_LIMIT_REQ,
	DUPLICATE,
	CLOSED
};

typedef struct TCP_INFO{
	uint16_t 			req_cnt;
	uint8_t 			flags;
	unsigned int		seq;
	unsigned int		ack;
	
	uint32_t 			sip;
	uint16_t 			sport;
	uint32_t 			dip;
	uint16_t 			dport;	
	struct ether_addr	d_mac_addr;
	struct ether_addr	s_mac_addr;
	
	struct  timeval 	last_time;
	struct 	TCP_INFO* 	prev;
	struct 	TCP_INFO* 	next;
	struct 	TCP_INFO* 	act_queue_prev;
	struct 	TCP_INFO* 	act_queue_next;
} __attribute__((__packed__)) t_tcp_info;


typedef struct CORE_TCP_INFO{
	struct 		TCP_INFO* 	tcp_info_list[CONN_MAX];
	struct 		TCP_INFO* 	act_queue_head;
	struct 		TCP_INFO* 	act_queue_tail;
	
	uint32_t 				pid;
	uint32_t 				qid;
	
	uint64_t    			socket_cur_count;
	struct  	timeval 	latest_check_time;
	struct  	timeval 	latest_req_time;
	
	uint64_t				socket_tot_count;
	uint64_t				request_count;
	uint64_t				response_count;
	struct 		timeval 	start_time;
	struct 		timeval 	stop_time;
	
	uint64_t				syn_count;
	uint64_t				syn_ack_count;
	
} __attribute__((__packed__)) t_core_tcp_info;


extern void pktgen_tcp_hdr_ctor(pkt_seq_t * pkt, tcpip_t * tip, __attribute__ ((unused)) int type);
extern void pktgen_tcp_hdr_ctor_ack(pkt_seq_t *pkt, tcpip_t *tip);


void pktgen_process_tcp( struct rte_mbuf * m, uint32_t pid, uint32_t qid );

void init_tcp_info_container(struct CORE_TCP_INFO* cti);
void resp_ack_next_push(struct rte_mbuf * mbuf, tcpip_t * tip, ipHdr_t * ip, uint32_t pid, uint32_t qid);
uint16_t gen_http_req_data(tcpip_t * tip, struct rte_mbuf * resp_buf, uint8_t keep_alive);
void tcp_process_conn( struct rte_mbuf * m, uint32_t pid, uint32_t qid );
void process_pack( struct rte_mbuf * m, uint32_t pid, uint32_t qid );
static void set_tcp_common_attr(struct rte_mbuf * mbuf, struct ether_hdr *eth, tcpip_t * tip, ipHdr_t * ip, uint16_t flags, uint8_t is_syn_ack);
static struct rte_mbuf * tcp_process_conn_rst(struct rte_mbuf * m_ack, uint32_t pid, uint32_t qid);
void pkt_reset_src_dst_tcp( struct rte_mbuf * mbuf, range_info_t * range, port_info_t * info, uint8_t qid);
static struct rte_mbuf * send_tcp_ack(struct rte_mbuf * m, uint8_t is_syn_ack);
static struct rte_mbuf * gen_req_get( struct rte_mbuf * m_ack, uint32_t pid, uint32_t qid );

static seq_t get_tcp_next_seq(tcpip_t * tip);
static seq_t get_tcp_next_ack(tcpip_t * tip, ipHdr_t * ip, uint8_t is_syn_ack);

static struct rte_mbuf *gen_req_tcp_http_post(struct rte_mbuf *m_ack, 
				uint32_t pid, uint32_t qid, uint32_t *post_left_len, 
				uint32_t cur_pkt_idx, uint16_t pkt_num, uint32_t single_body_len,
				char *http_req_header, uint32_t http_head_total_len, uint32_t *http_head_left_len);

void http_req_post(struct rte_mbuf * mbuf, tcpip_t * tip, ipHdr_t * ip, uint32_t pid, uint32_t qid);
void fin_req(struct rte_mbuf * mbuf, uint32_t pid, uint32_t qid);
static struct rte_mbuf * gen_fin( struct rte_mbuf * m_ack, uint32_t pid, uint32_t qid );

#endif	// _PKTGEN_TCP_H_

