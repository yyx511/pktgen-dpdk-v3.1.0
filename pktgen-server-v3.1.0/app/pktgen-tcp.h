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

#define CONN_MAX 10000000
#define U_HASHKEY 1234567890


//tcp cksum 虚头部
typedef struct TCP_Fake_Head
{
	uint32_t  src_ip;
	uint32_t  dst_ip;
	uint8_t  mbz;
	uint8_t  protocol_type;
	uint16_t  tcp_head_len;
} __attribute__((__packed__)) tcp_fake_head;


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

typedef struct TCP_INFO{
	uint8_t 			flags;
	uint32_t 			sip;
	uint16_t 			sport;
	uint32_t 			dip;
	uint16_t 			dport;	
	struct  timeval 	last_time;
	struct TCP_INFO	* 	next;
} __attribute__((__packed__)) t_tcp_info;

typedef struct CORE_TCP_INFO{
	struct TCP_INFO* 	tcp_info_map[CONN_MAX];
	uint64_t			request_count;
	uint64_t			response_count;	
	uint64_t			syn_count;
	uint64_t			syn_ack_count;
	
} __attribute__((__packed__)) t_core_tcp_info;



void init_tcp_info_container();
extern void pktgen_tcp_hdr_ctor(pkt_seq_t * pkt, tcpip_t * tip, __attribute__ ((unused)) int type);
void pktgen_process_tcp( struct rte_mbuf * m, uint32_t pid, uint32_t vlan, uint32_t qid );
void tcp_process_conn( struct rte_mbuf * m, uint32_t pid, uint32_t vlan, uint32_t qid );

static struct rte_mbuf * gen_ack(struct rte_mbuf * m);

#endif	// _PKTGEN_TCP_H_

