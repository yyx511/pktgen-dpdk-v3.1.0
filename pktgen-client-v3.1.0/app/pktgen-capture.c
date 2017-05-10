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

#include "pktgen-capture.h"

#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>

#include "pktgen-cmds.h"
#include "pktgen-log.h"


/**************************************************************************//**
*
* pktgen_packet_capture_init - Initialize memory and data structures for packet
* capture.
*
* DESCRIPTION
* Initialization of memory zones and data structures for packet capture
* storage.
*
* PARAMETERS:
* capture: capture_t struct that will keep a pointer to the allocated memzone
* socket_id: Socket where the memzone will be reserved
*
* RETURNS: N/A
*
* SEE ALSO:
*/
void pktgen_packet_capture_init(capture_t *capture, int socket_id)
{
	char memzone_name[RTE_MEMZONE_NAMESIZE];

	if (!capture)
		return;

	capture->lcore    = RTE_MAX_LCORE;
	capture->port     = RTE_MAX_ETHPORTS;
	capture->mem_used = 0;

	scrn_snprintf(memzone_name, sizeof(memzone_name), "Capture_MZ_%d", socket_id);
	capture->mz = rte_memzone_reserve(memzone_name, 0, socket_id,
			RTE_MEMZONE_1GB | RTE_MEMZONE_SIZE_HINT_ONLY);
}


/**************************************************************************//**
*
* pktgen_set_capture - Enable or disable packet capturing
*
* DESCRIPTION
* Set up packet capturing for the given ports and make sure only 1 port per
* socket is in capture mode.
*
* PARAMETERS:
* info: port to capture from
* onOff: enable or disable capturing?
*
* RETURNS: N/A
*
* SEE ALSO:
*/

void
pktgen_set_capture(port_info_t * info, uint32_t onOff)
{
	if ( onOff == ENABLE_STATE ) {
		/* Enabling an aleady enabled port is a no-op */
		if ( rte_atomic32_read(&info->port_flags) & CAPTURE_PKTS )
			return;

		if (get_port_rxcnt(pktgen.l2p, info->pid) == 0) {
			pktgen_log_warning("Port %d has no RX queue: capture is not possible", info->pid);
			return;
		}

		// Find an lcore that can capture packets for the requested port
		uint8_t lid_idx, lid, rxid;
		for (lid_idx = 0; lid_idx < get_port_nb_lids(pktgen.l2p, info->pid); ++lid_idx) {
			lid = get_port_lid(pktgen.l2p, info->pid, lid_idx);
			for (rxid = 0; rxid < get_lcore_rxcnt(pktgen.l2p, lid); ++rxid)
				if (get_rx_pid(pktgen.l2p, lid, rxid) == info->pid)
					goto found_rx_lid;
		}
		lid = RTE_MAX_LCORE;

found_rx_lid:
		if (lid == RTE_MAX_LCORE) {
			pktgen_log_warning("Port %d has no rx lcore: capture is not possible", info->pid);
			return;
		}

		// Get socket of the selected lcore and check if capturing is possible
		uint8_t sid = pktgen.core_info[lid].s.socket_id;
		if (pktgen.capture[sid].mz == NULL) {
			pktgen_log_warning("No memory allocated for capturing on socket %d, are hugepages allocated on this socket?", sid);
			return;
		}

		if (pktgen.capture[sid].lcore != RTE_MAX_LCORE) {
			pktgen_log_warning("Lcore %d is already capturing on socket %d and only 1 lcore can capture on a socket. Disable capturing on the port associated with this lcore first.", pktgen.capture[sid].lcore, sid);
			return;
		}

		// Everything checks out: enable packet capture
		pktgen.capture[sid].mem_used = 0;
		pktgen.capture[sid].lcore = lid;
		pktgen.capture[sid].port = info->pid;

		// Write end-of-data sentinel to start of capture memory. This
		// effectively clears previously captured data.
		*(unsigned char *)pktgen.capture[sid].mz->addr = 0;

		pktgen_set_port_flags(info, CAPTURE_PKTS);

		pktgen_log_info("Capturing on port %d, lcore %d, socket %d; buffer size: %.2f MB (~%.2f seconds for 64 byte packets at line rate)",
				info->pid, lid, sid,
				(double)pktgen.capture[sid].mz->len / (1024 * 1024),
				(double)pktgen.capture[sid].mz->len /
					(66 /* 64 bytes payload + 2 bytes for payload size */
					* ((double)info->link.link_speed * 1000 * 1000 / 8) /* Xbit -> Xbyte */
					/ 84) /* 64 bytes payload + 20 byte etherrnet frame overhead: 84 bytes per packet */
		);
	}
	else {
		if (!(rte_atomic32_read(&info->port_flags) & CAPTURE_PKTS))
			return;

		// This should never happen: capture cannot have been enabled when
		// this condition is true.
		if (get_port_rxcnt(pktgen.l2p, info->pid) == 0) {
			pktgen_log_warning("Port %d has no RX queue: capture is not possible", info->pid);
			return;
		}

		int sid;
		for (sid = 0; sid < RTE_MAX_NUMA_NODES; ++sid)
			if (pktgen.capture[sid].port == info->pid)
				break;

		// This should never happen.
		if (sid == RTE_MAX_NUMA_NODES) {
			pktgen_log_error("Could not find socket for port %d", info->pid);
			return;
		}

		/* If there is previously captured data in the buffer, write it
		 * to disk. */
		if (pktgen.capture[sid].mem_used > 0) {
			pcap_t *pcap;
			pcap_dumper_t *pcap_dumper;
			struct pcap_pkthdr pcap_hdr;

			unsigned char *pkt, *buf_end;
			uint16_t pkt_len, data_len;
			size_t mem_dumped = 0;
			unsigned int pct = 0;

			char status[256];
			sprintf(status, "\r    Dumping ~%.2fMB of captured data to disk: 0%%",
					(double)pktgen.capture[sid].mem_used / (1024 * 1024));
			printf_status("%s", status);

			pcap = pcap_open_dead(DLT_EN10MB, 65535);
			// TODO: make filename unique (timestamp in filename?)
			pcap_dumper = pcap_dump_open(pcap, "pktgen.pcap");

			pkt = pktgen.capture[sid].mz->addr;
			buf_end = (unsigned char *)pktgen.capture[sid].mz->addr + pktgen.capture[sid].mz->len;
			while (pkt + 2 * sizeof(uint16_t) < buf_end) {
				pkt_len  = *(uint16_t *)pkt;
				pkt += sizeof(uint16_t);
				data_len = *(uint16_t *)pkt;
				pkt += sizeof(uint16_t);

				/* Check for end-of-data sentinel */
				if (pkt_len == 0)
					break;

				//pcap_hdr.ts     = xxx;	// FIXME use real timestamp
				pcap_hdr.len    = pkt_len;
				pcap_hdr.caplen = data_len;

				pcap_dump((u_char *)pcap_dumper, &pcap_hdr, (const u_char *)pkt);

				pkt += data_len;
				mem_dumped = pkt - (unsigned char *)pktgen.capture[sid].mz->addr;

				// The amount of data to dump to disk, is potentially very large
				// (a few gigabytes), so print a percentage counter.
				if (pct < mem_dumped * 100 / pktgen.capture[sid].mem_used) {
					pct = mem_dumped * 100 / pktgen.capture[sid].mem_used;

					if (pct % 10 == 0)
						strncatf(status, "%d%%", pct);
					else if (pct % 2 == 0)
						strncatf(status, ".");

					printf_status("%s", status);
				}
			}
			printf_status("\r");

			pcap_dump_close(pcap_dumper);
			pcap_close(pcap);
		}

		pktgen.capture[sid].mem_used = 0;
		pktgen.capture[sid].lcore = RTE_MAX_LCORE;
		pktgen.capture[sid].port = RTE_MAX_ETHPORTS;

		pktgen_clr_port_flags(info, CAPTURE_PKTS);
	}
}



/**************************************************************************//**
*
* pktgen_packet_capture_bulk - Capture packets to memory.
*
* DESCRIPTION
* Capture packet contents to memory, so they can be written to disk later.
*
* A captured packet is stored as follows:
* - uint16_t: untruncated packet length
* - uint16_t: size of actual packet contents that are stored
* - unsigned char[]: packet contents (number of bytes stored equals previous
*       uint16_t)
*
* RETURNS: N/A
*
* SEE ALSO:
*/

void
pktgen_packet_capture_bulk(struct rte_mbuf ** pkts, int nb_dump, capture_t *capture )
{
	unsigned int plen, i;
	struct rte_mbuf *pkt;
	unsigned char *buf_tail, *buf_end;

	buf_tail = (unsigned char *)capture->mz->addr + capture->mem_used;
	buf_end  = (unsigned char *)capture->mz->addr + capture->mz->len;

	/* Don't capture if buffer is full */
	if (buf_tail == buf_end)
		return;

	for (i = 0; i < nb_dump; i++) {
		pkt = pkts[i];
		/* If the packet is segmented by DPDK, only the contents of the first
		 * segment are captured. Capturing all segments uses too much CPU
		 * cycles, which causes packets to be dropped.
		 * Hence, data_len is used instead of pkt_len. */
		plen = pkt->data_len;

		/* If packet to capture is larger than available buffer size, stop
		 * capturing.
		 * The packet data is prepended by the untruncated packet length and
		 * the amount of captured data (which can be less than the packet size
		 * if DPDK has stored the packet contents in segmented mbufs).
		 */
		if (buf_tail + 2 * sizeof(uint16_t) + plen > buf_end) {
			/* If memory is available, write end-of-data sentinel. A packet
			 * length of 0 signals the end of the captured data to the routine
			 * that dumps the data to disk. */
			if (buf_end - buf_tail >= sizeof(uint16_t))
				*(uint16_t *)buf_tail = 0;

			capture->mem_used = capture->mz->len;
			return;
		}

		/* Write untruncated data length and size of the actually captured
		 * data. */
		*(uint16_t *)buf_tail = pkt->pkt_len;	/* untruncated length */
		buf_tail += sizeof(uint16_t);
		*(uint16_t *)buf_tail = plen;				/* captured data */
		buf_tail += sizeof(uint16_t);

		rte_memcpy(buf_tail, pkt->buf_addr + pkt->data_off, plen);
		buf_tail += plen;
	}

	/* Write end-of-data sentinel if memory is available. */
	if (buf_end - buf_tail >= sizeof(uint16_t))
		*(uint16_t *)buf_tail = 0;

	capture->mem_used = buf_tail - (unsigned char *)capture->mz->addr;
}
