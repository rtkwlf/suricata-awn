/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Flow utility functions
 */

#include "suricata-common.h"
#include "threads.h"

#include "stream-tcp.h"
#include "flow.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-var.h"
#include "app-layer.h"

#include "util-var.h"
#include "util-debug.h"
#include "util-macset.h"
#include "flow-storage.h"

#include "detect.h"
#include "detect-engine-state.h"

#include "decode-icmpv4.h"

#include "util-validate.h"

/** \brief allocate a flow
 *
 *  We check against the memuse counter. If it passes that check we increment
 *  the counter first, then we try to alloc.
 *
 *  \retval f the flow or NULL on out of memory
 */
Flow *FlowAlloc(void)
{
    Flow *f;
    size_t size = sizeof(Flow) + FlowStorageSize();

    if (!(FLOW_CHECK_MEMCAP(size))) {
        return NULL;
    }

    (void) SC_ATOMIC_ADD(flow_memuse, size);

    f = SCMalloc(size);
    if (unlikely(f == NULL)) {
        (void)SC_ATOMIC_SUB(flow_memuse, size);
        return NULL;
    }
    memset(f, 0, size);

    /* coverity[missing_lock] */
    FLOW_INITIALIZE(f);
    return f;
}


/**
 *  \brief cleanup & free the memory of a flow
 *
 *  \param f flow to clear & destroy
 */
void FlowFree(Flow *f)
{
    FLOW_DESTROY(f);
    SCFree(f);

    size_t size = sizeof(Flow) + FlowStorageSize();
    (void) SC_ATOMIC_SUB(flow_memuse, size);
}

/**
 *  \brief   Function to map the protocol to the defined FLOW_PROTO_* enumeration.
 *
 *  \param   proto  protocol which is needed to be mapped
 */

uint8_t FlowGetProtoMapping(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_TCP:
            return FLOW_PROTO_TCP;
        case IPPROTO_UDP:
            return FLOW_PROTO_UDP;
        case IPPROTO_ICMP:
            return FLOW_PROTO_ICMP;
        default:
            return FLOW_PROTO_DEFAULT;
    }
}

uint8_t FlowGetReverseProtoMapping(uint8_t rproto)
{
    switch (rproto) {
        case FLOW_PROTO_TCP:
            return IPPROTO_TCP;
        case FLOW_PROTO_UDP:
            return IPPROTO_UDP;
        case FLOW_PROTO_ICMP:
            return IPPROTO_ICMP;
        default:
            exit(EXIT_FAILURE);
    }
}

static inline void FlowSetICMPv4CounterPart(Flow *f)
{
    int ctype = ICMPv4GetCounterpart(f->icmp_s.type);
    if (ctype == -1)
        return;

    f->icmp_d.type = (uint8_t)ctype;
}

static inline void FlowSetICMPv6CounterPart(Flow *f)
{
    int ctype = ICMPv6GetCounterpart(f->icmp_s.type);
    if (ctype == -1)
        return;

    f->icmp_d.type = (uint8_t)ctype;
}

/* initialize the flow from the first packet
 * we see from it. */
void FlowInit(Flow *f, const Packet *p)
{
    SCEnter();
    SCLogDebug("flow %p", f);

    f->proto = p->proto;
    f->recursion_level = p->recursion_level;
    memcpy(&f->vlan_id[0], &p->vlan_id[0], sizeof(f->vlan_id));
    f->vlan_idx = p->vlan_idx;
    f->livedev = p->livedev;

    int pkt_is_from_client = 1;

    if (p->tcph != NULL) { /* XXX MACRO */
        /* If the first packet to be seen by suricata is a TCP SYNACK then it's from
         * the server rather than the client, and the flow direction should be set
         * accordingly. But only do this if midstream flow pickup or async flows are
         * enabled in config, as these are required for the TCP session state to be
         * tracked.
         */
        if (stream_config.midstream == TRUE || stream_config.async_oneside == TRUE) {
            if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                pkt_is_from_client = 0;
            }
        }

        if (likely(pkt_is_from_client)) {
            SET_TCP_SRC_PORT(p, &f->sp);
            SET_TCP_DST_PORT(p, &f->dp);
        } else {
            SET_TCP_SRC_PORT(p, &f->dp);
            SET_TCP_DST_PORT(p, &f->sp);
        }
    } else if (p->udph != NULL) { /* XXX MACRO */
        SET_UDP_SRC_PORT(p,&f->sp);
        SET_UDP_DST_PORT(p,&f->dp);
    } else if (p->icmpv4h != NULL) {
        f->icmp_s.type = p->icmp_s.type;
        f->icmp_s.code = p->icmp_s.code;
        FlowSetICMPv4CounterPart(f);
    } else if (p->icmpv6h != NULL) {
        f->icmp_s.type = p->icmp_s.type;
        f->icmp_s.code = p->icmp_s.code;
        FlowSetICMPv6CounterPart(f);
    } else if (p->sctph != NULL) { /* XXX MACRO */
        SET_SCTP_SRC_PORT(p,&f->sp);
        SET_SCTP_DST_PORT(p,&f->dp);
    } else if (p->esph != NULL) {
        f->esp.spi = ESP_GET_SPI(p);
    } else {
        /* nothing to do for this IP proto. */
        SCLogDebug("no special setup for IP proto %u", p->proto);
    }

    if (PKT_IS_IPV4(p)) {
        if (likely(pkt_is_from_client)) {
            FLOW_SET_IPV4_SRC_ADDR_FROM_PACKET(p, &f->src);
            FLOW_SET_IPV4_DST_ADDR_FROM_PACKET(p, &f->dst);
            f->min_ttl_toserver = f->max_ttl_toserver = IPV4_GET_IPTTL((p));
        } else {
            FLOW_SET_IPV4_SRC_ADDR_FROM_PACKET(p, &f->dst);
            FLOW_SET_IPV4_DST_ADDR_FROM_PACKET(p, &f->src);
            f->min_ttl_toclient = f->max_ttl_toclient = IPV4_GET_IPTTL((p));
        }
        f->flags |= FLOW_IPV4;
    } else if (PKT_IS_IPV6(p)) {
        if (likely(pkt_is_from_client)) {
            FLOW_SET_IPV6_SRC_ADDR_FROM_PACKET(p, &f->src);
            FLOW_SET_IPV6_DST_ADDR_FROM_PACKET(p, &f->dst);
            f->min_ttl_toserver = f->max_ttl_toserver = IPV6_GET_HLIM((p));
        } else {
            FLOW_SET_IPV6_SRC_ADDR_FROM_PACKET(p, &f->dst);
            FLOW_SET_IPV6_DST_ADDR_FROM_PACKET(p, &f->src);
            f->min_ttl_toclient = f->max_ttl_toclient = IPV6_GET_HLIM((p));
        }
        f->flags |= FLOW_IPV6;
    }
#ifdef DEBUG
    /* XXX handle default */
    else {
        printf("FIXME: %s:%s:%" PRId32 "\n", __FILE__, __FUNCTION__, __LINE__);
    }
#endif

    f->startts = p->ts;

    f->protomap = FlowGetProtoMapping(f->proto);
    f->timeout_policy = FlowGetTimeoutPolicy(f);
    const uint32_t timeout_at = (uint32_t)SCTIME_SECS(f->startts) + f->timeout_policy;
    f->timeout_at = timeout_at;

    if (MacSetFlowStorageEnabled()) {
        DEBUG_VALIDATE_BUG_ON(FlowGetStorageById(f, MacSetGetFlowStorageID()) != NULL);
        MacSet *ms = MacSetInit(10);
        FlowSetStorageById(f, MacSetGetFlowStorageID(), ms);
    }

    SCReturn;
}

void FlowInitFromFlow(Flow* f, const Flow* old_f, const Packet* p) {
    SCEnter();
    SCLogDebug("flow %p old_flow", f, old_f);

    f->proto = old_f->proto;
    f->recursion_level = old_f->recursion_level;
    f->vlan_id[0] = old_f->vlan_id[0];
    f->vlan_id[1] = old_f->vlan_id[1];
    f->vlan_idx = old_f->vlan_idx;
    f->livedev = old_f->livedev;

    f->src = old_f->src;
    f->dst = old_f->dst;
    f->sp = old_f->sp;
    f->dp = old_f->dp;

    f->flags = old_f->flags;

    f->flow_hash = old_f->flow_hash;
    
    if (PKT_IS_IPV4(p)) {
        bool from_client = (f->src.addr_data32[0] == p->ip4h->s_ip_src.s_addr);
            
        if (from_client) {
            f->min_ttl_toserver = f->max_ttl_toserver = IPV4_GET_IPTTL((p));
        } else {
            f->min_ttl_toclient = f->max_ttl_toclient = IPV4_GET_IPTTL((p));
        }
        f->flags |= FLOW_IPV4;
    } else if (PKT_IS_IPV6(p)) {
        bool from_client = (( f->src.addr_data32[0] == p->ip6h->s_ip6_src[0] ) &&
                            ( f->src.addr_data32[1] == p->ip6h->s_ip6_src[1] ) &&
                            ( f->src.addr_data32[2] == p->ip6h->s_ip6_src[2] ) &&
                            ( f->src.addr_data32[3] == p->ip6h->s_ip6_src[3] ));

        if (from_client) {
            f->min_ttl_toserver = f->max_ttl_toserver = IPV6_GET_HLIM((p));
        } else {
            f->min_ttl_toclient = f->max_ttl_toclient = IPV6_GET_HLIM((p));
        }
        f->flags |= FLOW_IPV6;
    }    

    COPY_TIMESTAMP(&p->ts, &f->startts);


    f->protomap = FlowGetProtoMapping(f->proto);
    f->timeout_policy = FlowGetTimeoutPolicy(f);
    const uint32_t timeout_at = (uint32_t)f->startts.tv_sec + f->timeout_policy;
    f->timeout_at = timeout_at;

    if (MacSetFlowStorageEnabled()) {
        MacSet *ms = FlowGetStorageById(f, MacSetGetFlowStorageID());
        if (ms != NULL) {
            MacSetReset(ms);
        } else {
            ms = MacSetInit(10);
            FlowSetStorageById(f, MacSetGetFlowStorageID(), ms);
        }
    }

    SCReturn;
}

FlowStorageId g_bypass_info_id = { .id = -1 };

FlowStorageId GetFlowBypassInfoID(void)
{
    return g_bypass_info_id;
}

static void FlowBypassFree(void *x)
{
    FlowBypassInfo *fb = (FlowBypassInfo *) x;

    if (fb == NULL)
        return;

    if (fb->bypass_data && fb->BypassFree) {
        fb->BypassFree(fb->bypass_data);
    }
    SCFree(fb);
}

void RegisterFlowBypassInfo(void)
{
    g_bypass_info_id = FlowStorageRegister("bypass_counters", sizeof(void *),
                                              NULL, FlowBypassFree);
}

void FlowEndCountersRegister(ThreadVars *t, FlowEndCounters *fec)
{
    for (int i = 0; i < FLOW_STATE_SIZE; i++) {
        const char *name = NULL;
        if (i == FLOW_STATE_NEW) {
            name = "flow.end.state.new";
        } else if (i == FLOW_STATE_ESTABLISHED) {
            name = "flow.end.state.established";
        } else if (i == FLOW_STATE_CLOSED) {
            name = "flow.end.state.closed";
        } else if (i == FLOW_STATE_LOCAL_BYPASSED) {
            name = "flow.end.state.local_bypassed";
#ifdef CAPTURE_OFFLOAD
        } else if (i == FLOW_STATE_CAPTURE_BYPASSED) {
            name = "flow.end.state.capture_bypassed";
#endif
        }
        if (name) {
            fec->flow_state[i] = StatsRegisterCounter(name, t);
        }
    }

    for (enum TcpState i = TCP_NONE; i <= TCP_CLOSED; i++) {
        const char *name = NULL;
        switch (i) {
            case TCP_NONE:
                name = "flow.end.tcp_state.none";
                break;
            case TCP_SYN_SENT:
                name = "flow.end.tcp_state.syn_sent";
                break;
            case TCP_SYN_RECV:
                name = "flow.end.tcp_state.syn_recv";
                break;
            case TCP_ESTABLISHED:
                name = "flow.end.tcp_state.established";
                break;
            case TCP_FIN_WAIT1:
                name = "flow.end.tcp_state.fin_wait1";
                break;
            case TCP_FIN_WAIT2:
                name = "flow.end.tcp_state.fin_wait2";
                break;
            case TCP_TIME_WAIT:
                name = "flow.end.tcp_state.time_wait";
                break;
            case TCP_LAST_ACK:
                name = "flow.end.tcp_state.last_ack";
                break;
            case TCP_CLOSE_WAIT:
                name = "flow.end.tcp_state.close_wait";
                break;
            case TCP_CLOSING:
                name = "flow.end.tcp_state.closing";
                break;
            case TCP_CLOSED:
                name = "flow.end.tcp_state.closed";
                break;
        }

        fec->flow_tcp_state[i] = StatsRegisterCounter(name, t);
    }
    fec->flow_tcp_liberal = StatsRegisterCounter("flow.end.tcp_liberal", t);
}
