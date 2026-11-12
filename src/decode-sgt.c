/* Copyright (C) 2026 Arctic Wolf Labs
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

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-sgt.h"
#include "decode-events.h"
#include "decode-ethernet.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "conf.h"

static bool g_sgt_cmd_enabled = false;
static bool g_sgt_cmd_eve_enabled = false;

void DecodeSgtCmdConfig(void)
{
    int enabled = 0;
    SCConfGetBool("decoder.sgt-cmd.enabled", &enabled);
    g_sgt_cmd_enabled = (enabled != 0);

    SCLogConfig("SGT CMD decoder: %s",
            g_sgt_cmd_enabled ? "enabled" : "disabled");

    if (!g_sgt_cmd_enabled)
        return;

    int metadata = 0;
    SCConfGetBool("decoder.sgt-cmd.metadata", &metadata);
    g_sgt_cmd_eve_enabled = (metadata != 0);

    SCLogConfig("SGT CMD EVE output: %s",
            g_sgt_cmd_eve_enabled ? "enabled" : "disabled");
}

bool DecodeSgtCmdEveEnabled(void)
{
    return g_sgt_cmd_eve_enabled;
}

/**
 * DecodeSGT - decode a Cisco MetaData (CMD / EtherType 0x8909) frame.
 *
 * Spec: draft-smith-kandula-sxp-05 Appendix A.
 * Received buffer starts at Version (0x8909 EtherType consumed by DecodeEthernet):
 *   [Version 1B][Length 1B][Options: Length*4 B][Inner EtherType 2B][Raw IPv4/IPv6]
 *
 * Length: count of 4-byte option words (spec range 1–3).
 * Each option: [OptLen 3 bits | Type 13 bits][Value 2–6 bytes].
 *   OptLen = additional 4-byte units; SGT option always has OptLen=0.
 *   Type=1 (SGT): combined first 2 bytes = 0x0001, value = 16-bit SGT tag.
 * Inner EtherType follows all option words; not counted in Length.
 */
int DecodeSGT(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
              const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (!g_sgt_cmd_enabled)
        return TM_ECODE_OK;

    StatsIncr(tv, dtv->counter_sgt);

    if (len < CMD_BASE_HDR_LEN) {
        ENGINE_SET_INVALID_EVENT(p, SGT_CMD_HDR_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    const CMDHdr *cmd = (const CMDHdr *)pkt;
    uint32_t cmd_total = CMD_TOTAL_LEN(cmd->length);

    if (cmd_total > len) {
        ENGINE_SET_INVALID_EVENT(p, SGT_CMD_HDR_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    /* cmd_total == len means options + inner EtherType fill the buffer exactly;
     * no bytes remain for the inner IP payload. */
    if (cmd_total == len) {
        ENGINE_SET_INVALID_EVENT(p, SGT_CMD_NO_INNER_FRAME);
        return TM_ECODE_FAILED;
    }

    /* Scan option words for SGT (draft-smith-kandula-sxp-05 §A.1.2).
     * Each option word: [OptLen 3 bits | Type 13 bits][Value 2-6 bytes].
     * OptLen = additional 4-byte units beyond the base 4 bytes of this option.
     * SGT option: OptLen=0, Type=1, Value=2 bytes → always 4 bytes total. */
    uint16_t sgt_value = 0;
    const uint8_t *opt     = pkt + CMD_BASE_HDR_LEN;
    const uint8_t *opt_end = opt + ((uint32_t)cmd->length * 4U);
    while (opt + 4U <= opt_end) {
        uint16_t combined = SCNtohs(*(const uint16_t *)opt);
        uint16_t opt_type = CMD_OPT_TYPE(combined);
        uint32_t opt_size = CMD_OPT_SIZE(combined);
        if (opt_type == CMD_OPTION_TYPE_SGT)
            sgt_value = SCNtohs(*(const uint16_t *)(opt + 2));
        opt += opt_size;
    }

    /* Inner EtherType immediately follows the options */
    uint16_t inner_etype = SCNtohs(*(const uint16_t *)opt_end);

    SCLogDebug("p %p CMD version=%u length=%u sgt=0x%04x inner_etype=0x%04x",
               p, cmd->version, cmd->length, sgt_value, inner_etype);

    p->cmd_present = 1;
    p->cmd_version = cmd->version;
    p->sgt_value   = sgt_value;

    const uint8_t *inner    = pkt + cmd_total;
    uint32_t       inner_len = len - cmd_total;

    if (inner_etype == ETHERNET_TYPE_IP || inner_etype == ETHERNET_TYPE_IPV6) {
        DecodeNetworkLayer(tv, dtv, inner_etype, p, inner, inner_len);
    } else {
        SCLogDebug("CMD unsupported inner EtherType 0x%04x", inner_etype);
        ENGINE_SET_INVALID_EVENT(p, SGT_CMD_UNSUPPORTED_INNER_PROTOCOL);
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

/*
 * Valid CMD frame matching the Wireshark-confirmed wire format:
 *   version=1, length=1 (1 option word), SGT option type=0x0001, sgt=10,
 *   inner EtherType=0x0800 (IPv4), minimal raw IPv4 header.
 */
static int DecodeSGTTest01(void)
{
    bool saved_enabled = g_sgt_cmd_enabled;
    bool saved_eve     = g_sgt_cmd_eve_enabled;
    g_sgt_cmd_enabled     = true;
    g_sgt_cmd_eve_enabled = true;

    uint8_t raw[] = {
        /* CMD base: version=1, length=1 (1 option word follows) */
        0x01, 0x01,
        /* Option word: type=0x0001 (SGT), value=10 (0x000a) */
        0x00, 0x01, 0x00, 0x0a,
        /* Inner EtherType: IPv4 (0x0800) */
        0x08, 0x00,
        /* Raw IPv4 header (20 bytes): ver=4, IHL=5, total_len=20 */
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0xf8, 0x68,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    DecodeSGT(&tv, &dtv, p, raw, sizeof(raw));

    int pass = (p->sgt_value == 10 &&
                p->cmd_version == 1 &&
                p->cmd_present == 1);

    g_sgt_cmd_enabled     = saved_enabled;
    g_sgt_cmd_eve_enabled = saved_eve;
    SCFree(p);
    return pass;
}

/* Frame shorter than CMD_BASE_HDR_LEN (2 bytes) must set SGT_CMD_HDR_TOO_SMALL */
static int DecodeSGTTest02(void)
{
    bool saved = g_sgt_cmd_enabled;
    g_sgt_cmd_enabled = true;

    uint8_t raw[] = { 0x01 };  /* 1 byte < CMD_BASE_HDR_LEN=2 */

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    DecodeSGT(&tv, &dtv, p, raw, sizeof(raw));

    int pass = ENGINE_ISSET_EVENT(p, SGT_CMD_HDR_TOO_SMALL);
    g_sgt_cmd_enabled = saved;
    SCFree(p);
    return pass;
}

/* CMD with no options (length=0): EtherType immediately follows base header.
 * No SGT option present, so sgt_value stays 0. */
static int DecodeSGTTest03(void)
{
    bool saved_enabled = g_sgt_cmd_enabled;
    bool saved_eve     = g_sgt_cmd_eve_enabled;
    g_sgt_cmd_enabled     = true;
    g_sgt_cmd_eve_enabled = true;

    uint8_t raw[] = {
        /* CMD base: version=1, length=0 (no option words) */
        0x01, 0x00,
        /* Inner EtherType: IPv4 (0x0800) */
        0x08, 0x00,
        /* Raw IPv4 header (20 bytes) */
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0xf8, 0x68,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    DecodeSGT(&tv, &dtv, p, raw, sizeof(raw));

    int pass = (p->cmd_present == 1 && p->sgt_value == 0);
    g_sgt_cmd_enabled     = saved_enabled;
    g_sgt_cmd_eve_enabled = saved_eve;
    SCFree(p);
    return pass;
}

/* SGT option with OptLen=7 (the maximum 3-bit value, opt_size=32).
 *
 * The spec requires OptLen=0 for the SGT option (4-byte total: 2-byte
 * combined header + 2-byte SGT value).  OptLen=7 declares opt_size=32
 * bytes but the option area is only 4 bytes — the declared size exceeds
 * the actual area.
 *
 * The decoder reads sgt_value from opt+2 BEFORE advancing opt+=opt_size,
 * so the SGT tag is extracted correctly.  opt+=32 then jumps past opt_end
 * and the loop terminates.  The frame is accepted and cmd_present is set. */
static int DecodeSGTTest04(void)
{
    bool saved_enabled = g_sgt_cmd_enabled;
    bool saved_eve     = g_sgt_cmd_eve_enabled;
    g_sgt_cmd_enabled     = true;
    g_sgt_cmd_eve_enabled = true;

    uint8_t raw[] = {
        /* CMD base: version=1, length=1 (1 option word = 4 bytes) */
        0x01, 0x01,
        /* Option word: combined=0xE001 → OptLen=7 (top 3 bits=111), Type=SGT (0x0001) */
        /* opt_size = 4 + 7*4 = 32; sgt_value read from opt+2 = 0x000A = 10 */
        0xE0, 0x01, 0x00, 0x0a,
        /* Inner EtherType: IPv4 (0x0800) */
        0x08, 0x00,
        /* Raw IPv4 header (20 bytes) */
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0xf8, 0x68,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    DecodeSGT(&tv, &dtv, p, raw, sizeof(raw));

    int pass = (p->cmd_present == 1 && p->sgt_value == 10);

    g_sgt_cmd_enabled     = saved_enabled;
    g_sgt_cmd_eve_enabled = saved_eve;
    SCFree(p);
    return pass;
}
#endif /* UNITTESTS */

void DecodeSGTRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeSGTTest01", DecodeSGTTest01);
    UtRegisterTest("DecodeSGTTest02", DecodeSGTTest02);
    UtRegisterTest("DecodeSGTTest03", DecodeSGTTest03);
    UtRegisterTest("DecodeSGTTest04", DecodeSGTTest04);
#endif
}
