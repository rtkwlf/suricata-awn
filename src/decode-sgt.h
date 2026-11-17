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

#ifndef SURICATA_DECODE_SGT_H
#define SURICATA_DECODE_SGT_H

/* EtherType for Cisco MetaData (CMD) frames carrying SGT */
#define ETHERNET_TYPE_CISCO_CMD 0x8909
#define ETHERNET_TYPE_SGT       ETHERNET_TYPE_CISCO_CMD  /* backward-compat alias */

/*
 * Cisco MetaData (CMD) Version 1 — draft-smith-kandula-sxp-05 Appendix A.
 *
 * From Suricata's perspective the 0x8909 EtherType is consumed by DecodeEthernet;
 * DecodeSGT receives the bytes starting at Version:
 *
 *  Byte 0         Byte 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Version    |    Length     |   base header (2 bytes)
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Per option word (4 + OptLen*4 bytes each):
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |OptLen |      Option Type      |          Value                |
 *  | 3 bit |       13 bit          |       2–6 bytes               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  After all option words:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Inner EtherType          |   2 bytes (0x0800/0x86DD)
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Raw IPv4 / IPv6          |   no inner Ethernet header
 *
 * Length:    number of 4-byte option words; spec valid range 1–3.
 *            Does NOT include the 2-byte base header or inner EtherType.
 * OptLen:    top 3 bits of each option's first 2 bytes — additional 4-byte
 *            units beyond the base 4 bytes of that option.
 * Type 1:    SGT option (OptLen=0, value=2 bytes).
 *
 * Total CMD overhead = 2 (base) + Length*4 (options) + 2 (inner EtherType).
 */
typedef struct CMDHdr_ {
    uint8_t version;  /* CMD version */
    uint8_t length;   /* option words count (4-byte units) */
} __attribute__((__packed__)) CMDHdr;

/* SGT option type (13-bit Option Type field value) */
#define CMD_OPTION_TYPE_SGT  1U

/* Extract the 3-bit option length and 13-bit option type from the combined field */
#define CMD_OPT_LEN(combined)   (((combined) >> 13) & 0x7U)
#define CMD_OPT_TYPE(combined)  ((combined) & 0x1FFFU)
/* Total size of one option word in bytes: 4 base + OptLen*4 extra */
#define CMD_OPT_SIZE(combined)  (4U + CMD_OPT_LEN(combined) * 4U)

/* 2-byte base header (version + length) */
#define CMD_BASE_HDR_LEN   2U
/* 2-byte inner EtherType field after all option words */
#define CMD_ETHERTYPE_LEN  2U

/* Total CMD overhead before the inner IP payload */
#define CMD_TOTAL_LEN(length) \
    (CMD_BASE_HDR_LEN + ((uint32_t)(length) * 4U) + CMD_ETHERTYPE_LEN)

void DecodeSgtCmdConfig(void);
bool DecodeSgtCmdEveEnabled(void);
void DecodeSGTRegisterTests(void);

#endif /* SURICATA_DECODE_SGT_H */
