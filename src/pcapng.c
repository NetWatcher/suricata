/* pcapng.c
 *
 * Original code downloaded from: https://www.wireshark.org/download.html
 *
 * pcapng.c -- This file contains extraction of code from wireshark app
 * that allows to use pcapng file format.
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 * Copyright (c) 1998 by Gerald Combs <gerald@wireshark.org>
 * Copyright (c) 2013 by Balint Reczey <balint@balintreczey.hu>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifdef HAVE_LIBPCAPNG

#include <fcntl.h>

#include "pcapng.h"

static const struct {
    int	linktype_value;
    int	wtap_encap_value;
} pcap_to_wtap_map[] = {
    /*
     * These are the values that are almost certainly the same
     * in all libpcaps (I've yet to find one where the values
     * in question are used for some purpose other than the
     * one below, but...), and thus assigned as LINKTYPE_ values,
     * and that Wiretap and Wireshark currently support.
     */
    { 0,		WTAP_ENCAP_NULL },	/* null encapsulation */
    { 1,		WTAP_ENCAP_ETHERNET },
    { 3,		WTAP_ENCAP_AX25 },
    { 6,		WTAP_ENCAP_TOKEN_RING },	/* IEEE 802 Networks - assume token ring */
    { 7,		WTAP_ENCAP_ARCNET },
    { 8,		WTAP_ENCAP_SLIP },
    { 9,		WTAP_ENCAP_PPP },
#ifdef BIT_SWAPPED_MAC_ADDRS
    { 10,		WTAP_ENCAP_FDDI_BITSWAPPED },
#else
    { 10,		WTAP_ENCAP_FDDI },
#endif

    { 32,		WTAP_ENCAP_REDBACK },

    /*
     * 50 is DLT_PPP_SERIAL in NetBSD; it appears that DLT_PPP
     * on BSD (at least according to standard tcpdump) has, as
     * the first octet, an indication of whether the packet was
     * transmitted or received (rather than having the standard
     * PPP address value of 0xff), but that DLT_PPP_SERIAL puts
     * a real live PPP header there, or perhaps a Cisco PPP header
     * as per section 4.3.1 of RFC 1547 (implementations of this
     * exist in various BSDs in "sys/net/if_spppsubr.c", and
     * I think also exist either in standard Linux or in
     * various Linux patches; the implementations show how to handle
     * Cisco keepalive packets).
     *
     * However, I don't see any obvious place in FreeBSD "if_ppp.c"
     * where anything other than the standard PPP header would be
     * passed up.  I see some stuff that sets the first octet
     * to 0 for incoming and 1 for outgoing packets before applying
     * a BPF filter to see whether to drop packets whose protocol
     * field has the 0x8000 bit set, i.e. network control protocols -
     * those are handed up to userland - but that code puts the
     * address field back before passing the packet up.
     *
     * I also don't see anything immediately obvious that munges
     * the address field for sync PPP, either.
     *
     * Wireshark currently assumes that if the first octet of a
     * PPP frame is 0xFF, it's the address field and is followed
     * by a control field and a 2-byte protocol, otherwise the
     * address and control fields are absent and the frame begins
     * with a protocol field.  If we ever see a BSD/OS PPP
     * capture, we'll have to handle it differently, and we may
     * have to handle standard BSD captures differently if, in fact,
     * they don't have 0xff 0x03 as the first two bytes - but, as per
     * the two paragraphs preceding this, it's not clear that
     * the address field *is* munged into an incoming/outgoing
     * field when the packet is handed to the BPF device.
     *
     * For now, we just map DLT_PPP_SERIAL to WTAP_ENCAP_PPP, as
     * we treat WTAP_ENCAP_PPP packets as if those beginning with
     * 0xff have the standard RFC 1662 "PPP in HDLC-like Framing"
     * 0xff 0x03 address/control header, and DLT_PPP_SERIAL frames
     * appear to contain that unless they're Cisco frames (if we
     * ever see a capture with them, we'd need to implement the
     * RFC 1547 stuff, and the keepalive protocol stuff).
     *
     * We may have to distinguish between "PPP where if it doesn't
     * begin with 0xff there's no HDLC encapsulation and the frame
     * begins with the protocol field" (which is how we handle
     * WTAP_ENCAP_PPP now) and "PPP where there's either HDLC
     * encapsulation or Cisco PPP" (which is what DLT_PPP_SERIAL
     * is) at some point.
     *
     * XXX - NetBSD has DLT_HDLC, which appears to be used for
     * Cisco HDLC.  Ideally, they should use DLT_PPP_SERIAL
     * only for real live HDLC-encapsulated PPP, not for Cisco
     * HDLC.
     */
    { 50,		WTAP_ENCAP_PPP },

    /*
     * Used by NetBSD and OpenBSD pppoe(4).
     */
    { 51,		WTAP_ENCAP_PPP_ETHER },

    /*
     * Apparently used by the Axent Raptor firewall (now Symantec
     * Enterprise Firewall).
     * Thanks, Axent, for not reserving that type with tcpdump.org
     * and not telling anybody about it.
     */
    { 99,		WTAP_ENCAP_SYMANTEC },

    /*
     * These are the values that libpcap 0.5 and later use in
     * capture file headers, in an attempt to work around the
     * confusion decried above, and that Wiretap and Wireshark
     * currently support.  I.e., they're the LINKTYPE_ values
     * for RFC 1483 ATM and "raw IP", respectively, not the
     * DLT_ values for them on all platforms.
     */
    { 100,		WTAP_ENCAP_ATM_RFC1483 },
    { 101,		WTAP_ENCAP_RAW_IP },
#if 0
    /*
     * More values used by libpcap 0.5 as DLT_ values and used by the
     * current CVS version of libpcap in capture file headers.
     * They are not yet handled in Wireshark.
     * If we get a capture that contains them, we'll implement them.
     */
    { 102,		WTAP_ENCAP_SLIP_BSDOS },
    { 103,		WTAP_ENCAP_PPP_BSDOS },
#endif

    /*
     * These ones are handled in Wireshark, though.
     */
    { 104,		WTAP_ENCAP_CHDLC },	/* Cisco HDLC */
    { 105,		WTAP_ENCAP_IEEE_802_11 }, /* IEEE 802.11 */
    { 106,		WTAP_ENCAP_LINUX_ATM_CLIP },
    { 107,		WTAP_ENCAP_FRELAY },	/* Frame Relay */
    { 108,		WTAP_ENCAP_NULL },	/* OpenBSD loopback */
    { 109,		WTAP_ENCAP_ENC },	/* OpenBSD IPSEC enc */
#if 0
    { 110,		WTAP_ENCAP_LANE_802_3 },/* ATM LANE 802.3 */
    { 111,		WTAP_ENCAP_HIPPI },	/* NetBSD HIPPI */
#endif
    { 112,		WTAP_ENCAP_CHDLC },	/* NetBSD HDLC framing */

    /*
     * Linux "cooked mode" captures, used by the current CVS version
     * of libpcap
         * OR
         * it could be a packet in Cisco's ERSPAN encapsulation which uses
         * this number as well (why can't people stick to protocols when it
         * comes to allocating/using DLT types).
     */
    { 113,		WTAP_ENCAP_SLL },	/* Linux cooked capture */

    { 114,		WTAP_ENCAP_LOCALTALK },	/* Localtalk */

    /*
     * The tcpdump.org version of libpcap uses 117, rather than 17,
     * for OpenBSD packet filter logging, so as to avoid conflicting
     * with DLT_LANE8023 in SuSE 6.3 libpcap.
     */
    { 117,		WTAP_ENCAP_PFLOG },

    { 118,		WTAP_ENCAP_CISCO_IOS },
    { 119,		WTAP_ENCAP_IEEE_802_11_PRISM }, /* 802.11 plus Prism monitor mode radio header */
    { 121,		WTAP_ENCAP_HHDLC },	/* HiPath HDLC */
    { 122,		WTAP_ENCAP_IP_OVER_FC },   /* RFC 2625 IP-over-FC */
    { 123,		WTAP_ENCAP_ATM_PDUS },  /* SunATM */
    { 127,		WTAP_ENCAP_IEEE_802_11_RADIOTAP },  /* 802.11 plus radiotap radio header */
    { 128,		WTAP_ENCAP_TZSP },	/* Tazmen Sniffer Protocol */
    { 129,		WTAP_ENCAP_ARCNET_LINUX },
    { 130,		WTAP_ENCAP_JUNIPER_MLPPP }, /* Juniper MLPPP on ML-, LS-, AS- PICs */
    { 131,		WTAP_ENCAP_JUNIPER_MLFR }, /* Juniper MLFR (FRF.15) on ML-, LS-, AS- PICs */
    { 133,		WTAP_ENCAP_JUNIPER_GGSN},
    /*
     * Values 132 and 134 not listed here are reserved for use
     * in Juniper hardware.
     */
    { 135,		WTAP_ENCAP_JUNIPER_ATM2 }, /* various encapsulations captured on the ATM2 PIC */
    { 136,		WTAP_ENCAP_JUNIPER_SVCS }, /* various encapsulations captured on the services PIC */
    { 137,		WTAP_ENCAP_JUNIPER_ATM1 }, /* various encapsulations captured on the ATM1 PIC */

    { 138,		WTAP_ENCAP_APPLE_IP_OVER_IEEE1394 },
                        /* Apple IP-over-IEEE 1394 */

    { 139,		WTAP_ENCAP_MTP2_WITH_PHDR },
    { 140,		WTAP_ENCAP_MTP2 },
    { 141,		WTAP_ENCAP_MTP3 },
    { 142,		WTAP_ENCAP_SCCP },
    { 143,		WTAP_ENCAP_DOCSIS },
    { 144,		WTAP_ENCAP_IRDA },	/* IrDA capture */

    /* Reserved for private use. */
    { 147,		WTAP_ENCAP_USER0 },
    { 148,		WTAP_ENCAP_USER1 },
    { 149,		WTAP_ENCAP_USER2 },
    { 150,		WTAP_ENCAP_USER3 },
    { 151,		WTAP_ENCAP_USER4 },
    { 152,		WTAP_ENCAP_USER5 },
    { 153,		WTAP_ENCAP_USER6 },
    { 154,		WTAP_ENCAP_USER7 },
    { 155,		WTAP_ENCAP_USER8 },
    { 156,		WTAP_ENCAP_USER9 },
    { 157,		WTAP_ENCAP_USER10 },
    { 158,		WTAP_ENCAP_USER11 },
    { 159,		WTAP_ENCAP_USER12 },
    { 160,		WTAP_ENCAP_USER13 },
    { 161,		WTAP_ENCAP_USER14 },
    { 162,		WTAP_ENCAP_USER15 },

    { 163,		WTAP_ENCAP_IEEE_802_11_AVS },  /* 802.11 plus AVS radio header */

    /*
     * 164 is reserved for Juniper-private chassis-internal
     * meta-information such as QoS profiles, etc..
     */

    { 165,		WTAP_ENCAP_BACNET_MS_TP },

    /*
     * 166 is reserved for a PPP variant in which the first byte
     * of the 0xff03 header, the 0xff, is replaced by a direction
     * byte.  I don't know whether any captures look like that,
     * but it is used for some Linux IP filtering (ipfilter?).
     */

    /* Ethernet PPPoE frames captured on a service PIC */
    { 167,		WTAP_ENCAP_JUNIPER_PPPOE },

        /*
     * 168 is reserved for more Juniper private-chassis-
     * internal meta-information.
     */

    { 169,		WTAP_ENCAP_GPRS_LLC },

    /*
     * 170 and 171 are reserved for ITU-T G.7041/Y.1303 Generic
     * Framing Procedure.
     */

    /* Registered by Gcom, Inc. */
    { 172,		WTAP_ENCAP_GCOM_TIE1 },
    { 173,		WTAP_ENCAP_GCOM_SERIAL },

    { 177,		WTAP_ENCAP_LINUX_LAPD },

    /* Ethernet frames prepended with meta-information */
    { 178,		WTAP_ENCAP_JUNIPER_ETHER },
    /* PPP frames prepended with meta-information */
    { 179,		WTAP_ENCAP_JUNIPER_PPP },
    /* Frame-Relay frames prepended with meta-information */
    { 180,		WTAP_ENCAP_JUNIPER_FRELAY },
    /* C-HDLC frames prepended with meta-information */
    { 181,		WTAP_ENCAP_JUNIPER_CHDLC },
    /* VOIP Frames prepended with meta-information */
    { 183,		WTAP_ENCAP_JUNIPER_VP },
    /* raw USB packets */
    { 186, 		WTAP_ENCAP_USB },
    /* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
    { 187, 		WTAP_ENCAP_BLUETOOTH_H4 },
    /* IEEE 802.16 MAC Common Part Sublayer */
    { 188,		WTAP_ENCAP_IEEE802_16_MAC_CPS },
    /* USB packets with Linux-specified header */
    { 189, 		WTAP_ENCAP_USB_LINUX },
    /* CAN 2.0b frame */
    { 190, 		WTAP_ENCAP_CAN20B },
    /* Per-Packet Information header */
    { 192,		WTAP_ENCAP_PPI },
    /* IEEE 802.15.4 Wireless PAN */
    { 195,		WTAP_ENCAP_IEEE802_15_4 },
    /* SITA File Encapsulation */
    { 196,		WTAP_ENCAP_SITA },
    /* Endace Record File Encapsulation */
    { 197,		WTAP_ENCAP_ERF },
    /* IPMB */
    { 199,		WTAP_ENCAP_IPMB },
    /* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
    { 201, 		WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR },
    /* AX.25 packet with a 1-byte KISS header */
    { 202,		WTAP_ENCAP_AX25_KISS },
    /* LAPD frame */
    { 203, 		WTAP_ENCAP_LAPD },
    /* PPP with pseudoheader */
    { 204,		WTAP_ENCAP_PPP_WITH_PHDR },
    /* IPMB/I2C */
    { 209,		WTAP_ENCAP_I2C },
    /* FlexRay frame */
    { 210, 		WTAP_ENCAP_FLEXRAY },
    /* MOST frame */
    { 211, 		WTAP_ENCAP_MOST },
    /* LIN frame */
    { 212, 		WTAP_ENCAP_LIN },
    /* X2E Xoraya serial frame */
    { 213, 		WTAP_ENCAP_X2E_SERIAL },
    /* X2E Xoraya frame */
    { 214, 		WTAP_ENCAP_X2E_XORAYA },
    /* IEEE 802.15.4 Wireless PAN non-ASK PHY */
    { 215,		WTAP_ENCAP_IEEE802_15_4_NONASK_PHY },
    /* USB packets with padded Linux-specified header */
    { 220, 		WTAP_ENCAP_USB_LINUX_MMAPPED },
    /* Fibre Channel FC-2 frame */
    { 224,		WTAP_ENCAP_FIBRE_CHANNEL_FC2 },
    /* Fibre Channel FC-2 frame with Delimiter */
    { 225,		WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS },
    /* Solaris IPNET */
    { 226,		WTAP_ENCAP_IPNET },
    /* SocketCAN frame */
    { 227,		WTAP_ENCAP_SOCKETCAN },
    /* Raw IPv4 */
    { 228,		WTAP_ENCAP_RAW_IP4 },
    /* Raw IPv6 */
    { 229,		WTAP_ENCAP_RAW_IP6 },
    /* IEEE 802.15.4 Wireless PAN no fcs */
    { 230,		WTAP_ENCAP_IEEE802_15_4_NOFCS },
    /* D-BUS */
    { 231,		WTAP_ENCAP_DBUS },
    /* DVB-CI (Common Interface) */
    { 235,		WTAP_ENCAP_DVBCI },
    /* MUX27010 */
    { 236,		WTAP_ENCAP_MUX27010 },
    /* STANAG 5066 - DTS(Data Transfer Sublayer) PDU */
    { 237,		WTAP_ENCAP_STANAG_5066_D_PDU },
    /* NFLOG */
    { 239,		WTAP_ENCAP_NFLOG },
    /* netANALYZER pseudo-header followed by Ethernet with CRC */
    { 240,		WTAP_ENCAP_NETANALYZER },
    /* netANALYZER pseudo-header in transparent mode */
    { 241,		WTAP_ENCAP_NETANALYZER_TRANSPARENT },
    /* IP-over-Infiniband, as specified by RFC 4391 section 6 */
    { 242,		WTAP_ENCAP_IP_OVER_IB },
    /* ISO/IEC 13818-1 MPEG2-TS packets */
    { 243,		WTAP_ENCAP_MPEG_2_TS },
    /* NFC LLCP */
    { 245,		WTAP_ENCAP_NFC_LLCP },
    /* SCTP */
    { 248,		WTAP_ENCAP_SCTP},
    /* USBPcap */
    { 249,		WTAP_ENCAP_USBPCAP},
    /* RTAC SERIAL */
    { 250,		WTAP_ENCAP_RTAC_SERIAL},
    /* Bluetooth Low Energy Link Layer */
    { 251,		WTAP_ENCAP_BLUETOOTH_LE_LL},
    /* Wireshark Upper PDU export */
    { 252,		WTAP_ENCAP_WIRESHARK_UPPER_PDU},
    /* Netlink Protocol (nlmon devices) */
    { 253,		WTAP_ENCAP_NETLINK },
    /* Bluetooth Linux Monitor */
    { 254,		WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR },
    /* Bluetooth BR/EDR Baseband RF captures */
    { 255,		WTAP_ENCAP_BLUETOOTH_BREDR_BB },
    /* Bluetooth Low Energy Link Layer RF captures */
    { 256,		WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR },

    /* Apple PKTAP */
    { 258,		WTAP_ENCAP_PKTAP },

    /* Ethernet Passive Optical Network */
    { 259,		WTAP_ENCAP_EPON },

    /* IPMI Trace Data Collection */
    { 260,		WTAP_ENCAP_IPMI_TRACE },

    /*
     * To repeat:
     *
     * If you need a new encapsulation type for libpcap files, do
     * *N*O*T* use *ANY* of the values listed here!  I.e., do *NOT*
     * add a new encapsulation type by changing an existing entry;
     * leave the existing entries alone.
     *
     * Instead, send mail to tcpdump-workers@lists.tcpdump.org, asking
     * for a new DLT_ value, and specifying the purpose of the new value.
     * When you get the new DLT_ value, use that numerical value in
     * the "linktype_value" field of "pcap_to_wtap_map[]".
     */

    /*
     * The following are entries for libpcap type values that have
     * different meanings on different OSes.  I.e., these are DLT_
     * values that are different on different OSes, and that have
     * a separate LINKTYPE_ value assigned to them.
     *
     * We put these *after* the entries for the LINKTYPE_ values for
     * those Wiretap encapsulation types, so that, when writing a
     * pcap or pcap-ng file, Wireshark writes the LINKTYPE_ value,
     * not the OS's DLT_ value, as the file's link-layer header type
     * for pcap or the interface's link-layer header type.
     */

    /*
     * 11 is DLT_ATM_RFC1483 on most platforms; the only libpcaps I've
     * seen that define anything other than DLT_ATM_RFC1483 as 11 are
     * the BSD/OS one, which defines DLT_FR as 11.  We handle it as
     * Frame Relay on BSD/OS and LLC-encapsulated ATM on all other
     * platforms.
     */
#if defined(__bsdi__) /* BSD/OS */
    { 11,		WTAP_ENCAP_FRELAY },
#else
    { 11,		WTAP_ENCAP_ATM_RFC1483 },
#endif

    /*
     * 12 is DLT_RAW on most platforms, but it's DLT_C_HDLC on
     * BSD/OS, and DLT_LOOP on OpenBSD.
     *
     * We don't yet handle DLT_C_HDLC, but we can handle DLT_LOOP
     * (it's just like DLT_NULL, only with the AF_ value in network
     * rather than host byte order - Wireshark figures out the
     * byte order from the data, so we don't care what byte order
     * it's in), so if DLT_LOOP is defined as 12, interpret 12
     * as WTAP_ENCAP_NULL, otherwise, unless DLT_C_HDLC is defined
     * as 12, interpret it as WTAP_ENCAP_RAW_IP.
     */
#if defined(__OpenBSD__)
    { 12,		WTAP_ENCAP_NULL },
#elif defined(__bsdi__) /* BSD/OS */
    /*
     * Put entry for Cisco HDLC here.
     * XXX - is this just WTAP_ENCAP_CHDLC, i.e. does the frame
     * start with a 4-byte Cisco HDLC header?
     */
#else
    { 12,		WTAP_ENCAP_RAW_IP },
#endif

    /*
     * 13 is DLT_SLIP_BSDOS on FreeBSD and NetBSD, but those OSes
     * don't actually generate it.  I infer that BSD/OS translates
     * DLT_SLIP from the kernel BPF code to DLT_SLIP_BSDOS in
     * libpcap, as the BSD/OS link-layer header is different;
     * however, in BSD/OS, DLT_SLIP_BSDOS is 15.
     *
     * From this, I infer that there's no point in handling 13
     * as DLT_SLIP_BSDOS.
     *
     * 13 is DLT_ATM_RFC1483 on BSD/OS.
     *
     * 13 is DLT_ENC in OpenBSD, which is, I suspect, some kind
     * of decrypted IPsec traffic.
     *
     * We treat 13 as WTAP_ENCAP_ENC on all systems except those
     * that define DLT_ATM_RFC1483 as 13 - presumably only
     * BSD/OS does so - so that, on BSD/OS systems, we still
     * treate 13 as WTAP_ENCAP_ATM_RFC1483, but, on all other
     * systems, we can read OpenBSD DLT_ENC captures.
     */
#if defined(__bsdi__) /* BSD/OS */
    { 13,		WTAP_ENCAP_ATM_RFC1483 },
#else
    { 13,		WTAP_ENCAP_ENC },
#endif

    /*
     * 14 is DLT_PPP_BSDOS on FreeBSD and NetBSD, but those OSes
     * don't actually generate it.  I infer that BSD/OS translates
     * DLT_PPP from the kernel BPF code to DLT_PPP_BSDOS in
     * libpcap, as the BSD/OS link-layer header is different;
     * however, in BSD/OS, DLT_PPP_BSDOS is 16.
     *
     * From this, I infer that there's no point in handling 14
     * as DLT_PPP_BSDOS.
     *
     * 14 is DLT_RAW on BSD/OS and OpenBSD.
     */
    { 14,		WTAP_ENCAP_RAW_IP },

    /*
     * 15 is:
     *
     *	DLT_SLIP_BSDOS on BSD/OS;
     *
     *	DLT_HIPPI on NetBSD;
     *
     *	DLT_LANE8023 with Alexey Kuznetzov's patches for
     *	Linux libpcap;
     *
     *	DLT_I4L_RAWIP with the ISDN4Linux patches for libpcap
     *	(and on SuSE 6.3);
     *
     * but we don't currently handle any of those.
     */

    /*
     * 16 is:
     *
     *	DLT_PPP_BSDOS on BSD/OS;
     *
     *	DLT_HDLC on NetBSD (Cisco HDLC);
     *
     *	DLT_CIP with Alexey Kuznetzov's patches for
     *	Linux libpcap - this is WTAP_ENCAP_LINUX_ATM_CLIP;
     *
     *	DLT_I4L_IP with the ISDN4Linux patches for libpcap
     *	(and on SuSE 6.3).
     */
#if defined(__NetBSD__)
    { 16,		WTAP_ENCAP_CHDLC },
#elif !defined(__bsdi__)
    /*
     * If you care about the two different Linux interpretations
     * of 16, fix it yourself.
     */
    { 16,		WTAP_ENCAP_LINUX_ATM_CLIP },
#endif

    /*
     * 17 is DLT_LANE8023 in SuSE 6.3 libpcap; we don't currently
     * handle it.
     * It is also used as the PF (Packet Filter) logging format beginning
     * with OpenBSD 3.0; we use 17 for PF logs on OpenBSD and don't
     * use it otherwise.
     */
#if defined(__OpenBSD__)
    { 17,		WTAP_ENCAP_OLD_PFLOG },
#endif

    /*
     * 18 is DLT_CIP in SuSE 6.3 libpcap; if it's the same as the
     * DLT_CIP of 16 that the Alexey Kuznetzov patches for
     * libpcap/tcpdump define, it's WTAP_ENCAP_LINUX_ATM_CLIP.
     * I've not found any libpcap that uses it for any other purpose -
     * hopefully nobody will do so in the future.
     */
    { 18,		WTAP_ENCAP_LINUX_ATM_CLIP },

    /*
     * 19 is DLT_ATM_CLIP in the libpcap/tcpdump patches in the
     * recent versions I've seen of the Linux ATM distribution;
     * I've not yet found any libpcap that uses it for any other
     * purpose - hopefully nobody will do so in the future.
     */
    { 19,		WTAP_ENCAP_LINUX_ATM_CLIP },

    /*
     * To repeat:
     *
     * If you need a new encapsulation type for libpcap files, do
     * *N*O*T* use *ANY* of the values listed here!  I.e., do *NOT*
     * add a new encapsulation type by changing an existing entry;
     * leave the existing entries alone.
     *
     * Instead, send mail to tcpdump-workers@lists.tcpdump.org, asking
     * for a new DLT_ value, and specifying the purpose of the new value.
     * When you get the new DLT_ value, use that numerical value in
     * the "linktype_value" field of "pcap_to_wtap_map[]".
     */
};
#define NUM_PCAP_ENCAPS (sizeof pcap_to_wtap_map / sizeof pcap_to_wtap_map[0])

static int
wtap_pcap_encap_to_wtap_encap(int encap)
{
    unsigned int i;

    for (i = 0; i < NUM_PCAP_ENCAPS; i++) {
        if (pcap_to_wtap_map[i].linktype_value == encap)
            return pcap_to_wtap_map[i].wtap_encap_value;
    }
    return WTAP_ENCAP_UNKNOWN;
}

int get_encapsulation_type(const void *source){

    gboolean byte_swapped;
    int file_encap;
    struct pcap_hdr hdr;
    memcpy(&hdr,source,sizeof(struct pcap_hdr));

    switch (hdr.magic) {

        case PCAP_MAGIC:
            /* Host that wrote it has our byte order, and was running
               a program using either standard or ss990417 libpcap. */
            byte_swapped = FALSE;

            break;

        case PCAP_MODIFIED_MAGIC:
            /* Host that wrote it has our byte order, and was running
               a program using either ss990915 or ss991029 libpcap. */
            byte_swapped = FALSE;

            break;

        case PCAP_SWAPPED_MAGIC:
            /* Host that wrote it has a byte order opposite to ours,
               and was running a program using either standard or
               ss990417 libpcap. */
            byte_swapped = TRUE;

            break;

        case PCAP_SWAPPED_MODIFIED_MAGIC:
            /* Host that wrote it out has a byte order opposite to
               ours, and was running a program using either ss990915
               or ss991029 libpcap. */
            byte_swapped = TRUE;

            break;

        case PCAP_NSEC_MAGIC:
            /* Host that wrote it has our byte order, and was writing
               the file in a format similar to standard libpcap
               except that the time stamps have nanosecond resolution. */
            byte_swapped = FALSE;

            break;

        case PCAP_SWAPPED_NSEC_MAGIC:
            /* Host that wrote it out has a byte order opposite to
               ours, and was writing the file in a format similar to
               standard libpcap except that the time stamps have
               nanosecond resolution. */
            byte_swapped = TRUE;
            break;

        default:
            /* Not a "libpcap" type we know about. */
            return 0;
    }
    if (byte_swapped) {
        /* Byte-swap the header fields about which we care. */
        hdr.version_major = GUINT16_SWAP_LE_BE(hdr.version_major);
        hdr.version_minor = GUINT16_SWAP_LE_BE(hdr.version_minor);
        hdr.snaplen = GUINT32_SWAP_LE_BE(hdr.snaplen);
        hdr.network = GUINT32_SWAP_LE_BE(hdr.network);
    }
    if (hdr.version_major == 2 && hdr.version_minor == 2) {
        switch (hdr.network) {

        case 6:
            hdr.network = 1;	/* DLT_EN10MB, Ethernet */

            break;

        case 9:
            hdr.network = 6;	/* DLT_IEEE802, Token Ring */

            break;

        case 15:
            hdr.network = 10;	/* DLT_FDDI, FDDI */

            break;

        case 24:
            hdr.network = 0;	/* DLT_NULL, loopback */

            break;
        }
    }
    file_encap = wtap_pcap_encap_to_wtap_encap(hdr.network);
    if (file_encap == WTAP_ENCAP_UNKNOWN) {

            return -1;
    }
    return file_encap;
}

static FILE* wtap_dump_file_open(const char *filename)
{
    return fopen(filename, "wb");
}

/* internally close a file for writing (compressed or not) */
static int wtap_dump_file_close(FILE* fh)
{
    return fclose(fh);
}

/* internally writing raw bytes (compressed or not) */
static gboolean wtap_dump_file_write(wtap_dumper *wdh, const void *buf, size_t bufsize,int *err)
{
    size_t nwritten = 0;
#ifdef HAVE_LIBZ
    if (wdh->compressed) {
        nwritten = gzwfile_write((GZWFILE_T)wdh->fh, buf, (unsigned) bufsize);
        /*
         * gzwfile_write() returns 0 on error.
         */
        if (nwritten == 0) {
            *err = gzwfile_geterr((GZWFILE_T)wdh->fh);
            return FALSE;
        }
    } else
#endif
    {
        nwritten = fwrite(buf, 1, bufsize, (FILE *)wdh->fh);
        /*
         * At least according to the Mac OS X man page,
         * this can return a short count on an error.
         */
        if (nwritten != bufsize) {
            if (ferror((FILE *)wdh->fh))
                *err = errno;
            else
                *err = 999;//WTAP_ERR_SHORT_WRITE;
            return FALSE;
        }
    }
    return TRUE;
}

static gboolean
pcapng_write_if_descr_block(wtap_dumper *wdh, wtapng_if_descr_t *int_data, int *err)
{
        pcapng_block_header_t bh;
        pcapng_interface_description_block_t idb;
        const guint32 zero_pad = 0;
        gboolean have_options = FALSE;
        struct option option_hdr;                   /* guint16 type, guint16 value_length; */
        guint32 options_total_length = 0;
        guint32 comment_len = 0, if_name_len = 0, if_description_len = 0 , if_os_len = 0, if_filter_str_len = 0;
        guint32 comment_pad_len = 0, if_name_pad_len = 0, if_description_pad_len = 0, if_os_pad_len = 0, if_filter_str_pad_len = 0;


//		pcapng_debug3("pcapng_write_if_descr_block: encap = %d (%s), snaplen = %d",
//                      int_data->link_type,
//                      wtap_encap_string(wtap_pcap_encap_to_wtap_encap(int_data->link_type)),
//                      int_data->snap_len);

        if (int_data->link_type == (guint16)-1) {
                *err = 999;//WTAP_ERR_UNSUPPORTED_ENCAP;
                return FALSE;
        }

        /* Calculate options length */
        if (int_data->opt_comment) {
                have_options = TRUE;
                comment_len = (guint32)strlen(int_data->opt_comment) & 0xffff;
                if ((comment_len % 4)) {
                        comment_pad_len = 4 - (comment_len % 4);
                } else {
                        comment_pad_len = 0;
                }
                options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
        }

        /*
         * if_name        2  A UTF-8 string containing the name of the device used to capture data.
         */
        if (int_data->if_name) {
                have_options = TRUE;
                if_name_len = (guint32)strlen(int_data->if_name) & 0xffff;
                if ((if_name_len % 4)) {
                        if_name_pad_len = 4 - (if_name_len % 4);
                } else {
                        if_name_pad_len = 0;
                }
                options_total_length = options_total_length + if_name_len + if_name_pad_len + 4 /* comment options tag */ ;
        }

        /*
         * if_description 3  A UTF-8 string containing the description of the device used to capture data.
         */
        if (int_data->if_description) {
                have_options = TRUE;
                if_description_len = (guint32)strlen(int_data->if_description) & 0xffff;
                if ((if_description_len % 4)) {
                        if_description_pad_len = 4 - (if_description_len % 4);
                } else {
                        if_description_pad_len = 0;
                }
                options_total_length = options_total_length + if_description_len + if_description_pad_len + 4 /* comment options tag */ ;
        }
        /* Currently not handled
         * if_IPv4addr    4  Interface network address and netmask.
         * if_IPv6addr    5  Interface network address and prefix length (stored in the last byte).
         * if_MACaddr     6  Interface Hardware MAC address (48 bits). 00 01 02 03 04 05
         * if_EUIaddr     7  Interface Hardware EUI address (64 bits), if available. TODO: give a good example
         */
        /*
         * if_speed       8  Interface speed (in bps). 100000000 for 100Mbps
         */
        if (int_data->if_speed != 0) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4;
        }
        /*
         * if_tsresol     9  Resolution of timestamps.
         */
        if (int_data->if_tsresol != 0) {
                have_options = TRUE;
                options_total_length = options_total_length + 4 + 4;
        }
        /* Not used
         * if_tzone      10  Time zone for GMT support (TODO: specify better). TODO: give a good example
         */
        /*
         * if_filter     11  The filter (e.g. "capture only TCP traffic") used to capture traffic.
         * The first byte of the Option Data keeps a code of the filter used (e.g. if this is a libpcap string, or BPF bytecode, and more).
         */
        if (int_data->if_filter_str) {
                have_options = TRUE;
                if_filter_str_len = (guint32)(strlen(int_data->if_filter_str) + 1) & 0xffff;
                if ((if_filter_str_len % 4)) {
                        if_filter_str_pad_len = 4 - (if_filter_str_len % 4);
                } else {
                        if_filter_str_pad_len = 0;
                }
                options_total_length = options_total_length + if_filter_str_len + if_filter_str_pad_len + 4 /* comment options tag */ ;
        }
        /*
         * if_os         12  A UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
         */
        if (int_data->if_os) {
                have_options = TRUE;
                if_os_len = (guint32)strlen(int_data->if_os) & 0xffff;
                if ((if_os_len % 4)) {
                        if_os_pad_len = 4 - (if_os_len % 4);
                } else {
                        if_os_pad_len = 0;
                }
                options_total_length = options_total_length + if_os_len + if_os_pad_len + 4 /* comment options tag */ ;
        }
        /*
         * if_fcslen     13  An integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
         * -1 if unknown or changes between packets, opt 13  An integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
         */
        if (int_data->if_fcslen != 0) {
        }
        /* Not used
         * if_tsoffset   14  A 64 bits integer value that specifies an offset (in seconds) that must be added to the timestamp of each packet
         * to obtain the absolute timestamp of a packet. If the option is missing, the timestamps stored in the packet must be considered absolute timestamps.
         */

        if (have_options) {
                /* End-of-options tag */
                options_total_length += 4;
        }

        /* write block header */
        bh.block_type = BLOCK_TYPE_IDB;
        bh.block_total_length = (guint32)(sizeof(bh) + sizeof(idb) + options_total_length + 4);

        if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh;

        /* write block fixed content */
        idb.linktype    = int_data->link_type;
        idb.reserved    = 0;
        idb.snaplen     = int_data->snap_len;

        if (!wtap_dump_file_write(wdh, &idb, sizeof idb, err))
                return FALSE;
        wdh->bytes_dumped += sizeof idb;

        /* XXX - write (optional) block options */
        if (comment_len != 0) {
                option_hdr.type         = OPT_COMMENT;
                option_hdr.value_length = comment_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_if_descr_block, comment:'%s' comment_len %u comment_pad_len %u" , int_data->opt_comment, comment_len, comment_pad_len);
                if (!wtap_dump_file_write(wdh, int_data->opt_comment, comment_len, err))
                        return FALSE;
                wdh->bytes_dumped += comment_len;

                /* write padding (if any) */
                if (comment_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += comment_pad_len;
                }
        }
        /*
         * if_name        2  A UTF-8 string containing the name of the device used to capture data.
         */
        if (if_name_len !=0) {
                option_hdr.type = IDB_OPT_IF_NAME;
                option_hdr.value_length = if_name_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_if_descr_block, if_name:'%s' if_name_len %u if_name_pad_len %u" , int_data->if_name, if_name_len, if_name_pad_len);
                if (!wtap_dump_file_write(wdh, int_data->if_name, if_name_len, err))
                        return FALSE;
                wdh->bytes_dumped += if_name_len;

                /* write padding (if any) */
                if (if_name_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, if_name_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += if_name_pad_len;
                }
        }
        /*
         * if_description 3  A UTF-8 string containing the description of the device used to capture data.
         */
        if (if_description_len != 0) {
                option_hdr.type          = IDB_OPT_IF_NAME;
                option_hdr.value_length = if_description_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_if_descr_block, if_description:'%s' if_description_len %u if_description_pad_len %u" , int_data->if_description, if_description_len, if_description_pad_len);
                if (!wtap_dump_file_write(wdh, int_data->if_description, if_description_len, err))
                        return FALSE;
                wdh->bytes_dumped += if_description_len;

                /* write padding (if any) */
                if (if_description_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, if_description_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += if_description_pad_len;
                }
        }
        /* Currently not handled
         * if_IPv4addr    4  Interface network address and netmask.
         * if_IPv6addr    5  Interface network address and prefix length (stored in the last byte).
         * if_MACaddr     6  Interface Hardware MAC address (48 bits). 00 01 02 03 04 05
         * if_EUIaddr     7  Interface Hardware EUI address (64 bits), if available. TODO: give a good example
         */
        /*
         * if_speed       8  Interface speed (in bps). 100000000 for 100Mbps
         */
        if (int_data->if_speed != 0) {
                option_hdr.type          = IDB_OPT_IF_SPEED;
                option_hdr.value_length = 8;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug1("pcapng_write_if_descr_block: if_speed %" G_GINT64_MODIFIER "u (bps)", int_data->if_speed);
                if (!wtap_dump_file_write(wdh, &int_data->if_speed, sizeof(guint64), err))
                        return FALSE;
                wdh->bytes_dumped += 8;
        }
        /*
         * if_tsresol     9  Resolution of timestamps.
         * default is 6 for microsecond resolution, opt 9  Resolution of timestamps.
         * If the Most Significant Bit is equal to zero, the remaining bits indicates
         * the resolution of the timestamp as as a negative power of 10
         */
        if (int_data->if_tsresol != 0) {
                option_hdr.type          = IDB_OPT_IF_TSRESOL;
                option_hdr.value_length = 1;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the time stamp resolution */
                pcapng_debug1("pcapng_write_if_descr_block: if_tsresol %u", int_data->if_tsresol);
                if (!wtap_dump_file_write(wdh, &int_data->if_tsresol, 1, err))
                        return FALSE;
                wdh->bytes_dumped += 1;
                if (!wtap_dump_file_write(wdh, &zero_pad, 3, err))
                        return FALSE;
                wdh->bytes_dumped += 3;
        }
        /* not used
         * if_tzone      10  Time zone for GMT support (TODO: specify better). TODO: give a good example
         */
        /*
         * if_filter     11  The filter (e.g. "capture only TCP traffic") used to capture traffic.
         */
        /* Libpcap string variant */
        if (if_filter_str_len !=0) {
                option_hdr.type          = IDB_OPT_IF_FILTER;
                option_hdr.value_length = if_filter_str_len;
                /* if_filter_str_len includes the leading byte indicating filter type (libpcap str or BPF code) */
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the zero indicating libpcap filter variant */
                if (!wtap_dump_file_write(wdh, &zero_pad, 1, err))
                        return FALSE;
                wdh->bytes_dumped += 1;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_if_descr_block, if_filter_str:'%s' if_filter_str_len %u if_filter_str_pad_len %u" , int_data->if_filter_str, if_filter_str_len, if_filter_str_pad_len);
                /* if_filter_str_len includes the leading byte indicating filter type (libpcap str or BPF code) */
                if (!wtap_dump_file_write(wdh, int_data->if_filter_str, if_filter_str_len-1, err))
                        return FALSE;
                wdh->bytes_dumped += if_filter_str_len - 1;

                /* write padding (if any) */
                if (if_filter_str_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, if_filter_str_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += if_filter_str_pad_len;
                }
        }
        /*
         * if_os         12  A UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
         */
        if (if_os_len != 0) {
                option_hdr.type          = IDB_OPT_IF_OS;
                option_hdr.value_length = if_os_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_if_descr_block, if_os:'%s' if_os_len %u if_os_pad_len %u" , int_data->if_os, if_os_len, if_os_pad_len);
                if (!wtap_dump_file_write(wdh, int_data->if_os, if_os_len, err))
                        return FALSE;
                wdh->bytes_dumped += if_os_len;

                /* write padding (if any) */
                if (if_os_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, if_os_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += if_os_pad_len;
                }
        }

        if (have_options) {
                option_hdr.type = OPT_EOFOPT;
                option_hdr.value_length = 0;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
        }

        /*
         * if_fcslen     13  An integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
         */
        /*
         * if_tsoffset   14  A 64 bits integer value that specifies an offset (in seconds) that must be added to the timestamp of each packet
         * to obtain the absolute timestamp of a packet. If the option is missing, the timestamps stored in the packet must be considered absolute timestamps.
         */

        /* write block footer */
        if (!wtap_dump_file_write(wdh, &bh.block_total_length,
            sizeof bh.block_total_length, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh.block_total_length;

        return TRUE;
}

static gboolean
pcapng_write_section_header_block(wtap_dumper *wdh, int *err)
{
        pcapng_block_header_t bh;
        pcapng_section_header_block_t shb;
        const guint32 zero_pad = 0;
        gboolean have_options = FALSE;
        struct option option_hdr;                   /* guint16 type, guint16 value_length; */
        guint32 options_total_length = 0;
        guint32 comment_len = 0, shb_hardware_len = 0, shb_os_len = 0, shb_user_appl_len = 0;
        guint32 comment_pad_len = 0, shb_hardware_pad_len = 0, shb_os_pad_len = 0, shb_user_appl_pad_len = 0;

        if (wdh->shb_hdr) {
                pcapng_debug0("pcapng_write_section_header_block: Have shb_hdr");
                /* Check if we should write comment option */
                if (wdh->shb_hdr->opt_comment) {
                        have_options = TRUE;
                        comment_len = (guint32)strlen(wdh->shb_hdr->opt_comment) & 0xffff;
                        if ((comment_len % 4)) {
                                comment_pad_len = 4 - (comment_len % 4);
                        } else {
                                comment_pad_len = 0;
                        }
                        options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
                }

                /* Check if we should write shb_hardware option */
                if (wdh->shb_hdr->shb_hardware) {
                        have_options = TRUE;
                        shb_hardware_len = (guint32)strlen(wdh->shb_hdr->shb_hardware) & 0xffff;
                        if ((shb_hardware_len % 4)) {
                                shb_hardware_pad_len = 4 - (shb_hardware_len % 4);
                        } else {
                                shb_hardware_pad_len = 0;
                        }
                        options_total_length = options_total_length + shb_hardware_len + shb_hardware_pad_len + 4 /* options tag */ ;
                }

                /* Check if we should write shb_os option */
                if (wdh->shb_hdr->shb_os) {
                        have_options = TRUE;
                        shb_os_len = (guint32)strlen(wdh->shb_hdr->shb_os) & 0xffff;
                        if ((shb_os_len % 4)) {
                                shb_os_pad_len = 4 - (shb_os_len % 4);
                        } else {
                                shb_os_pad_len = 0;
                        }
                        options_total_length = options_total_length + shb_os_len + shb_os_pad_len + 4 /* options tag */ ;
                }

                /* Check if we should write shb_user_appl option */
                if (wdh->shb_hdr->shb_user_appl) {
                        have_options = TRUE;
                        shb_user_appl_len = (guint32)strlen(wdh->shb_hdr->shb_user_appl) & 0xffff;
                        if ((shb_user_appl_len % 4)) {
                                shb_user_appl_pad_len = 4 - (shb_user_appl_len % 4);
                        } else {
                                shb_user_appl_pad_len = 0;
                        }
                        options_total_length = options_total_length + shb_user_appl_len + shb_user_appl_pad_len + 4 /* options tag */ ;
                }
                if (have_options) {
                        /* End-of-options tag */
                        options_total_length += 4;
                }
        }

        /* write block header */
        bh.block_type = BLOCK_TYPE_SHB;
        bh.block_total_length = (guint32)(sizeof(bh) + sizeof(shb) + options_total_length + 4);
        pcapng_debug2("pcapng_write_section_header_block: Total len %u, Options total len %u",bh.block_total_length, options_total_length);

        if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh;

        /* write block fixed content */
        /* XXX - get these values from wblock? */
        shb.magic = 0x1A2B3C4D;
        shb.version_major = 1;
        shb.version_minor = 0;
        shb.section_length = -1;

        if (!wtap_dump_file_write(wdh, &shb, sizeof shb, err))
                return FALSE;
        wdh->bytes_dumped += sizeof shb;

        /* XXX - write (optional) block options
         * opt_comment  1
         * shb_hardware 2
         * shb_os       3
         * shb_user_appl 4
         */

        if (comment_len) {
                option_hdr.type          = OPT_COMMENT;
                option_hdr.value_length = comment_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_section_header_block, comment:'%s' comment_len %u comment_pad_len %u" , wdh->shb_hdr->opt_comment, comment_len, comment_pad_len);
                if (!wtap_dump_file_write(wdh, wdh->shb_hdr->opt_comment, comment_len, err))
                        return FALSE;
                wdh->bytes_dumped += comment_len;

                /* write padding (if any) */
                if (comment_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += comment_pad_len;
                }
        }

        if (shb_hardware_len) {
                option_hdr.type          = OPT_SHB_HARDWARE;
                option_hdr.value_length = shb_hardware_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the string */
                pcapng_debug3("pcapng_write_section_header_block, shb_hardware:'%s' shb_hardware_len %u shb_hardware_pad_len %u" , wdh->shb_hdr->shb_hardware, shb_hardware_len, shb_hardware_pad_len);
                if (!wtap_dump_file_write(wdh, wdh->shb_hdr->shb_hardware, shb_hardware_len, err))
                        return FALSE;
                wdh->bytes_dumped += shb_hardware_len;

                /* write padding (if any) */
                if (shb_hardware_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, shb_hardware_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += shb_hardware_pad_len;
                }
        }

        if (shb_os_len) {
                option_hdr.type          = OPT_SHB_OS;
                option_hdr.value_length = shb_os_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the string */
                pcapng_debug3("pcapng_write_section_header_block, shb_os:'%s' shb_os_len %u shb_os_pad_len %u" , wdh->shb_hdr->shb_os, shb_os_len, shb_os_pad_len);
                if (!wtap_dump_file_write(wdh, wdh->shb_hdr->shb_os, shb_os_len, err))
                        return FALSE;
                wdh->bytes_dumped += shb_os_len;

                /* write padding (if any) */
                if (shb_os_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, shb_os_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += shb_os_pad_len;
                }
        }

        if (shb_user_appl_len) {
                option_hdr.type          = OPT_SHB_USERAPPL;
                option_hdr.value_length = shb_user_appl_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_section_header_block, shb_user_appl:'%s' shb_user_appl_len %u shb_user_appl_pad_len %u" , wdh->shb_hdr->shb_user_appl, shb_user_appl_len, shb_user_appl_pad_len);
                if (!wtap_dump_file_write(wdh, wdh->shb_hdr->shb_user_appl, shb_user_appl_len, err))
                        return FALSE;
                wdh->bytes_dumped += shb_user_appl_len;

                /* write padding (if any) */
                if (shb_user_appl_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, shb_user_appl_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += shb_user_appl_pad_len;
                }
        }

        /* Write end of options if we have otions */
        if (have_options) {
                option_hdr.type = OPT_EOFOPT;
                option_hdr.value_length = 0;
                if (!wtap_dump_file_write(wdh, &zero_pad, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
        }

        /* write block footer */
        if (!wtap_dump_file_write(wdh, &bh.block_total_length,
            sizeof bh.block_total_length, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh.block_total_length;

        return TRUE;
}

static int
pcap_get_phdr_size(int encap, const union wtap_pseudo_header *pseudo_header)
{
    int hdrsize;

    switch (encap) {

    case WTAP_ENCAP_ATM_PDUS:
        hdrsize = SUNATM_LEN;
        break;

    case WTAP_ENCAP_IRDA:
        hdrsize = IRDA_SLL_LEN;
        break;

    case WTAP_ENCAP_MTP2_WITH_PHDR:
        hdrsize = MTP2_HDR_LEN;
        break;

    case WTAP_ENCAP_LINUX_LAPD:
        hdrsize = LAPD_SLL_LEN;
        break;

    case WTAP_ENCAP_SITA:
        hdrsize = SITA_HDR_LEN;
        break;

    case WTAP_ENCAP_ERF:
        hdrsize = (int)sizeof (struct erf_phdr);
        switch (pseudo_header->erf.phdr.type & 0x7F) {

        case ERF_TYPE_MC_HDLC:
        case ERF_TYPE_MC_RAW:
        case ERF_TYPE_MC_ATM:
        case ERF_TYPE_MC_RAW_CHANNEL:
        case ERF_TYPE_MC_AAL5:
        case ERF_TYPE_MC_AAL2:
        case ERF_TYPE_COLOR_MC_HDLC_POS:
            hdrsize += (int)sizeof(struct erf_mc_hdr);
            break;

        case ERF_TYPE_ETH:
        case ERF_TYPE_COLOR_ETH:
        case ERF_TYPE_DSM_COLOR_ETH:
            hdrsize += (int)sizeof(struct erf_eth_hdr);
            break;

        default:
            break;
        }

        /*
         * Add in the lengths of the extension headers.
         */
        if (pseudo_header->erf.phdr.type & 0x80) {
            int i = 0, max = sizeof(pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);
            guint8 erf_exhdr[8];
            guint8 type;

            do {
                phtonll(erf_exhdr, pseudo_header->erf.ehdr_list[i].ehdr);
                type = erf_exhdr[0];
                hdrsize += 8;
                i++;
            } while (type & 0x80 && i < max);
        }
        break;

    case WTAP_ENCAP_I2C:
        hdrsize = (int)sizeof (struct i2c_file_hdr);
        break;

    case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
        hdrsize = (int)sizeof (struct libpcap_bt_phdr);
        break;

    case WTAP_ENCAP_PPP_WITH_PHDR:
        hdrsize = (int)sizeof (struct libpcap_ppp_phdr);
        break;

    case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
        hdrsize = (int)sizeof (struct libpcap_bt_monitor_phdr);
    break;

    default:
        hdrsize = 0;
        break;
    }

    return hdrsize;
}

static gboolean
pcap_write_phdr(wtap_dumper *wdh, int encap, const union wtap_pseudo_header *pseudo_header,
    int *err)
{
    guint8 atm_hdr[SUNATM_LEN];
    guint8 irda_hdr[IRDA_SLL_LEN];
    guint8 lapd_hdr[LAPD_SLL_LEN];
    guint8 mtp2_hdr[MTP2_HDR_LEN];
    guint8 sita_hdr[SITA_HDR_LEN];
    guint8 erf_hdr[ sizeof(struct erf_mc_phdr)];
    struct i2c_file_hdr i2c_hdr;
    struct libpcap_bt_phdr bt_hdr;
    struct libpcap_bt_monitor_phdr bt_monitor_hdr;
    struct libpcap_ppp_phdr ppp_hdr;
    size_t size;

    switch (encap) {

    case WTAP_ENCAP_ATM_PDUS:
        /*
         * Write the ATM header.
         */
        atm_hdr[SUNATM_FLAGS] =
            (pseudo_header->atm.channel == 0) ? 0x80 : 0x00;
        switch (pseudo_header->atm.aal) {

        case AAL_SIGNALLING:
            /* Q.2931 */
            atm_hdr[SUNATM_FLAGS] |= 0x06;
            break;

        case AAL_5:
            switch (pseudo_header->atm.type) {

            case TRAF_LANE:
                /* LANE */
                atm_hdr[SUNATM_FLAGS] |= 0x01;
                break;

            case TRAF_LLCMX:
                /* RFC 1483 LLC multiplexed traffic */
                atm_hdr[SUNATM_FLAGS] |= 0x02;
                break;

            case TRAF_ILMI:
                /* ILMI */
                atm_hdr[SUNATM_FLAGS] |= 0x05;
                break;
            }
            break;
        }
        atm_hdr[SUNATM_VPI] = (guint8)pseudo_header->atm.vpi;
        phtons(&atm_hdr[SUNATM_VCI], pseudo_header->atm.vci);
        if (!wtap_dump_file_write(wdh, atm_hdr, sizeof(atm_hdr), err))
            return FALSE;
        wdh->bytes_dumped += sizeof(atm_hdr);
        break;

    case WTAP_ENCAP_IRDA:
        /*
         * Write the IrDA header.
         */
        memset(irda_hdr, 0, sizeof(irda_hdr));
        phtons(&irda_hdr[IRDA_SLL_PKTTYPE_OFFSET],
            pseudo_header->irda.pkttype);
        phtons(&irda_hdr[IRDA_SLL_PROTOCOL_OFFSET], 0x0017);
        if (!wtap_dump_file_write(wdh, irda_hdr, sizeof(irda_hdr), err))
            return FALSE;
        wdh->bytes_dumped += sizeof(irda_hdr);
        break;

    case WTAP_ENCAP_MTP2_WITH_PHDR:
        /*
         * Write the MTP2 header.
         */
        memset(&mtp2_hdr, 0, sizeof(mtp2_hdr));
        mtp2_hdr[MTP2_SENT_OFFSET] = pseudo_header->mtp2.sent;
        mtp2_hdr[MTP2_ANNEX_A_USED_OFFSET] = pseudo_header->mtp2.annex_a_used;
        phtons(&mtp2_hdr[MTP2_LINK_NUMBER_OFFSET],
            pseudo_header->mtp2.link_number);
        if (!wtap_dump_file_write(wdh, mtp2_hdr, sizeof(mtp2_hdr), err))
            return FALSE;
        wdh->bytes_dumped += sizeof(mtp2_hdr);
        break;

    case WTAP_ENCAP_LINUX_LAPD:
        /*
         * Write the LAPD header.
         */
        memset(&lapd_hdr, 0, sizeof(lapd_hdr));
        phtons(&lapd_hdr[LAPD_SLL_PKTTYPE_OFFSET],
            pseudo_header->lapd.pkttype);
        phtons(&lapd_hdr[LAPD_SLL_PROTOCOL_OFFSET], ETH_P_LAPD);
        lapd_hdr[LAPD_SLL_ADDR_OFFSET + 0] =
            pseudo_header->lapd.we_network?0x01:0x00;
        if (!wtap_dump_file_write(wdh, lapd_hdr, sizeof(lapd_hdr), err))
            return FALSE;
        wdh->bytes_dumped += sizeof(lapd_hdr);
        break;

    case WTAP_ENCAP_SITA:
        /*
         * Write the SITA header.
         */
        memset(&sita_hdr, 0, sizeof(sita_hdr));
        sita_hdr[SITA_FLAGS_OFFSET]   = pseudo_header->sita.sita_flags;
        sita_hdr[SITA_SIGNALS_OFFSET] = pseudo_header->sita.sita_signals;
        sita_hdr[SITA_ERRORS1_OFFSET] = pseudo_header->sita.sita_errors1;
        sita_hdr[SITA_ERRORS2_OFFSET] = pseudo_header->sita.sita_errors2;
        sita_hdr[SITA_PROTO_OFFSET]   = pseudo_header->sita.sita_proto;
        if (!wtap_dump_file_write(wdh, sita_hdr, sizeof(sita_hdr), err))
            return FALSE;
        wdh->bytes_dumped += sizeof(sita_hdr);
        break;

    case WTAP_ENCAP_ERF:
        /*
         * Write the ERF header.
         */
        memset(&erf_hdr, 0, sizeof(erf_hdr));
        phtolell(&erf_hdr[0], pseudo_header->erf.phdr.ts);
        erf_hdr[8] = pseudo_header->erf.phdr.type;
        erf_hdr[9] = pseudo_header->erf.phdr.flags;
        phtons(&erf_hdr[10], pseudo_header->erf.phdr.rlen);
        phtons(&erf_hdr[12], pseudo_header->erf.phdr.lctr);
        phtons(&erf_hdr[14], pseudo_header->erf.phdr.wlen);
        size = sizeof(struct erf_phdr);

        switch(pseudo_header->erf.phdr.type & 0x7F) {
        case ERF_TYPE_MC_HDLC:
        case ERF_TYPE_MC_RAW:
        case ERF_TYPE_MC_ATM:
        case ERF_TYPE_MC_RAW_CHANNEL:
        case ERF_TYPE_MC_AAL5:
        case ERF_TYPE_MC_AAL2:
        case ERF_TYPE_COLOR_MC_HDLC_POS:
            phtonl(&erf_hdr[16], pseudo_header->erf.subhdr.mc_hdr);
            size += (int)sizeof(struct erf_mc_hdr);
            break;
        case ERF_TYPE_ETH:
        case ERF_TYPE_COLOR_ETH:
        case ERF_TYPE_DSM_COLOR_ETH:
            phtons(&erf_hdr[16], pseudo_header->erf.subhdr.eth_hdr);
            size += (int)sizeof(struct erf_eth_hdr);
            break;
        default:
            break;
        }
        if (!wtap_dump_file_write(wdh, erf_hdr, size, err))
            return FALSE;
        wdh->bytes_dumped += size;

        /*
         * Now write out the extension headers.
         */
        if (pseudo_header->erf.phdr.type & 0x80) {
            int i = 0, max = sizeof(pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);
            guint8 erf_exhdr[8];
            guint8 type;

            do {
                phtonll(erf_exhdr, pseudo_header->erf.ehdr_list[i].ehdr);
                type = erf_exhdr[0];
                if (!wtap_dump_file_write(wdh, erf_exhdr, 8, err))
                    return FALSE;
                wdh->bytes_dumped += 8;
                i++;
            } while (type & 0x80 && i < max);
        }
        break;

    case WTAP_ENCAP_I2C:
        /*
         * Write the I2C header.
         */
        memset(&i2c_hdr, 0, sizeof(i2c_hdr));
        i2c_hdr.bus = pseudo_header->i2c.bus |
            (pseudo_header->i2c.is_event ? 0x80 : 0x00);
        phtonl((guint8 *)&i2c_hdr.flags, pseudo_header->i2c.flags);
        if (!wtap_dump_file_write(wdh, &i2c_hdr, sizeof(i2c_hdr), err))
            return FALSE;
        wdh->bytes_dumped += sizeof(i2c_hdr);
        break;

    case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
        bt_hdr.direction = GUINT32_TO_BE(pseudo_header->p2p.sent ? LIBPCAP_BT_PHDR_SENT : LIBPCAP_BT_PHDR_RECV);
        if (!wtap_dump_file_write(wdh, &bt_hdr, sizeof bt_hdr, err))
            return FALSE;
        wdh->bytes_dumped += sizeof bt_hdr;
        break;

    case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
        bt_monitor_hdr.adapter_id = GUINT16_TO_BE(pseudo_header->btmon.adapter_id);
        bt_monitor_hdr.opcode = GUINT16_TO_BE(pseudo_header->btmon.opcode);

        if (!wtap_dump_file_write(wdh, &bt_monitor_hdr, sizeof bt_monitor_hdr, err))
            return FALSE;
        wdh->bytes_dumped += sizeof bt_monitor_hdr;
        break;

    case WTAP_ENCAP_PPP_WITH_PHDR:
        ppp_hdr.direction = (pseudo_header->p2p.sent ? LIBPCAP_PPP_PHDR_SENT : LIBPCAP_PPP_PHDR_RECV);
        if (!wtap_dump_file_write(wdh, &ppp_hdr, sizeof ppp_hdr, err))
            return FALSE;
        wdh->bytes_dumped += sizeof ppp_hdr;
        break;
    }
    return TRUE;
}

static gboolean
pcapng_write_enhanced_packet_block(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err)
{
        pcapng_block_header_t bh;
        pcapng_enhanced_packet_block_t epb;
        guint64 ts;
        const guint32 zero_pad = 0;
        guint32 pad_len;
        guint32 phdr_len;
        gboolean have_options = FALSE;
        guint32 options_total_length = 0;
        struct option option_hdr;
        guint32 comment_len = 0, comment_pad_len = 0;
        wtapng_if_descr_t int_data;

    /* Don't write anything we're not willing to read. */
    if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return FALSE;
    }

        phdr_len = (guint32)pcap_get_phdr_size(phdr->pkt_encap, pseudo_header);
        if ((phdr_len + phdr->caplen) % 4) {
                pad_len = 4 - ((phdr_len + phdr->caplen) % 4);
        } else {
                pad_len = 0;
        }

        /* Check if we should write comment option */
        if (phdr->opt_comment) {
                have_options = TRUE;
                comment_len = (guint32)strlen(phdr->opt_comment) & 0xffff;
                if ((comment_len % 4)) {
                        comment_pad_len = 4 - (comment_len % 4);
                } else {
                        comment_pad_len = 0;
                }
                options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
        }
        if (phdr->presence_flags & WTAP_HAS_PACK_FLAGS) {
                have_options = TRUE;
                options_total_length = options_total_length + 8;
        }
        if (have_options) {
                /* End-of optios tag */
                options_total_length += 4;
        }

        /* write (enhanced) packet block header */
        bh.block_type = BLOCK_TYPE_EPB;
        bh.block_total_length = (guint32)sizeof(bh) + (guint32)sizeof(epb) + phdr_len + phdr->caplen + pad_len + options_total_length + 4;

        if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh;

        /* write block fixed content */
        if (phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
                epb.interface_id        = phdr->interface_id;
        else {
                /*
                 * XXX - we should support writing WTAP_ENCAP_PER_PACKET
                 * data to pcap-NG files even if we *don't* have interface
                 * IDs.
                 */
                epb.interface_id        = 0;
        }
        /*
         * Split the 64-bit timestamp into two 32-bit pieces, using
         * the time stamp resolution for the interface.
         */
        if (epb.interface_id >= wdh->interface_data->len) {
                /*
                 * Our caller is doing something bad.
                 */
                *err = WTAP_ERR_INTERNAL;
                return FALSE;
        }
        int_data = g_array_index(wdh->interface_data, wtapng_if_descr_t,
            epb.interface_id);
        ts = ((guint64)phdr->ts.secs) * int_data.time_units_per_second +
             (((guint64) phdr->ts.nsecs) * int_data.time_units_per_second) / 1000000;
        epb.timestamp_high      = (guint32)(ts >> 32);
        epb.timestamp_low       = (guint32)ts;
        epb.captured_len        = phdr->caplen + phdr_len;
        epb.packet_len          = phdr->len + phdr_len;

        if (!wtap_dump_file_write(wdh, &epb, sizeof epb, err))
                return FALSE;
        wdh->bytes_dumped += sizeof epb;

        /* write pseudo header */
        if (!pcap_write_phdr(wdh, phdr->pkt_encap, pseudo_header, err)) {
                return FALSE;
        }
        wdh->bytes_dumped += phdr_len;

        /* write packet data */
        if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
                return FALSE;
        wdh->bytes_dumped += phdr->caplen;

        /* write padding (if any) */
        if (pad_len != 0) {
                if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
                        return FALSE;
                wdh->bytes_dumped += pad_len;
        }

        /* XXX - write (optional) block options */
        /* options defined in Section 2.5 (Options)
         * Name           Code Length     Description
         * opt_comment    1    variable   A UTF-8 string containing a comment that is associated to the current block.
         *
         * Enhanced Packet Block options
         * epb_flags      2    4          A flags word containing link-layer information. A complete specification of
         *                                the allowed flags can be found in Appendix A (Packet Block Flags Word).
         * epb_hash       3    variable   This option contains a hash of the packet. The first byte specifies the hashing algorithm,
         *                                while the following bytes contain the actual hash, whose size depends on the hashing algorithm,
         *                                                                and hence from the value in the first bit. The hashing algorithm can be: 2s complement
         *                                                                (algorithm byte = 0, size=XXX), XOR (algorithm byte = 1, size=XXX), CRC32 (algorithm byte = 2, size = 4),
         *                                                                MD-5 (algorithm byte = 3, size=XXX), SHA-1 (algorithm byte = 4, size=XXX).
         *                                                                The hash covers only the packet, not the header added by the capture driver:
         *                                                                this gives the possibility to calculate it inside the network card.
         *                                                                The hash allows easier comparison/merging of different capture files, and reliable data transfer between the
         *                                                                data acquisition system and the capture library.
         * epb_dropcount   4   8          A 64bit integer value specifying the number of packets lost (by the interface and the operating system)
         *                                between this packet and the preceding one.
         * opt_endofopt    0   0          It delimits the end of the optional fields. This block cannot be repeated within a given list of options.
         */
        if (phdr->opt_comment) {
                option_hdr.type         = OPT_COMMENT;
                option_hdr.value_length = comment_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_enhanced_packet_block, comment:'%s' comment_len %u comment_pad_len %u" , phdr->opt_comment, comment_len, comment_pad_len);
                if (!wtap_dump_file_write(wdh, phdr->opt_comment, comment_len, err))
                        return FALSE;
                wdh->bytes_dumped += comment_len;

                /* write padding (if any) */
                if (comment_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += comment_pad_len;
                }

                pcapng_debug2("pcapng_write_enhanced_packet_block: Wrote Options comments: comment_len %u, comment_pad_len %u",
                        comment_len,
                        comment_pad_len);
        }
        if (phdr->presence_flags & WTAP_HAS_PACK_FLAGS) {
                option_hdr.type         = OPT_EPB_FLAGS;
                option_hdr.value_length = 4;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
                if (!wtap_dump_file_write(wdh, &phdr->pack_flags, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
                pcapng_debug1("pcapng_write_enhanced_packet_block: Wrote Options packet flags: %x", phdr->pack_flags);
        }
        /* Write end of options if we have otions */
        if (have_options) {
                if (!wtap_dump_file_write(wdh, &zero_pad, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
        }

        /* write block footer */
        if (!wtap_dump_file_write(wdh, &bh.block_total_length,
            sizeof bh.block_total_length, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh.block_total_length;

        return TRUE;
}

static gboolean pcapng_dump(wtap_dumper *wdh,
        const struct wtap_pkthdr *phdr,
        const guint8 *pd, int *err)
{
        const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
#ifdef HAVE_PLUGINS
        block_handler *handler;
#endif

        pcapng_debug2("pcapng_dump: encap = %d (%s)",
                      phdr->pkt_encap,
                      wtap_encap_string(phdr->pkt_encap));

        switch (phdr->rec_type) {

        case REC_TYPE_PACKET:
                if (!pcapng_write_enhanced_packet_block(wdh, phdr, pseudo_header, pd, err)) {
                        return FALSE;
                }
                break;

        case REC_TYPE_FT_SPECIFIC_EVENT:
        case REC_TYPE_FT_SPECIFIC_REPORT:
#ifdef HAVE_PLUGINS
                /*
                 * Do we have a handler for this block type?
                 */
                if (block_handlers != NULL &&
                    (handler = (block_handler *)g_hash_table_lookup(block_handlers,
                                                                    GUINT_TO_POINTER(pseudo_header->ftsrec.record_type))) != NULL) {
                    /* Yes. Call it to write out this record. */
                    if (!handler->write(wdh, phdr, pd, err))
                        return FALSE;
                } else
#endif
                {
                        /* No. */
                        *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
                        return FALSE;
                }
                break;

        default:
                /* We don't support writing this record type. */
                *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
                return FALSE;
        }

        return TRUE;
}

static gboolean
pcapng_write_interface_statistics_block(wtap_dumper *wdh, wtapng_if_stats_t *if_stats, int *err)
{

        pcapng_block_header_t bh;
        pcapng_interface_statistics_block_t isb;
        const guint32 zero_pad = 0;
        gboolean have_options = FALSE;
        struct option option_hdr;                   /* guint16 type, guint16 value_length; */
        guint32 options_total_length = 0;
        guint32 comment_len = 0;
        guint32 comment_pad_len = 0;

        pcapng_debug0("pcapng_write_interface_statistics_block");


        /* Calculate options length */
        if (if_stats->opt_comment) {
                have_options = TRUE;
                comment_len = (guint32)strlen(if_stats->opt_comment) & 0xffff;
                if ((comment_len % 4)) {
                        comment_pad_len = 4 - (comment_len % 4);
                } else {
                        comment_pad_len = 0;
                }
                options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
        }
        /*guint64				isb_starttime */
        if (if_stats->isb_starttime != 0) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }
        /*guint64				isb_endtime */
        if (if_stats->isb_endtime != 0) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }
        /*guint64				isb_ifrecv */
        if (if_stats->isb_ifrecv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }
        /*guint64				isb_ifdrop */
        if (if_stats->isb_ifdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }
        /*guint64				isb_filteraccept */
        if (if_stats->isb_filteraccept != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }
        /*guint64				isb_osdrop */
        if (if_stats->isb_osdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }
        /*guint64				isb_usrdeliv */
        if (if_stats->isb_usrdeliv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                have_options = TRUE;
                options_total_length = options_total_length + 8 + 4 /* options tag */ ;
        }

        /* write block header */
        if (have_options) {
                /* End-of-optios tag */
                options_total_length += 4;
        }

        /* write block header */
        bh.block_type = BLOCK_TYPE_ISB;
        bh.block_total_length = (guint32)(sizeof(bh) + sizeof(isb) + options_total_length + 4);

        if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh;

        /* write block fixed content */
        isb.interface_id                = if_stats->interface_id;
        isb.timestamp_high              = if_stats->ts_high;
        isb.timestamp_low               = if_stats->ts_low;


        if (!wtap_dump_file_write(wdh, &isb, sizeof isb, err))
                return FALSE;
        wdh->bytes_dumped += sizeof isb;

        /* write (optional) block options */
        if (comment_len) {
                option_hdr.type          = OPT_COMMENT;
                option_hdr.value_length  = comment_len;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write the comments string */
                pcapng_debug3("pcapng_write_interface_statistics_block, comment:'%s' comment_len %u comment_pad_len %u" , if_stats->opt_comment, comment_len, comment_pad_len);
                if (!wtap_dump_file_write(wdh, if_stats->opt_comment, comment_len, err))
                        return FALSE;
                wdh->bytes_dumped += comment_len;

                /* write padding (if any) */
                if (comment_pad_len != 0) {
                        if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                                return FALSE;
                        wdh->bytes_dumped += comment_pad_len;
                }
        }
        /*guint64               isb_starttime */
        if (if_stats->isb_starttime != 0) {
                guint32 high, low;

                option_hdr.type = ISB_STARTTIME;
                option_hdr.value_length = 8;
                high = (guint32)((if_stats->isb_starttime>>32) & 0xffffffff);
                low = (guint32)(if_stats->isb_starttime & 0xffffffff);
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_starttime */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_starttime: %" G_GINT64_MODIFIER "u" , if_stats->isb_starttime);
                if (!wtap_dump_file_write(wdh, &high, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
                if (!wtap_dump_file_write(wdh, &low, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
        }
        /*guint64               isb_endtime */
        if (if_stats->isb_endtime != 0) {
                guint32 high, low;

                option_hdr.type = ISB_ENDTIME;
                option_hdr.value_length = 8;
                high = (guint32)((if_stats->isb_endtime>>32) & 0xffffffff);
                low = (guint32)(if_stats->isb_endtime & 0xffffffff);
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_endtime */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_starttime: %" G_GINT64_MODIFIER "u" , if_stats->isb_endtime);
                if (!wtap_dump_file_write(wdh, &high, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
                if (!wtap_dump_file_write(wdh, &low, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
        }
        /*guint64               isb_ifrecv;*/
        if (if_stats->isb_ifrecv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                option_hdr.type          = ISB_IFRECV;
                option_hdr.value_length  = 8;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_ifrecv */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_ifrecv: %" G_GINT64_MODIFIER "u" , if_stats->isb_ifrecv);
                if (!wtap_dump_file_write(wdh, &if_stats->isb_ifrecv, 8, err))
                        return FALSE;
                wdh->bytes_dumped += 8;
        }
        /*guint64               isb_ifdrop;*/
        if (if_stats->isb_ifdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                option_hdr.type          = ISB_IFDROP;
                option_hdr.value_length  = 8;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_ifdrop */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_ifdrop: %" G_GINT64_MODIFIER "u" , if_stats->isb_ifdrop);
                if (!wtap_dump_file_write(wdh, &if_stats->isb_ifdrop, 8, err))
                        return FALSE;
                wdh->bytes_dumped += 8;
        }
        /*guint64               isb_filteraccept;*/
        if (if_stats->isb_filteraccept != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                option_hdr.type          = ISB_FILTERACCEPT;
                option_hdr.value_length  = 8;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_filteraccept */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_filteraccept: %" G_GINT64_MODIFIER "u" , if_stats->isb_filteraccept);
                if (!wtap_dump_file_write(wdh, &if_stats->isb_filteraccept, 8, err))
                        return FALSE;
                wdh->bytes_dumped += 8;
        }
        /*guint64               isb_osdrop;*/
        if (if_stats->isb_osdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                option_hdr.type          = ISB_OSDROP;
                option_hdr.value_length  = 8;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_osdrop */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_osdrop: %" G_GINT64_MODIFIER "u" , if_stats->isb_osdrop);
                if (!wtap_dump_file_write(wdh, &if_stats->isb_osdrop, 8, err))
                        return FALSE;
                wdh->bytes_dumped += 8;
        }
        /*guint64               isb_usrdeliv;*/
        if (if_stats->isb_usrdeliv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
                option_hdr.type          = ISB_USRDELIV;
                option_hdr.value_length  = 8;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;

                /* Write isb_usrdeliv */
                pcapng_debug1("pcapng_write_interface_statistics_block, isb_usrdeliv: %" G_GINT64_MODIFIER "u" , if_stats->isb_usrdeliv);
                if (!wtap_dump_file_write(wdh, &if_stats->isb_usrdeliv, 8, err))
                        return FALSE;
                wdh->bytes_dumped += 8;
        }

        if (have_options) {
                option_hdr.type = OPT_EOFOPT;
                option_hdr.value_length = 0;
                if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                        return FALSE;
                wdh->bytes_dumped += 4;
        }

        /* write block footer */
        if (!wtap_dump_file_write(wdh, &bh.block_total_length,
            sizeof bh.block_total_length, err))
                return FALSE;
        wdh->bytes_dumped += sizeof bh.block_total_length;

        return TRUE;

}

/* Arbitrary. */
#define NRES_REC_MAX_SIZE ((WTAP_MAX_PACKET_SIZE * 4) + 16)
static gboolean
pcapng_write_name_resolution_block(wtap_dumper *wdh, int *err)
{
    pcapng_block_header_t bh;
    pcapng_name_resolution_block_t nrb;
    guint8 *rec_data;
    gint rec_off, namelen, tot_rec_len;
    hashipv4_t *ipv4_hash_list_entry;
    hashipv6_t *ipv6_hash_list_entry;
    int i;

    if ((!wdh->addrinfo_lists) || ((!wdh->addrinfo_lists->ipv4_addr_list)&&(!wdh->addrinfo_lists->ipv6_addr_list))) {
        return TRUE;
    }

    rec_off = 8; /* block type + block total length */
    bh.block_type = BLOCK_TYPE_NRB;
    bh.block_total_length = rec_off + 8; /* end-of-record + block total length */
    rec_data = (guint8 *)g_malloc(NRES_REC_MAX_SIZE);

    if (wdh->addrinfo_lists->ipv4_addr_list){
        i = 0;
        ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, i);
        while(ipv4_hash_list_entry != NULL){

            nrb.record_type = NRES_IP4RECORD;
            namelen = (gint)strlen(ipv4_hash_list_entry->name) + 1;
            nrb.record_len = 4 + namelen;
            tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);

            if (rec_off + tot_rec_len > NRES_REC_MAX_SIZE){
                /* We know the total length now; copy the block header. */
                memcpy(rec_data, &bh, sizeof(bh));

                /* End of record */
                memset(rec_data + rec_off, 0, 4);
                rec_off += 4;

                memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

                pcapng_debug2("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

                if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
                    g_free(rec_data);
                    return FALSE;
                }
                wdh->bytes_dumped += bh.block_total_length;

                /*Start a new NRB */
                rec_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = rec_off + 8; /* end-of-record + block total length */

            }

            bh.block_total_length += tot_rec_len;
            memcpy(rec_data + rec_off, &nrb, sizeof(nrb));
            rec_off += 4;
            memcpy(rec_data + rec_off, &(ipv4_hash_list_entry->addr), 4);
            rec_off += 4;
            memcpy(rec_data + rec_off, ipv4_hash_list_entry->name, namelen);
            rec_off += namelen;
            memset(rec_data + rec_off, 0, PADDING4(namelen));
            rec_off += PADDING4(namelen);
            pcapng_debug1("NRB: added IPv4 record for %s", ipv4_hash_list_entry->name);

            i++;
            ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, i);
        }
        g_list_free(wdh->addrinfo_lists->ipv4_addr_list);
        wdh->addrinfo_lists->ipv4_addr_list = NULL;
    }

    if (wdh->addrinfo_lists->ipv6_addr_list){
        i = 0;
        ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, i);
        while(ipv6_hash_list_entry != NULL){

            nrb.record_type = NRES_IP6RECORD;
            namelen = (gint)strlen(ipv6_hash_list_entry->name) + 1;
            nrb.record_len = 16 + namelen;  /* 16 bytes IPv6 address length */
            /* 2 bytes record type, 2 bytes length field */
            tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);

            if (rec_off + tot_rec_len > NRES_REC_MAX_SIZE){
                /* We know the total length now; copy the block header. */
                memcpy(rec_data, &bh, sizeof(bh));

                /* End of record */
                memset(rec_data + rec_off, 0, 4);
                rec_off += 4;

                memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

                pcapng_debug2("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

                if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
                    g_free(rec_data);
                    return FALSE;
                }
                wdh->bytes_dumped += bh.block_total_length;

                /*Start a new NRB */
                rec_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = rec_off + 8; /* end-of-record + block total length */

            }

            bh.block_total_length += tot_rec_len;
            memcpy(rec_data + rec_off, &nrb, sizeof(nrb));
            rec_off += 4;
            memcpy(rec_data + rec_off, &(ipv6_hash_list_entry->addr), 16);
            rec_off += 16;
            memcpy(rec_data + rec_off, ipv6_hash_list_entry->name, namelen);
            rec_off += namelen;
            memset(rec_data + rec_off, 0, PADDING4(namelen));
            rec_off += PADDING4(namelen);
            pcapng_debug1("NRB: added IPv6 record for %s", ipv6_hash_list_entry->name);

            i++;
            ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, i);
        }
        g_list_free(wdh->addrinfo_lists->ipv6_addr_list);
        wdh->addrinfo_lists->ipv6_addr_list = NULL;
    }

    /* We know the total length now; copy the block header. */
    memcpy(rec_data, &bh, sizeof(bh));

    /* End of record */
    memset(rec_data + rec_off, 0, 4);
    rec_off += 4;

    memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

    pcapng_debug2("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

    if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
        g_free(rec_data);
        return FALSE;
    }

    g_free(rec_data);
    wdh->bytes_dumped += bh.block_total_length;
    return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean pcapng_dump_close(wtap_dumper *wdh, int *err)
{
        guint i, j;

        /* Flush any hostname resolution info we may have */
        pcapng_write_name_resolution_block(wdh, err);

        for (i = 0; i < wdh->interface_data->len; i++) {

                /* Get the interface description */
                wtapng_if_descr_t int_data;

                int_data = g_array_index(wdh->interface_data, wtapng_if_descr_t, i);
                for (j = 0; j < int_data.num_stat_entries; j++) {
                        wtapng_if_stats_t if_stats;

                        if_stats = g_array_index(int_data.interface_statistics, wtapng_if_stats_t, j);
                        pcapng_debug1("pcapng_dump_close: write ISB for interface %u",if_stats.interface_id);
                        if (!pcapng_write_interface_statistics_block(wdh, &if_stats, err)) {
                                return FALSE;
                        }
                }
        }

        pcapng_debug0("pcapng_dump_close");
        return TRUE;
}

static void wtap_dump_flush(wtap_dumper *wdh)
{
#ifdef HAVE_LIBZ
    if(wdh->compressed) {
        gzwfile_flush((GZWFILE_T)wdh->fh);
    } else
#endif
    {
        fflush((FILE *)wdh->fh);
    }
}
static gboolean
pcapng_dump_open(wtap_dumper *wdh, int *err)
{
        guint i;

        //pcapng_debug0("pcapng_dump_open");
        /* This is a pcapng file */
//        wdh->subtype_write = pcapng_dump;
//        wdh->subtype_close = pcapng_dump_close;

        if (wdh->interface_data->len == 0) {
//                pcapng_debug0("There are no interfaces. Can't handle that...");
//                *err = WTAP_ERR_INTERNAL;
                return FALSE;
        }

        /* write the section header block */
        if (!pcapng_write_section_header_block(wdh, err)) {
                return FALSE;
        }
        //pcapng_debug0("pcapng_dump_open: wrote section header block.");

        /* Write the Interface description blocks */
//        pcapng_debug1("pcapng_dump_open: Number of IDB:s to write (number of interfaces) %u",
//                wdh->interface_data->len);

        for (i = 0; i < wdh->interface_data->len; i++) {

                /* Get the interface description */
                wtapng_if_descr_t int_data;

                int_data = g_array_index(wdh->interface_data, wtapng_if_descr_t, i);

                if (!pcapng_write_if_descr_block(wdh, &int_data, err)) {
                        return FALSE;
                }

        }

        return TRUE;
}

static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int *err)
{
    int fd;
    fd = fileno((FILE *)wdh->fh);
    if (lseek(fd, 1, SEEK_CUR) != -1)
        lseek(fd, 0, SEEK_SET);

    if (!pcapng_dump_open(wdh, err)) {
            return FALSE;
    }
    return TRUE;
}


gboolean wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
           const guint8 *pd, int *err,int flush_flag)
{
    gboolean res = pcapng_dump(wdh, phdr, pd, err);
    if(flush_flag)
        wtap_dump_flush(wdh);
    return res;
}


gboolean wtap_dump_close(wtap_dumper *wdh, int *err)
{
    gboolean ret = TRUE;

    if (!pcapng_dump_close(wdh, err))
                ret = FALSE;

    errno = WTAP_ERR_CANT_CLOSE;
    /* Don't close stdout */
    if (wdh->fh != stdout) {
        if (wtap_dump_file_close(wdh->fh) == EOF) {
            if (ret) {
                /* The per-format close function succeeded,
                   but the fclose didn't.  Save the reason
                   why, if our caller asked for it. */
                if (err != NULL)
                    *err = errno;
            }
            ret = FALSE;
        }
    } else {
        /* as we don't close stdout, at least try to flush it */
        wtap_dump_flush(wdh);
    }
    g_array_free(wdh->interface_data,TRUE);
    g_free(wdh);
    return ret;
}


wtap_dumper* wtap_dump_open_ng(const char *filename, wtapng_section_t *shb_hdr,
        wtapng_iface_descriptions_t *idb_inf, int *err){

    wtap_dumper *wdh;
    wdh = (wtap_dumper *)g_malloc0(sizeof (wtap_dumper));
    if(wdh == NULL){
        return NULL;
    }
    wdh->fh = wtap_dump_file_open(filename);
    if (wdh->fh == NULL) {
        return NULL;	/* can't create file */
    }
    wdh->interface_data =  idb_inf->interface_data;
    wdh->shb_hdr  = shb_hdr;

    if (!wtap_dump_open_finish(wdh, err)) {
        /* Get rid of the file we created; we couldn't finish
           opening it. */
        if (wdh->fh != stdout) {
            wtap_dump_file_close(wdh->fh);
            unlink(filename);
        }
        return NULL;
    }
    return wdh;
}
#endif /*#ifdef HAVE_LIBPCAPNG*/

