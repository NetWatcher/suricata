/* pcapng.h
 *
 * Original code downloaded from: https://www.wireshark.org/download.html
 *
 * pcapng.h -- This file contains extraction of code from wireshark app
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

#ifndef PCAPNG_H_
#define PCAPNG_H_

#ifdef HAVE_LIBPCAPNG

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

/* Block types */
#define BLOCK_TYPE_IDB 0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB  0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB 0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_NRB 0x00000004 /* Name Resolution Block */
#define BLOCK_TYPE_ISB 0x00000005 /* Interface Statistics Block */
#define BLOCK_TYPE_EPB 0x00000006 /* Enhanced Packet Block */
#define BLOCK_TYPE_SHB 0x0A0D0D0A /* Section Header Block */

#define ISB_STARTTIME     2
#define ISB_ENDTIME       3
#define ISB_IFRECV        4
#define ISB_IFDROP        5
#define ISB_FILTERACCEPT  6
#define ISB_OSDROP        7
#define ISB_USRDELIV      8

/* Options */
#define OPT_EOFOPT        0
#define OPT_COMMENT       1
#define OPT_SHB_HARDWARE  2
#define OPT_SHB_OS        3
#define OPT_SHB_USERAPPL  4
#define OPT_EPB_FLAGS     2
#define OPT_EPB_HASH      3
#define OPT_EPB_DROPCOUNT 4

typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;
typedef signed int gint32;
typedef unsigned int guint32;
typedef signed long gssize;
typedef unsigned long gsize;
typedef unsigned char guint8;

#define IDB_OPT_IF_NAME         2
#define IDB_OPT_IF_DESCR        3
#define IDB_OPT_IF_SPEED        8
#define IDB_OPT_IF_TSRESOL      9
#define IDB_OPT_IF_FILTER       11
#define IDB_OPT_IF_OS           12

/**
 * Wiretap error codes.
 */
#define WTAP_ERR_NOT_REGULAR_FILE              -1
    /** The file being opened for reading isn't a plain file (or pipe) */

#define WTAP_ERR_RANDOM_OPEN_PIPE              -2
    /** The file is being opened for random access and it's a pipe */

#define WTAP_ERR_FILE_UNKNOWN_FORMAT           -3
    /** The file being opened is not a capture file in a known format */

#define WTAP_ERR_UNSUPPORTED                   -4
    /** Supported file type, but there's something in the file we
       can't support */

#define WTAP_ERR_CANT_WRITE_TO_PIPE            -5
    /** Wiretap can't save to a pipe in the specified format */

#define WTAP_ERR_CANT_OPEN                     -6
    /** The file couldn't be opened, reason unknown */

#define WTAP_ERR_UNSUPPORTED_FILE_TYPE         -7
    /** Wiretap can't save files in the specified format */

#define WTAP_ERR_UNSUPPORTED_ENCAP             -8
    /** Wiretap can't read or save files in the specified format with the
       specified encapsulation */

#define WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED  -9
    /** The specified format doesn't support per-packet encapsulations */

#define WTAP_ERR_CANT_CLOSE                   -10
    /** The file couldn't be closed, reason unknown */

#define WTAP_ERR_CANT_READ                    -11
    /** An attempt to read failed, reason unknown */

#define WTAP_ERR_SHORT_READ                   -12
    /** An attempt to read read less data than it should have */

#define WTAP_ERR_BAD_FILE                     -13
    /** The file appears to be damaged or corrupted or otherwise bogus */

#define WTAP_ERR_SHORT_WRITE                  -14
    /** An attempt to write wrote less data than it should have */

#define WTAP_ERR_UNC_TRUNCATED                -15
    /** Sniffer compressed data was oddly truncated */

#define WTAP_ERR_UNC_OVERFLOW                 -16
    /** Uncompressing Sniffer data would overflow buffer */

#define WTAP_ERR_UNC_BAD_OFFSET               -17
    /** LZ77 compressed data has bad offset to string */

#define WTAP_ERR_RANDOM_OPEN_STDIN            -18
    /** We're trying to open the standard input for random access */

#define WTAP_ERR_COMPRESSION_NOT_SUPPORTED    -19
    /* The filetype doesn't support output compression */

#define WTAP_ERR_CANT_SEEK                    -20
    /** An attempt to seek failed, reason unknown */

#define WTAP_ERR_CANT_SEEK_COMPRESSED         -21
    /** An attempt to seek on a compressed stream */

#define WTAP_ERR_DECOMPRESS                   -22
    /** Error decompressing */

#define WTAP_ERR_INTERNAL                     -23
    /** "Shouldn't happen" internal errors */

#define WTAP_ERR_PACKET_TOO_LARGE             -24
    /** Packet being written is larger than we support; do not use when
        reading, use WTAP_ERR_BAD_FILE instead */

#define WTAP_ERR_CHECK_WSLUA                  -25
    /** Not really an error: the file type being checked is from a Lua
        plugin, so that the code will call wslua_can_write_encap() instead if it gets this */

#define WTAP_ERR_REC_TYPE_UNSUPPORTED         -26
    /** Specified record type can't be written to that file type */

typedef void *WFILE_T;

#define pcapng_debug0(str)
#define pcapng_debug1(str,p1)
#define pcapng_debug2(str,p1,p2)
#define pcapng_debug3(str,p1,p2,p3)

/* Encapsulation types. Choose names that truly reflect
 * what is contained in the packet trace file.
 *
 * WTAP_ENCAP_PER_PACKET is a value passed to "wtap_dump_open()" or
 * "wtap_dump_fd_open()" to indicate that there is no single encapsulation
 * type for all packets in the file; this may cause those routines to
 * fail if the capture file format being written can't support that.
 * It's also returned by "wtap_file_encap()" for capture files that
 * don't have a single encapsulation type for all packets in the file.
 *
 * WTAP_ENCAP_UNKNOWN is returned by "wtap_pcap_encap_to_wtap_encap()"
 * if it's handed an unknown encapsulation.
 *
 * WTAP_ENCAP_FDDI_BITSWAPPED is for FDDI captures on systems where the
 * MAC addresses you get from the hardware are bit-swapped.  Ideally,
 * the driver would tell us that, but I know of none that do, so, for
 * now, we base it on the machine on which we're *reading* the
 * capture, rather than on the machine on which the capture was taken
 * (they're probably likely to be the same).  We assume that they're
 * bit-swapped on everything except for systems running Ultrix, Alpha
 * systems, and BSD/OS systems (that's what "tcpdump" does; I guess
 * Digital decided to bit-swap addresses in the hardware or in the
 * driver, and I guess BSDI bit-swapped them in the driver, given that
 * BSD/OS generally runs on Boring Old PC's).  If we create a wiretap
 * save file format, we'd use the WTAP_ENCAP values to flag the
 * encapsulation of a packet, so there we'd at least be able to base
 * it on the machine on which the capture was taken.
 *
 * WTAP_ENCAP_LINUX_ATM_CLIP is the encapsulation you get with the
 * ATM on Linux code from <http://linux-atm.sourceforge.net/>;
 * that code adds a DLT_ATM_CLIP DLT_ code of 19, and that
 * encapsulation isn't the same as the DLT_ATM_RFC1483 encapsulation
 * presumably used on some BSD systems, which we turn into
 * WTAP_ENCAP_ATM_RFC1483.
 *
 * WTAP_ENCAP_NULL corresponds to DLT_NULL from "libpcap".  This
 * corresponds to
 *
 *  1) PPP-over-HDLC encapsulation, at least with some versions
 *     of ISDN4BSD (but not the current ones, it appears, unless
 *     I've missed something);
 *
 *  2) a 4-byte header containing the AF_ address family, in
 *     the byte order of the machine that saved the capture,
 *     for the packet, as used on many BSD systems for the
 *     loopback device and some other devices, or a 4-byte header
 *     containing the AF_ address family in network byte order,
 *     as used on recent OpenBSD systems for the loopback device;
 *
 *  3) a 4-byte header containing 2 octets of 0 and an Ethernet
 *     type in the byte order from an Ethernet header, that being
 *     what older versions of "libpcap" on Linux turn the Ethernet
 *     header for loopback interfaces into (0.6.0 and later versions
 *     leave the Ethernet header alone and make it DLT_EN10MB). */
#define WTAP_ENCAP_PER_PACKET                   -1
#define WTAP_ENCAP_UNKNOWN                        0
#define WTAP_ENCAP_ETHERNET                       1
#define WTAP_ENCAP_TOKEN_RING                     2
#define WTAP_ENCAP_SLIP                           3
#define WTAP_ENCAP_PPP                            4
#define WTAP_ENCAP_FDDI                           5
#define WTAP_ENCAP_FDDI_BITSWAPPED                6
#define WTAP_ENCAP_RAW_IP                         7
#define WTAP_ENCAP_ARCNET                         8
#define WTAP_ENCAP_ARCNET_LINUX                   9
#define WTAP_ENCAP_ATM_RFC1483                   10
#define WTAP_ENCAP_LINUX_ATM_CLIP                11
#define WTAP_ENCAP_LAPB                          12
#define WTAP_ENCAP_ATM_PDUS                      13
#define WTAP_ENCAP_ATM_PDUS_UNTRUNCATED          14
#define WTAP_ENCAP_NULL                          15
#define WTAP_ENCAP_ASCEND                        16
#define WTAP_ENCAP_ISDN                          17
#define WTAP_ENCAP_IP_OVER_FC                    18
#define WTAP_ENCAP_PPP_WITH_PHDR                 19
#define WTAP_ENCAP_IEEE_802_11                   20
#define WTAP_ENCAP_IEEE_802_11_PRISM             21
#define WTAP_ENCAP_IEEE_802_11_WITH_RADIO        22
#define WTAP_ENCAP_IEEE_802_11_RADIOTAP          23
#define WTAP_ENCAP_IEEE_802_11_AVS               24
#define WTAP_ENCAP_SLL                           25
#define WTAP_ENCAP_FRELAY                        26
#define WTAP_ENCAP_FRELAY_WITH_PHDR              27
#define WTAP_ENCAP_CHDLC                         28
#define WTAP_ENCAP_CISCO_IOS                     29
#define WTAP_ENCAP_LOCALTALK                     30
#define WTAP_ENCAP_OLD_PFLOG                     31
#define WTAP_ENCAP_HHDLC                         32
#define WTAP_ENCAP_DOCSIS                        33
#define WTAP_ENCAP_COSINE                        34
#define WTAP_ENCAP_WFLEET_HDLC                   35
#define WTAP_ENCAP_SDLC                          36
#define WTAP_ENCAP_TZSP                          37
#define WTAP_ENCAP_ENC                           38
#define WTAP_ENCAP_PFLOG                         39
#define WTAP_ENCAP_CHDLC_WITH_PHDR               40
#define WTAP_ENCAP_BLUETOOTH_H4                  41
#define WTAP_ENCAP_MTP2                          42
#define WTAP_ENCAP_MTP3                          43
#define WTAP_ENCAP_IRDA                          44
#define WTAP_ENCAP_USER0                         45
#define WTAP_ENCAP_USER1                         46
#define WTAP_ENCAP_USER2                         47
#define WTAP_ENCAP_USER3                         48
#define WTAP_ENCAP_USER4                         49
#define WTAP_ENCAP_USER5                         50
#define WTAP_ENCAP_USER6                         51
#define WTAP_ENCAP_USER7                         52
#define WTAP_ENCAP_USER8                         53
#define WTAP_ENCAP_USER9                         54
#define WTAP_ENCAP_USER10                        55
#define WTAP_ENCAP_USER11                        56
#define WTAP_ENCAP_USER12                        57
#define WTAP_ENCAP_USER13                        58
#define WTAP_ENCAP_USER14                        59
#define WTAP_ENCAP_USER15                        60
#define WTAP_ENCAP_SYMANTEC                      61
#define WTAP_ENCAP_APPLE_IP_OVER_IEEE1394        62
#define WTAP_ENCAP_BACNET_MS_TP                  63
#define WTAP_ENCAP_NETTL_RAW_ICMP                64
#define WTAP_ENCAP_NETTL_RAW_ICMPV6              65
#define WTAP_ENCAP_GPRS_LLC                      66
#define WTAP_ENCAP_JUNIPER_ATM1                  67
#define WTAP_ENCAP_JUNIPER_ATM2                  68
#define WTAP_ENCAP_REDBACK                       69
#define WTAP_ENCAP_NETTL_RAW_IP                  70
#define WTAP_ENCAP_NETTL_ETHERNET                71
#define WTAP_ENCAP_NETTL_TOKEN_RING              72
#define WTAP_ENCAP_NETTL_FDDI                    73
#define WTAP_ENCAP_NETTL_UNKNOWN                 74
#define WTAP_ENCAP_MTP2_WITH_PHDR                75
#define WTAP_ENCAP_JUNIPER_PPPOE                 76
#define WTAP_ENCAP_GCOM_TIE1                     77
#define WTAP_ENCAP_GCOM_SERIAL                   78
#define WTAP_ENCAP_NETTL_X25                     79
#define WTAP_ENCAP_K12                           80
#define WTAP_ENCAP_JUNIPER_MLPPP                 81
#define WTAP_ENCAP_JUNIPER_MLFR                  82
#define WTAP_ENCAP_JUNIPER_ETHER                 83
#define WTAP_ENCAP_JUNIPER_PPP                   84
#define WTAP_ENCAP_JUNIPER_FRELAY                85
#define WTAP_ENCAP_JUNIPER_CHDLC                 86
#define WTAP_ENCAP_JUNIPER_GGSN                  87
#define WTAP_ENCAP_LINUX_LAPD                    88
#define WTAP_ENCAP_CATAPULT_DCT2000              89
#define WTAP_ENCAP_BER                           90
#define WTAP_ENCAP_JUNIPER_VP                    91
#define WTAP_ENCAP_USB                           92
#define WTAP_ENCAP_IEEE802_16_MAC_CPS            93
#define WTAP_ENCAP_NETTL_RAW_TELNET              94
#define WTAP_ENCAP_USB_LINUX                     95
#define WTAP_ENCAP_MPEG                          96
#define WTAP_ENCAP_PPI                           97
#define WTAP_ENCAP_ERF                           98
#define WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR        99
#define WTAP_ENCAP_SITA                         100
#define WTAP_ENCAP_SCCP                         101
#define WTAP_ENCAP_BLUETOOTH_HCI                102 /*raw packets without a transport layer header e.g. H4*/
#define WTAP_ENCAP_IPMB                         103
#define WTAP_ENCAP_IEEE802_15_4                 104
#define WTAP_ENCAP_X2E_XORAYA                   105
#define WTAP_ENCAP_FLEXRAY                      106
#define WTAP_ENCAP_LIN                          107
#define WTAP_ENCAP_MOST                         108
#define WTAP_ENCAP_CAN20B                       109
#define WTAP_ENCAP_LAYER1_EVENT                 110
#define WTAP_ENCAP_X2E_SERIAL                   111
#define WTAP_ENCAP_I2C                          112
#define WTAP_ENCAP_IEEE802_15_4_NONASK_PHY      113
#define WTAP_ENCAP_TNEF                         114
#define WTAP_ENCAP_USB_LINUX_MMAPPED            115
#define WTAP_ENCAP_GSM_UM                       116
#define WTAP_ENCAP_DPNSS                        117
#define WTAP_ENCAP_PACKETLOGGER                 118
#define WTAP_ENCAP_NSTRACE_1_0                  119
#define WTAP_ENCAP_NSTRACE_2_0                  120
#define WTAP_ENCAP_FIBRE_CHANNEL_FC2            121
#define WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS 122
#define WTAP_ENCAP_JPEG_JFIF                    123 /* obsoleted by WTAP_ENCAP_MIME*/
#define WTAP_ENCAP_IPNET                        124
#define WTAP_ENCAP_SOCKETCAN                    125
#define WTAP_ENCAP_IEEE_802_11_NETMON           126
#define WTAP_ENCAP_IEEE802_15_4_NOFCS           127
#define WTAP_ENCAP_RAW_IPFIX                    128
#define WTAP_ENCAP_RAW_IP4                      129
#define WTAP_ENCAP_RAW_IP6                      130
#define WTAP_ENCAP_LAPD                         131
#define WTAP_ENCAP_DVBCI                        132
#define WTAP_ENCAP_MUX27010                     133
#define WTAP_ENCAP_MIME                         134
#define WTAP_ENCAP_NETANALYZER                  135
#define WTAP_ENCAP_NETANALYZER_TRANSPARENT      136
#define WTAP_ENCAP_IP_OVER_IB                   137
#define WTAP_ENCAP_MPEG_2_TS                    138
#define WTAP_ENCAP_PPP_ETHER                    139
#define WTAP_ENCAP_NFC_LLCP                     140
#define WTAP_ENCAP_NFLOG                        141
#define WTAP_ENCAP_V5_EF                        142
#define WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR       143
#define WTAP_ENCAP_IXVERIWAVE                   144
#define WTAP_ENCAP_IEEE_802_11_AIROPEEK         145
#define WTAP_ENCAP_SDH                          146
#define WTAP_ENCAP_DBUS                         147
#define WTAP_ENCAP_AX25_KISS                    148
#define WTAP_ENCAP_AX25                         149
#define WTAP_ENCAP_SCTP                         150
#define WTAP_ENCAP_INFINIBAND                   151
#define WTAP_ENCAP_JUNIPER_SVCS                 152
#define WTAP_ENCAP_USBPCAP                      153
#define WTAP_ENCAP_RTAC_SERIAL                  154
#define WTAP_ENCAP_BLUETOOTH_LE_LL              155
#define WTAP_ENCAP_WIRESHARK_UPPER_PDU          156
#define WTAP_ENCAP_STANAG_4607                  157
#define WTAP_ENCAP_STANAG_5066_D_PDU            158
#define WTAP_ENCAP_NETLINK                      159
#define WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR      160
#define WTAP_ENCAP_BLUETOOTH_BREDR_BB           161
#define WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR    162
#define WTAP_ENCAP_NSTRACE_3_0                  163
#define WTAP_ENCAP_LOGCAT                       164
#define WTAP_ENCAP_LOGCAT_BRIEF                 165
#define WTAP_ENCAP_LOGCAT_PROCESS               166
#define WTAP_ENCAP_LOGCAT_TAG                   167
#define WTAP_ENCAP_LOGCAT_THREAD                168
#define WTAP_ENCAP_LOGCAT_TIME                  169
#define WTAP_ENCAP_LOGCAT_THREADTIME            170
#define WTAP_ENCAP_LOGCAT_LONG                  171
#define WTAP_ENCAP_PKTAP                        172
#define WTAP_ENCAP_EPON                         173
#define WTAP_ENCAP_IPMI_TRACE                   174
/* After adding new item here, please also add new item to encap_table_base array */

/*
 * Various pseudo-headers that appear at the beginning of packet data.
 *
 * We represent them as sets of offsets, as they might not be aligned on
 * an appropriate structure boundary in the buffer, and as that makes them
 * independent of the way the compiler might align fields.
 */

/*
 * The link-layer header on SunATM packets.
 */
#define SUNATM_FLAGS	0	/* destination and traffic type - 1 byte */
#define SUNATM_VPI	1	/* VPI - 1 byte */
#define SUNATM_VCI	2	/* VCI - 2 bytes */
#define SUNATM_LEN	4	/* length of the header */

/*
 * The link-layer header on Nokia IPSO ATM packets.
 */
#define NOKIAATM_FLAGS	0	/* destination - 1 byte */
#define NOKIAATM_VPI	1	/* VPI - 1 byte */
#define NOKIAATM_VCI	2	/* VCI - 2 bytes */
#define NOKIAATM_LEN	4	/* length of the header */

/*
 * The link-layer header on Nokia IPSO packets.
 */
#define NOKIA_LEN	4	/* length of the header */

/*
 * The fake link-layer header of IrDA packets as introduced by Jean Tourrilhes
 * to libpcap.
 */
#define IRDA_SLL_PKTTYPE_OFFSET		0	/* packet type - 2 bytes */
/* 12 unused bytes */
#define IRDA_SLL_PROTOCOL_OFFSET	14	/* protocol, should be ETH_P_LAPD - 2 bytes */
#define IRDA_SLL_LEN			16	/* length of the header */

/*
 * A header containing additional MTP information.
 */
#define MTP2_SENT_OFFSET		0	/* 1 byte */
#define MTP2_ANNEX_A_USED_OFFSET	1	/* 1 byte */
#define MTP2_LINK_NUMBER_OFFSET		2	/* 2 bytes */
#define MTP2_HDR_LEN			4	/* length of the header */

/*
 * A header containing additional SITA WAN information.
 */
#define SITA_FLAGS_OFFSET		0	/* 1 byte */
#define SITA_SIGNALS_OFFSET		1	/* 1 byte */
#define SITA_ERRORS1_OFFSET		2	/* 1 byte */
#define SITA_ERRORS2_OFFSET		3	/* 1 byte */
#define SITA_PROTO_OFFSET		4	/* 1 byte */
#define SITA_HDR_LEN			5	/* length of the header */

/*
 * The fake link-layer header of LAPD packets.
 */
#ifndef ETH_P_LAPD
#define ETH_P_LAPD 0x0030
#endif

#define LAPD_SLL_PKTTYPE_OFFSET		0	/* packet type - 2 bytes */
#define LAPD_SLL_HATYPE_OFFSET		2	/* hardware address type - 2 bytes */
#define LAPD_SLL_HALEN_OFFSET		4	/* hardware address length - 2 bytes */
#define LAPD_SLL_ADDR_OFFSET		6	/* address - 8 bytes */
#define LAPD_SLL_PROTOCOL_OFFSET	14	/* protocol, should be ETH_P_LAPD - 2 bytes */
#define LAPD_SLL_LEN			16	/* length of the header */

/*
 * The NFC LLCP per-packet header.
 */
#define LLCP_ADAPTER_OFFSET		0
#define LLCP_FLAGS_OFFSET		1
#define LLCP_HEADER_LEN			2

/* Record type defines */
#define ERF_TYPE_LEGACY             0
#define ERF_TYPE_HDLC_POS           1
#define ERF_TYPE_ETH                2
#define ERF_TYPE_ATM                3
#define ERF_TYPE_AAL5               4
#define ERF_TYPE_MC_HDLC            5
#define ERF_TYPE_MC_RAW             6
#define ERF_TYPE_MC_ATM             7
#define ERF_TYPE_MC_RAW_CHANNEL     8
#define ERF_TYPE_MC_AAL5            9
#define ERF_TYPE_COLOR_HDLC_POS     10
#define ERF_TYPE_COLOR_ETH          11
#define ERF_TYPE_MC_AAL2            12
#define ERF_TYPE_IP_COUNTER         13
#define ERF_TYPE_TCP_FLOW_COUNTER   14
#define ERF_TYPE_DSM_COLOR_HDLC_POS 15
#define ERF_TYPE_DSM_COLOR_ETH      16
#define ERF_TYPE_COLOR_MC_HDLC_POS  17
#define ERF_TYPE_AAL2               18
#define ERF_TYPE_INFINIBAND         21
#define ERF_TYPE_IPV4               22
#define ERF_TYPE_IPV6               23
#define ERF_TYPE_RAW_LINK           24
#define ERF_TYPE_INFINIBAND_LINK    25

#define ERF_TYPE_PAD                48

#define ERF_TYPE_MIN  1   /* sanity checking */
#define ERF_TYPE_MAX  48  /* sanity checking */

/*
 * Record type values.
 *
 * This list will expand over time, so don't assume everything will
 * forever be one of the types listed below.
 *
 * For file-type-specific records, the "ftsrec" field of the pseudo-header
 * contains a file-type-specific subtype value, such as a block type for
 * a pcap-ng file.
 *
 * An "event" is an indication that something happened during the capture
 * process, such as a status transition of some sort on the network.
 * These should, ideally, have a time stamp and, if they're relevant to
 * a particular interface on a multi-interface capture, should also have
 * an interface ID.  The data for the event is file-type-specific and
 * subtype-specific.  These should be dissected and displayed just as
 * packets are.
 *
 * A "report" supplies information not corresponding to an event;
 * for example, a pcap-ng Interface Statistics Block would be a report,
 * as it doesn't correspond to something happening on the network.
 * They may have a time stamp, and should be dissected and displayed
 * just as packets are.
 *
 * We distingiush between "events" and "reports" so that, for example,
 * the packet display can show the delta between a packet and an event
 * but not show the delta between a packet and a report, as the time
 * stamp of a report may not correspond to anything interesting on
 * the network but the time stamp of an event would.
 *
 * XXX - are there any file-type-specific records that *shouldn't* be
 * dissected and displayed?  If so, they should be parsed and the
 * information in them stored somewhere, and used somewhere, whether
 * it's just used when saving the file in its native format or also
 * used to parse *other* file-type-specific records.
 */
#define REC_TYPE_PACKET               0    /**< packet */
#define REC_TYPE_FT_SPECIFIC_EVENT    1    /**< file-type-specific event */
#define REC_TYPE_FT_SPECIFIC_REPORT   2    /**< file-type-specific report */

typedef struct erf_mc_hdr {
    guint32	mc;
} erf_mc_header_t;


typedef struct erf_eth_hdr {
    guint16	eth;
} erf_eth_header_t;

/*
 * I2C link-layer on-disk format
 */
struct i2c_file_hdr {
    guint8 bus;
    guint8 flags[4];
};


/** data structure to hold time values with nanosecond resolution*/
typedef struct nstime_t {
    time_t	secs;
    int	nsecs;
} nstime_t;

/* Packet "pseudo-header" information for Ethernet capture files. */
struct eth_phdr {
    gint   fcs_len;  /* Number of bytes of FCS - -1 means "unknown" */
};

/* Packet "pseudo-header" information for X.25 capture files. */
#define FROM_DCE 0x80
struct x25_phdr {
    guint8  flags;   /* ENCAP_LAPB, ENCAP_V120 : 1st bit means From DCE */
};

/* Packet "pseudo-header" information for ISDN capture files. */

/* Direction */
struct isdn_phdr {
    gboolean uton;
    guint8   channel;   /* 0 = D-channel; n = B-channel n */
};

/* Packet "pseudo-header" for ATM capture files.
   Not all of this information is supplied by all capture types.
   These originally came from the Network General (DOS-based)
   ATM Sniffer file format, but we've added some additional
   items. */

/*
 * Status bits.
 */
#define ATM_RAW_CELL         0x01 /* TRUE if the packet is a single cell */
#define ATM_NO_HEC           0x02 /* TRUE if the cell has HEC stripped out */
#define ATM_AAL2_NOPHDR      0x04 /* TRUE if the AAL2 PDU has no pseudo-header */
#define ATM_REASSEMBLY_ERROR 0x08 /* TRUE if this is an incompletely-reassembled PDU */

/*
 * AAL types.
 */
#define AAL_UNKNOWN     0  /* AAL unknown */
#define AAL_1           1  /* AAL1 */
#define AAL_2           2  /* AAL2 */
#define AAL_3_4         3  /* AAL3/4 */
#define AAL_5           4  /* AAL5 */
#define AAL_USER        5  /* User AAL */
#define AAL_SIGNALLING  6  /* Signaling AAL */
#define AAL_OAMCELL     7  /* OAM cell */

/*
 * Traffic types.
 */
#define TRAF_UNKNOWN    0  /* Unknown */
#define TRAF_LLCMX      1  /* LLC multiplexed (RFC 1483) */
#define TRAF_VCMX       2  /* VC multiplexed (RFC 1483) */
#define TRAF_LANE       3  /* LAN Emulation */
#define TRAF_ILMI       4  /* ILMI */
#define TRAF_FR         5  /* Frame Relay */
#define TRAF_SPANS      6  /* FORE SPANS */
#define TRAF_IPSILON    7  /* Ipsilon */
#define TRAF_UMTS_FP    8  /* UMTS Frame Protocol */
#define TRAF_GPRS_NS    9  /* GPRS Network Services */
#define TRAF_SSCOP     10  /* SSCOP */

/*
 * Traffic subtypes.
 */
#define TRAF_ST_UNKNOWN     0   /* Unknown */

/*
 * For TRAF_VCMX:
 */
#define TRAF_ST_VCMX_802_3_FCS   1  /* 802.3 with an FCS */
#define TRAF_ST_VCMX_802_4_FCS   2  /* 802.4 with an FCS */
#define TRAF_ST_VCMX_802_5_FCS   3  /* 802.5 with an FCS */
#define TRAF_ST_VCMX_FDDI_FCS    4  /* FDDI with an FCS */
#define TRAF_ST_VCMX_802_6_FCS   5  /* 802.6 with an FCS */
#define TRAF_ST_VCMX_802_3       7  /* 802.3 without an FCS */
#define TRAF_ST_VCMX_802_4       8  /* 802.4 without an FCS */
#define TRAF_ST_VCMX_802_5       9  /* 802.5 without an FCS */
#define TRAF_ST_VCMX_FDDI       10  /* FDDI without an FCS */
#define TRAF_ST_VCMX_802_6      11  /* 802.6 without an FCS */
#define TRAF_ST_VCMX_FRAGMENTS  12  /* Fragments */
#define TRAF_ST_VCMX_BPDU       13  /* BPDU */

/*
 * For TRAF_LANE:
 */
#define TRAF_ST_LANE_LE_CTRL     1  /* LANE: LE Ctrl */
#define TRAF_ST_LANE_802_3       2  /* LANE: 802.3 */
#define TRAF_ST_LANE_802_5       3  /* LANE: 802.5 */
#define TRAF_ST_LANE_802_3_MC    4  /* LANE: 802.3 multicast */
#define TRAF_ST_LANE_802_5_MC    5  /* LANE: 802.5 multicast */

/*
 * For TRAF_IPSILON:
 */
#define TRAF_ST_IPSILON_FT0      1  /* Ipsilon: Flow Type 0 */
#define TRAF_ST_IPSILON_FT1      2  /* Ipsilon: Flow Type 1 */
#define TRAF_ST_IPSILON_FT2      3  /* Ipsilon: Flow Type 2 */

struct atm_phdr {
    guint32 flags;      /* status flags */
    guint8  aal;        /* AAL of the traffic */
    guint8  type;       /* traffic type */
    guint8  subtype;    /* traffic subtype */
    guint16 vpi;        /* virtual path identifier */
    guint16 vci;        /* virtual circuit identifier */
    guint8  aal2_cid;   /* channel id */
    guint16 channel;    /* link: 0 for DTE->DCE, 1 for DCE->DTE */
    guint16 cells;      /* number of cells */
    guint16 aal5t_u2u;  /* user-to-user indicator */
    guint16 aal5t_len;  /* length of the packet */
    guint32 aal5t_chksum;   /* checksum for AAL5 packet */
};

/* Packet "pseudo-header" for Nokia output */
struct nokia_phdr {
    struct eth_phdr eth;
    guint8 stuff[4];    /* mysterious stuff */
};

/* Packet "pseudo-header" for the output from "wandsession", "wannext",
   "wandisplay", and similar commands on Lucent/Ascend access equipment. */

#define ASCEND_MAX_STR_LEN 64

#define ASCEND_PFX_WDS_X    1
#define ASCEND_PFX_WDS_R    2
#define ASCEND_PFX_WDD      3
#define ASCEND_PFX_ISDN_X   4
#define ASCEND_PFX_ISDN_R   5
#define ASCEND_PFX_ETHER    6

struct ascend_phdr {
    guint16 type;                         /* ASCEND_PFX_*, as defined above */
    char    user[ASCEND_MAX_STR_LEN];     /* Username, from wandsession header */
    guint32 sess;                         /* Session number, from wandsession header */
    char    call_num[ASCEND_MAX_STR_LEN]; /* Called number, from WDD header */
    guint32 chunk;                        /* Chunk number, from WDD header */
    guint32 task;                         /* Task number */
};

/* Also defined in epan/packet_info.h */
#define P2P_DIR_UNKNOWN -1
#define P2P_DIR_SENT     0
#define P2P_DIR_RECV     1

/* Packet "pseudo-header" for point-to-point links with direction flags. */
struct p2p_phdr {
    int sent; /* TRUE=sent, FALSE=received, -1=unknown*/
};

/*
 * Packet "pseudo-header" information for 802.11.
 * Radio information is only present for WTAP_ENCAP_IEEE_802_11_WITH_RADIO.
 *
 * Signal strength, etc. information:
 *
 * Raw signal strength can be measured in milliwatts.
 * It can also be represented as dBm, which is 10 times the log base 10
 * of the signal strength in mW.
 *
 * The Receive Signal Strength Indicator is an integer in the range 0 to 255.
 * The actual RSSI value for a given signal strength is dependent on the
 * vendor (and perhaps on the adapter).  The maximum possible RSSI value
 * is also dependent on the vendor and perhaps the adapter.
 *
 * The signal strength can be represented as a percentage, which is 100
 * times the ratio of the RSSI and the maximum RSSI.
 */
struct ieee_802_11_phdr {
    gint     fcs_len;       /* Number of bytes of FCS - -1 means "unknown" */
    gboolean decrypted;     /* TRUE if frame is decrypted even if "protected" bit is set */
    guint8   channel;       /* Channel number */
    guint16  data_rate;     /* in .5 Mb/s units */
    guint8   signal_level;  /* percentage */
};

/* Packet "pseudo-header" for the output from CoSine L2 debug output. */

#define COSINE_MAX_IF_NAME_LEN  128

#define COSINE_ENCAP_TEST      1
#define COSINE_ENCAP_PPoATM    2
#define COSINE_ENCAP_PPoFR     3
#define COSINE_ENCAP_ATM       4
#define COSINE_ENCAP_FR        5
#define COSINE_ENCAP_HDLC      6
#define COSINE_ENCAP_PPP       7
#define COSINE_ENCAP_ETH       8
#define COSINE_ENCAP_UNKNOWN  99

#define COSINE_DIR_TX 1
#define COSINE_DIR_RX 2

struct cosine_phdr {
    guint8  encap;      /* COSINE_ENCAP_* as defined above */
    guint8  direction;  /* COSINE_DIR_*, as defined above */
    char    if_name[COSINE_MAX_IF_NAME_LEN];  /* Encap & Logical I/F name */
    guint16 pro;        /* Protocol */
    guint16 off;        /* Offset */
    guint16 pri;        /* Priority */
    guint16 rm;         /* Rate Marking */
    guint16 err;        /* Error Code */
};

/* Packet "pseudo-header" for IrDA capture files. */

/*
 * Direction of the packet
 */
#define IRDA_INCOMING       0x0000
#define IRDA_OUTGOING       0x0004

/*
 * "Inline" log messages produced by IrCOMM2k on Windows
 */
#define IRDA_LOG_MESSAGE    0x0100  /* log message */
#define IRDA_MISSED_MSG     0x0101  /* missed log entry or frame */

/*
 * Differentiate between frames and log messages
 */
#define IRDA_CLASS_FRAME    0x0000
#define IRDA_CLASS_LOG      0x0100
#define IRDA_CLASS_MASK     0xFF00

struct irda_phdr {
    guint16 pkttype;    /* packet type */
};

/* Packet "pseudo-header" for nettl (HP-UX) capture files. */

struct nettl_phdr {
    guint16 subsys;
    guint32 devid;
    guint32 kind;
    gint32  pid;
    guint16 uid;
};

/* Packet "pseudo-header" for MTP2 files. */

#define MTP2_ANNEX_A_NOT_USED      0
#define MTP2_ANNEX_A_USED          1
#define MTP2_ANNEX_A_USED_UNKNOWN  2

struct mtp2_phdr {
    guint8  sent;
    guint8  annex_a_used;
    guint16 link_number;
};

/* Packet "pseudo-header" for K12 files. */

typedef union {
    struct {
        guint16 vp;
        guint16 vc;
        guint16 cid;
    } atm;

    guint32 ds0mask;
} k12_input_info_t;

struct k12_phdr {
    guint32           input;
    const gchar      *input_name;
    const gchar      *stack_file;
    guint32           input_type;
    k12_input_info_t  input_info;
    guint8           *extra_info;
    guint32           extra_length;
    void*             stuff;
};

#define K12_PORT_DS0S      0x00010008
#define K12_PORT_DS1       0x00100008
#define K12_PORT_ATMPVC    0x01020000

struct lapd_phdr {
    guint16 pkttype;    /* packet type */
    guint8 we_network;
};

struct wtap;
struct catapult_dct2000_phdr
{
    union
    {
        struct isdn_phdr isdn;
        struct atm_phdr  atm;
        struct p2p_phdr  p2p;
    } inner_pseudo_header;
    gint64       seek_off;
    struct wtap *wth;
};

#define LIBPCAP_BT_PHDR_SENT    0
#define LIBPCAP_BT_PHDR_RECV    1

/*
 * Header prepended by libpcap to each bluetooth hci h4 frame.
 * Values in network byte order
 */
struct libpcap_bt_phdr {
    guint32 direction;     /* Bit 0 hold the frame direction. */
};

/*
 * Header prepended by libpcap to each bluetooth monitor frame
 * Values in network byte order
 */
struct libpcap_bt_monitor_phdr {
    guint16 adapter_id;
    guint16 opcode;
};

#define LIBPCAP_PPP_PHDR_RECV    0
#define LIBPCAP_PPP_PHDR_SENT    1

/*
 * Header prepended by libpcap to each ppp frame.
 */
struct libpcap_ppp_phdr {
    guint8 direction;
};

/*
 * Endace Record Format pseudo header
 */
struct erf_phdr {
    guint64 ts;     /* Time stamp */
    guint8  type;
    guint8  flags;
    guint16 rlen;
    guint16 lctr;
    guint16 wlen;
};

struct erf_ehdr {
  guint64 ehdr;
};

/*
 * ERF pseudo header with optional subheader
 * (Multichannel or Ethernet)
 */

#define MAX_ERF_EHDR 8

struct erf_mc_phdr {
    struct erf_phdr phdr;
    struct erf_ehdr ehdr_list[MAX_ERF_EHDR];
    union
    {
        guint16 eth_hdr;
        guint32 mc_hdr;
    } subhdr;
};

#define LLCP_PHDR_FLAG_SENT 0
struct llcp_phdr {
    guint8 adapter;
    guint8 flags;
};

#define SITA_FRAME_DIR_TXED            (0x00)  /* values of sita_phdr.flags */
#define SITA_FRAME_DIR_RXED            (0x01)
#define SITA_FRAME_DIR                 (0x01)  /* mask */
#define SITA_ERROR_NO_BUFFER           (0x80)

#define SITA_SIG_DSR                   (0x01)  /* values of sita_phdr.signals */
#define SITA_SIG_DTR                   (0x02)
#define SITA_SIG_CTS                   (0x04)
#define SITA_SIG_RTS                   (0x08)
#define SITA_SIG_DCD                   (0x10)
#define SITA_SIG_UNDEF1                (0x20)
#define SITA_SIG_UNDEF2                (0x40)
#define SITA_SIG_UNDEF3                (0x80)

#define SITA_ERROR_TX_UNDERRUN         (0x01)  /* values of sita_phdr.errors2 (if SITA_FRAME_DIR_TXED) */
#define SITA_ERROR_TX_CTS_LOST         (0x02)
#define SITA_ERROR_TX_UART_ERROR       (0x04)
#define SITA_ERROR_TX_RETX_LIMIT       (0x08)
#define SITA_ERROR_TX_UNDEF1           (0x10)
#define SITA_ERROR_TX_UNDEF2           (0x20)
#define SITA_ERROR_TX_UNDEF3           (0x40)
#define SITA_ERROR_TX_UNDEF4           (0x80)

#define SITA_ERROR_RX_FRAMING          (0x01)  /* values of sita_phdr.errors1 (if SITA_FRAME_DIR_RXED) */
#define SITA_ERROR_RX_PARITY           (0x02)
#define SITA_ERROR_RX_COLLISION        (0x04)
#define SITA_ERROR_RX_FRAME_LONG       (0x08)
#define SITA_ERROR_RX_FRAME_SHORT      (0x10)
#define SITA_ERROR_RX_UNDEF1           (0x20)
#define SITA_ERROR_RX_UNDEF2           (0x40)
#define SITA_ERROR_RX_UNDEF3           (0x80)

#define SITA_ERROR_RX_NONOCTET_ALIGNED (0x01)  /* values of sita_phdr.errors2 (if SITA_FRAME_DIR_RXED) */
#define SITA_ERROR_RX_ABORT            (0x02)
#define SITA_ERROR_RX_CD_LOST          (0x04)
#define SITA_ERROR_RX_DPLL             (0x08)
#define SITA_ERROR_RX_OVERRUN          (0x10)
#define SITA_ERROR_RX_FRAME_LEN_VIOL   (0x20)
#define SITA_ERROR_RX_CRC              (0x40)
#define SITA_ERROR_RX_BREAK            (0x80)

#define SITA_PROTO_UNUSED              (0x00)  /* values of sita_phdr.proto */
#define SITA_PROTO_BOP_LAPB            (0x01)
#define SITA_PROTO_ETHERNET            (0x02)
#define SITA_PROTO_ASYNC_INTIO         (0x03)
#define SITA_PROTO_ASYNC_BLKIO         (0x04)
#define SITA_PROTO_ALC                 (0x05)
#define SITA_PROTO_UTS                 (0x06)
#define SITA_PROTO_PPP_HDLC            (0x07)
#define SITA_PROTO_SDLC                (0x08)
#define SITA_PROTO_TOKENRING           (0x09)
#define SITA_PROTO_I2C                 (0x10)
#define SITA_PROTO_DPM_LINK            (0x11)
#define SITA_PROTO_BOP_FRL             (0x12)

struct sita_phdr {
    guint8  sita_flags;
    guint8  sita_signals;
    guint8  sita_errors1;
    guint8  sita_errors2;
    guint8  sita_proto;
};

/*pseudo header for Bluetooth HCI*/
struct bthci_phdr {
    gboolean  sent;
    guint32   channel;
};

#define BTHCI_CHANNEL_COMMAND  1
#define BTHCI_CHANNEL_ACL      2
#define BTHCI_CHANNEL_SCO      3
#define BTHCI_CHANNEL_EVENT    4

/* pseudo header for WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR */
struct btmon_phdr {
    guint16   adapter_id;
    guint16   opcode;
};

/* pseudo header for WTAP_ENCAP_LAYER1_EVENT */
struct l1event_phdr {
    gboolean uton;
};

/* * I2C pseudo header */
struct i2c_phdr {
    guint8  is_event;
    guint8  bus;
    guint32 flags;
};

/* pseudo header for WTAP_ENCAP_GSM_UM */
struct gsm_um_phdr {
    gboolean uplink;
    guint8   channel;
    /* The following are only populated for downlink */
    guint8   bsic;
    guint16  arfcn;
    guint32  tdma_frame;
    guint8   error;
    guint16  timeshift;
};

#define GSM_UM_CHANNEL_UNKNOWN  0
#define GSM_UM_CHANNEL_BCCH     1
#define GSM_UM_CHANNEL_SDCCH    2
#define GSM_UM_CHANNEL_SACCH    3
#define GSM_UM_CHANNEL_FACCH    4
#define GSM_UM_CHANNEL_CCCH     5
#define GSM_UM_CHANNEL_RACH     6
#define GSM_UM_CHANNEL_AGCH     7
#define GSM_UM_CHANNEL_PCH      8

/*
 * "Pseudo-headers" are used to supply to the clients of wiretap
 * per-packet information that's not part of the packet payload
 * proper.
 *
 * NOTE: do not use pseudo-header structures to hold information
 * used by the code to read a particular capture file type; to
 * keep that sort of state information, add a new structure for
 * that private information to "wtap-int.h", add a pointer to that
 * type of structure to the "capture" member of the "struct wtap"
 * structure, and allocate one of those structures and set that member
 * in the "open" routine for that capture file type if the open
 * succeeds.  See various other capture file type handlers for examples
 * of that.
 */


struct nstr_phdr {
    gint64 rec_offset;
    gint32 rec_len;
    guint8 nicno_offset;
    guint8 nicno_len;
    guint8 dir_offset;
    guint8 dir_len;
    guint8 eth_offset;
    guint8 pcb_offset;
    guint8 l_pcb_offset;
    guint8 rec_type;
    guint8 vlantag_offset;
    guint8 coreid_offset;
    guint8 srcnodeid_offset;
    guint8 destnodeid_offset;
    guint8 clflags_offset;
    guint8 src_vmname_len_offset;
    guint8 dst_vmname_len_offset;
    guint8 ns_activity_offset;
    guint8 data_offset;
};

/* pseudo header for WTAP_ENCAP_LOGCAT */
struct logcat_phdr {
    gint version;
};

/* Pseudo-header for file-type-specific records */
struct ft_specific_record_phdr {
    guint record_type;    /* the type of record this is */
};

union wtap_pseudo_header {
    struct eth_phdr     eth;
    struct x25_phdr     x25;
    struct isdn_phdr    isdn;
    struct atm_phdr     atm;
    struct ascend_phdr  ascend;
    struct p2p_phdr     p2p;
    struct ieee_802_11_phdr ieee_802_11;
    struct cosine_phdr  cosine;
    struct irda_phdr    irda;
    struct nettl_phdr   nettl;
    struct mtp2_phdr    mtp2;
    struct k12_phdr     k12;
    struct lapd_phdr    lapd;
    struct catapult_dct2000_phdr dct2000;
    struct erf_mc_phdr  erf;
    struct sita_phdr    sita;
    struct bthci_phdr   bthci;
    struct btmon_phdr   btmon;
    struct l1event_phdr l1event;
    struct i2c_phdr     i2c;
    struct gsm_um_phdr  gsm_um;
    struct nstr_phdr    nstr;
    struct nokia_phdr   nokia;
    struct llcp_phdr    llcp;
    struct logcat_phdr  logcat;
    struct ft_specific_record_phdr ftsrec;
};

struct wtap_pkthdr {
    guint               rec_type;       /* what type of record is this? */
    guint32             presence_flags; /* what stuff do we have? */
    nstime_t            ts;
    guint32             caplen;         /* data length in the file */
    guint32             len;            /* data length on the wire */
    int                 pkt_encap;
                                        /* pcapng variables */
    guint32             interface_id;   /* identifier of the interface. */
                                        /* options */
    const gchar              *opt_comment;    /* NULL if not available */
    guint64             drop_count;     /* number of packets lost (by the interface and the
                                           operating system) between this packet and the preceding one. */
    guint32             pack_flags;     /* XXX - 0 for now (any value for "we don't have it"?) */

    union wtap_pseudo_header  pseudo_header;
};

/**
 * Holds the option strings from pcapng:s Section Header block(SHB).
 */
typedef struct wtapng_section_s {
    /* mandatory */
    guint64             section_length; /**< 64-bit value specifying the length in bytes of the
                                         *     following section.
                                         *     Section Length equal -1 (0xFFFFFFFFFFFFFFFF) means
                                         *     that the size of the section is not specified
                                         */
    /* options */
    const gchar         *opt_comment;   /**< NULL if not available */
    gchar               *shb_hardware;  /**< NULL if not available
                                         *     UTF-8 string containing the description of the
                                         *     hardware used to create this section.
                                         */
    const gchar         *shb_os;        /**< NULL if not available, UTF-8 string containing the
                                         *     name of the operating system used to create this section.
                                         */
    const gchar         *shb_user_appl; /**< NULL if not available, UTF-8 string containing the
                                         *     name of the application used to create this section.
                                         */
} wtapng_section_t;





/** struct holding the information to build IDB:s
 *  the interface_data array holds an array of wtapng_if_descr_t
 *  one per interface.
 */
typedef struct wtapng_iface_descriptions_s {
    GArray *interface_data;
} wtapng_iface_descriptions_t;


/** A struct with lists of resolved addresses.
 *  Used when writing name resoultion blocks (NRB)
 */
typedef struct addrinfo_lists {
    GList      *ipv4_addr_list; /**< A list of resolved hashipv4_t*/
    GList      *ipv6_addr_list; /**< A list of resolved hashipv6_t*/
} addrinfo_lists_t;

struct wtap_dumper {
    FILE	                *fh;
    struct wtapng_section_s *shb_hdr;
    GArray                  *interface_data;        /**< An array holding the interface data from pcapng IDB:s or equivalent(?) NULL if not present.*/
    guint64                  bytes_dumped;
    addrinfo_lists_t        *addrinfo_lists;        /**< Struct containing lists of resolved addresses */
};
typedef struct wtap_dumper wtap_dumper;
/**
 * Interface description data
 */
typedef struct wtapng_if_descr_s {
    int                    wtap_encap;            /**< link_type translated to wtap_encap */
    guint64                time_units_per_second;

    /* mandatory */
    guint16                link_type;
    guint32                snap_len;

    /* options */
    const gchar                 *opt_comment;           /**< NULL if not available */
    gchar                 *if_name;               /**< NULL if not available
                                                   *  opt 2
                                                   *     A UTF-8 string containing the name of the
                                                   *     device used to capture data.
                                                   */
    gchar                 *if_description;        /**< NULL if not available
                                                   *  opt 3
                                                   *     A UTF-8 string containing the description
                                                   *     of the device used to capture data.
                                                   */

    /* XXX: if_IPv4addr opt 4  Interface network address and netmask.                                */
    /* XXX: if_IPv6addr opt 5  Interface network address and prefix length (stored in the last byte).*/
    /* XXX: if_MACaddr  opt 6  Interface Hardware MAC address (48 bits).                             */
    /* XXX: if_EUIaddr  opt 7  Interface Hardware EUI address (64 bits)                              */

    guint64                if_speed;              /**< 0xFFFFFFFF if unknown
                                                   *  opt 8
                                                   *     Interface speed (in bps). 100000000 for 100Mbps
                                                   */
    guint8                 if_tsresol;            /**< default is 6 for microsecond resolution
                                                   *  opt 9
                                                   *     Resolution of timestamps.
                                                   *     If the Most Significant Bit is equal to zero,
                                                   *     the remaining bits indicates the resolution of the
                                                   *     timestamp as as a negative power of 10
                                                   */

    /* XXX: if_tzone      10  Time zone for GMT support (TODO: specify better). */

    gchar                 *if_filter_str;         /**< NULL if not available
                                                   *  opt 11  libpcap string.
                                                   */
    guint16                bpf_filter_len;        /** Opt 11 variant II BPF filter len 0 if not used*/
    gchar                 *if_filter_bpf_bytes;   /** Opt 11 BPF filter or NULL */
    gchar                 *if_os;                 /**< NULL if not available
                                                   *     12  A UTF-8 string containing the name of the
                                                   *     operating system of the machine in which this
                                                   *     interface is installed.
                                                   */
    gint8                  if_fcslen;             /**< -1 if unknown or changes between packets,
                                                   *  opt 13
                                                   *     An integer value that specified the length of
                                                   *     the Frame Check Sequence (in bits) for this interface. */
    /* XXX: guint64    if_tsoffset; opt 14  A 64 bits integer value that specifies an offset (in seconds)...*/
    guint8                 num_stat_entries;
    GArray                *interface_statistics;  /**< An array holding the interface statistics from
                                                   *     pcapng ISB:s or equivalent(?)*/
} wtapng_if_descr_t;

/* pcapng: common block header for every block type */
typedef struct pcapng_block_header_s {
        guint32 block_type;
        guint32 block_total_length;
        /* x bytes block_body */
        /* guint32 block_total_length */
} pcapng_block_header_t;

/* pcapng: section header block */
typedef struct pcapng_section_header_block_s {
    /* pcapng_block_header_t */
    guint32 magic;
    guint16 version_major;
    guint16 version_minor;
    guint64 section_length; /* might be -1 for unknown */
    /* ... Options ... */
} pcapng_section_header_block_t;

/* pcapng: interface description block */
typedef struct pcapng_interface_description_block_s {
        guint16 linktype;
        guint16 reserved;
        guint32 snaplen;
        /* ... Options ... */
} pcapng_interface_description_block_t;

/*
 * Minimum ISB size = minimum block size + size of fixed length portion of ISB.
 */
#define MIN_ISB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_interface_statistics_block_t)))

/* pcapng: common option header for every option type */
typedef struct pcapng_option_header_s {
        guint16 option_code;
        guint16 option_length;
        /* ... x bytes Option Body ... */
        /* ... Padding ... */
} pcapng_option_header_t;

struct option {
        guint16 type;
        guint16 value_length;
};

/*
 * Minimum PB size = minimum block size + size of fixed length portion of PB.
 */
#define MIN_PB_SIZE     ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_packet_block_t)))

/* pcapng: enhanced packet block */
typedef struct pcapng_enhanced_packet_block_s {
        guint32 interface_id;
        guint32 timestamp_high;
        guint32 timestamp_low;
        guint32 captured_len;
        guint32 packet_len;
        /* ... Packet Data ... */
        /* ... Padding ... */
        /* ... Options ... */
} pcapng_enhanced_packet_block_t;

/*
 * Maximum packet size we'll support.
 * 262144 is the largest snapshot length that libpcap supports, so we
 * use that.
 */
#define WTAP_MAX_PACKET_SIZE    262144


/*
 * Bits in presence_flags, indicating which of the fields we have.
 *
 * For the time stamp, we may need some more flags to indicate
 * whether the time stamp is an absolute date-and-time stamp, an
 * absolute time-only stamp (which can make relative time
 * calculations tricky, as you could in theory have two time
 * stamps separated by an unknown number of days), or a time stamp
 * relative to some unspecified time in the past (see mpeg.c).
 *
 * There is no presence flag for len - there has to be *some* length
 * value for the packet.  (The "captured length" can be missing if
 * the file format doesn't report a captured length distinct from
 * the on-the-network length because the application(s) producing those
 * files don't support slicing packets.)
 *
 * There could be a presence flag for the packet encapsulation - if it's
 * absent, use the file encapsulation - but it's not clear that's useful;
 * we currently do that in the module for the file format.
 */
#define WTAP_HAS_TS            0x00000001  /**< time stamp */
#define WTAP_HAS_CAP_LEN       0x00000002  /**< captured length separate from on-the-network length */
#define WTAP_HAS_INTERFACE_ID  0x00000004  /**< interface ID */
#define WTAP_HAS_COMMENTS      0x00000008  /**< comments */
#define WTAP_HAS_DROP_COUNT    0x00000010  /**< drop count */
#define WTAP_HAS_PACK_FLAGS    0x00000020  /**< packet flags */

/* Pointer routines to put items out in a particular byte order.
 * These will work regardless of the byte alignment of the pointer.
 */

#ifndef phtons
#define phtons(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 8);    \
        (p)[1] = (guint8)((v) >> 0);    \
    }
#endif

#ifndef phton24
#define phton24(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 16);    \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 0);     \
    }
#endif

#ifndef phtonl
#define phtonl(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 24);    \
        (p)[1] = (guint8)((v) >> 16);    \
        (p)[2] = (guint8)((v) >> 8);     \
        (p)[3] = (guint8)((v) >> 0);     \
    }
#endif

#ifndef phtonll
#define phtonll(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 56);    \
        (p)[1] = (guint8)((v) >> 48);    \
        (p)[2] = (guint8)((v) >> 40);    \
        (p)[3] = (guint8)((v) >> 32);    \
        (p)[4] = (guint8)((v) >> 24);    \
        (p)[5] = (guint8)((v) >> 16);    \
        (p)[6] = (guint8)((v) >> 8);     \
        (p)[7] = (guint8)((v) >> 0);     \
    }
#endif

#ifndef phtoles
#define phtoles(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);    \
        (p)[1] = (guint8)((v) >> 8);    \
    }
#endif

#ifndef phtolel
#define phtolel(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);     \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 16);    \
        (p)[3] = (guint8)((v) >> 24);    \
    }
#endif

#ifndef phtolell
#define phtolell(p, v) \
    {                 \
        (p)[0] = (guint8)((v) >> 0);     \
        (p)[1] = (guint8)((v) >> 8);     \
        (p)[2] = (guint8)((v) >> 16);    \
        (p)[3] = (guint8)((v) >> 24);    \
        (p)[4] = (guint8)((v) >> 32);    \
        (p)[5] = (guint8)((v) >> 40);    \
        (p)[6] = (guint8)((v) >> 48);    \
        (p)[7] = (guint8)((v) >> 56);    \
    }
#endif

/**
 * Struct holding data of the currently read file.
 */
struct wtap {
    //FILE_T                      fh;
    //FILE_T                      random_fh;              /**< Secondary FILE_T for random access */
    int                         file_type_subtype;
    guint                       snapshot_length;
    struct Buffer               *frame_buffer;
    struct wtap_pkthdr          phdr;
    struct wtapng_section_s     shb_hdr;
    guint                       number_of_interfaces;   /**< The number of interfaces a capture was made on, number of IDB:s in a pcapng file or equivalent(?)*/
    GArray                      *interface_data;        /**< An array holding the interface data from pcapng IDB:s or equivalent(?)*/

    void                        *priv;          /* this one holds per-file state and is free'd automatically by wtap_close() */
    void                        *wslua_data;    /* this one holds wslua state info and is not free'd */

    //subtype_read_func           subtype_read;
    //subtype_seek_read_func      subtype_seek_read;
    void                        (*subtype_sequential_close)(struct wtap*);
    void                        (*subtype_close)(struct wtap*);
    int                         file_encap;    /* per-file, for those
                                                * file formats that have
                                                * per-file encapsulation
                                                * types
                                                */
    int                         tsprecision;   /* timestamp precision of the lower 32bits
                                                * e.g. WTAP_FILE_TSPREC_USEC
                                                */
    //wtap_new_ipv4_callback_t    add_new_ipv4;
    //wtap_new_ipv6_callback_t    add_new_ipv6;
    GPtrArray                   *fast_seek;
};

 typedef struct wtap wtap;

 /**
  * Interface Statistics. pcap-ng Interface Statistics Block (ISB).
  */
 typedef struct wtapng_if_stats_s {
     /* mandatory */
     guint32  interface_id;
     guint32  ts_high;
     guint32  ts_low;
     /* options */
     gchar   *opt_comment;       /**< NULL if not available */
     guint64  isb_starttime;
     guint64  isb_endtime;
     guint64  isb_ifrecv;
     guint64  isb_ifdrop;
     guint64  isb_filteraccept;
     guint64  isb_osdrop;
     guint64  isb_usrdeliv;
 } wtapng_if_stats_t;

 /* pcapng: interface statistics block */
 typedef struct pcapng_interface_statistics_block_s {
         guint32 interface_id;
         guint32 timestamp_high;
         guint32 timestamp_low;
         /* ... Options ... */
 } pcapng_interface_statistics_block_t;

 /* pcapng: name resolution block */
 typedef struct pcapng_name_resolution_block_s {
         guint16 record_type;
         guint16 record_len;
         /* ... Record ... */
 } pcapng_name_resolution_block_t;

#define MAX_IP6_STR_LEN 40

#ifndef MAXNAMELEN
#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#endif

#define NRES_ENDOFRECORD 0
#define NRES_IP4RECORD 1
#define NRES_IP6RECORD 2
#define PADDING4(x) ((((x + 3) >> 2) << 2) - x)
/* IPv6 + MAXNAMELEN */
#define INITIAL_NRB_REC_SIZE (16 + 64)

 typedef struct hashipv4 {
     guint             addr;
     guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
     gchar             ip[16];
     gchar             name[MAXNAMELEN];
 } hashipv4_t;

 struct e_in6_addr {
 	guint8   bytes[16];		/**< 128 bit IP6 address */
 };


 typedef struct hashipv6 {
     struct e_in6_addr addr;
     guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
     gchar             ip6[MAX_IP6_STR_LEN]; /* XX */
     gchar             name[MAXNAMELEN];
 } hashipv6_t;

 /* Magic numbers in "libpcap" files.

    "libpcap" file records are written in the byte order of the host that
    writes them, and the reader is expected to fix this up.

    PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
    is a byte-swapped version of that.

    PCAP_MODIFIED_MAGIC is for Alexey Kuznetsov's modified "libpcap"
    format, as generated on Linux systems that have a "libpcap" with
    his patches, at

 	http://ftp.sunet.se/pub/os/Linux/ip-routing/lbl-tools/

    applied; PCAP_SWAPPED_MODIFIED_MAGIC is the byte-swapped version.

    PCAP_NSEC_MAGIC is for Ulf Lamping's modified "libpcap" format,
    which uses the same common file format as PCAP_MAGIC, but the
    timestamps are saved in nanosecond resolution instead of microseconds.
    PCAP_SWAPPED_NSEC_MAGIC is a byte-swapped version of that. */
 #define	PCAP_MAGIC			0xa1b2c3d4
 #define	PCAP_SWAPPED_MAGIC		0xd4c3b2a1
 #define	PCAP_MODIFIED_MAGIC		0xa1b2cd34
 #define	PCAP_SWAPPED_MODIFIED_MAGIC	0x34cdb2a1
 #define	PCAP_NSEC_MAGIC			0xa1b23c4d
 #define	PCAP_SWAPPED_NSEC_MAGIC		0x4d3cb2a1

 /* "libpcap" file header (minus magic number). */
 struct pcap_hdr {
	guint32 magic;
 	guint16	version_major;	/* major version number */
 	guint16	version_minor;	/* minor version number */
 	gint32	thiszone;	/* GMT to local correction */
 	guint32	sigfigs;	/* accuracy of timestamps */
 	guint32	snaplen;	/* max length of captured packets, in octets */
 	guint32	network;	/* data link type */
 };

 int get_encapsulation_type(const void *source);

 wtap_dumper* wtap_dump_open_ng(const char *filename, wtapng_section_t *shb_hdr,
 		wtapng_iface_descriptions_t *idb_inf, int *err);

 gboolean wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
 		   const guint8 *pd, int *err,int flush_flag);

 gboolean wtap_dump_close(wtap_dumper *wdh, int *err);


#endif /*#ifdef HAVE_LIBPCAPNG*/

#endif /* PCAPNG_H_ */
