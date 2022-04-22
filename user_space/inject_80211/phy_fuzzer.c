// Modified by: Michael Mehari
// SPDX-FileCopyrightText: 2020 UGent
// SPDX-FileCopyrightText: 2007 Andy Green <andy@warmcat.com>
// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

// Thanks for contributions:
// 2007-03-15 fixes to getopt_long code by Matteo Croce rootkit85@yahoo.it

// Modified by: Thomas Schuddinck
// Year: 2021-2022

#include "phy_fuzzer.h"
#include "radiotap.h"
#include <stdbool.h>
#include "signal_field_utilities.h"

#define BUF_SIZE_MAX (1536)
#define BUF_SIZE_TOTAL (BUF_SIZE_MAX + 1) // +1 in case the sprintf insert the last 0

/* wifi bitrate to use in 500kHz units */
static const u8 u8aRatesToUse[] = {
	6 * 2,
	9 * 2,
	12 * 2,
	18 * 2,
	24 * 2,
	36 * 2,
	48 * 2,
	54 * 2};

/* this is the template radiotap header we send packets out with */
static const u8 u8aRadiotapHeader[] =
	{
		0x00, 0x00,										// <-- radiotap version
		0x1c, 0x00,										// <- radiotap header length
		0x6f, 0x08, 0x08, 0x00,							// <-- bitmap
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
		0x00,											// <-- flags (Offset +0x10)
		0x6c,											// <-- rate (0ffset +0x11)
		0x71, 0x09, 0xc0, 0x00,							// <-- channel
		0xde,											// <-- antsignal
		0x00,											// <-- antnoise
		0x01,											// <-- antenna
		0x02, 0x00, 0x0f,								// <-- MCS
};

#define OFFSET_RATE 0x11
#define MCS_OFFSET 0x19
#define GI_OFFSET 0x1a
#define MCS_RATE_OFFSET 0x1b

/* IEEE80211 header */
static u8 ieee_hdr_data[] =
	{
		0x08, 0x02, 0x00, 0x00,				// FC 0x0801. 0--subtype; 8--type&version; 02--toDS0 fromDS1 (data packet from DS to STA)
		0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // BSSID/MAC of AP
		0x66, 0x55, 0x44, 0x33, 0x22, 0x22, // Source address (STA)
		0x66, 0x55, 0x44, 0x33, 0x22, 0x33, // Destination address (another STA under the same AP)
		0x10, 0x86,							// 0--fragment number; 0x861=2145--sequence number
};

static u8 ieee_hdr_mgmt[] =
	{
		0x00, 0x00, 0x00, 0x00,				// FC 0x0000. 0--subtype; 0--type&version;
		0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // BSSID/MAC of AP
		0x66, 0x55, 0x44, 0x33, 0x22, 0x22, // Source address (STA)
		0x66, 0x55, 0x44, 0x33, 0x22, 0x33, // Destination address (another STA under the same AP)
		0x10, 0x86,							// 0--fragment number; 0x861=2145--sequence number
};

static u8 ieee_hdr_ack_cts[] =
	{
		0xd4, 0x00, 0x00, 0x00,				// FC 0xd400. d--subtype; 4--type&version;
		0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mac addr of the peer
};

static u8 ieee_hdr_rts[] =
	{
		0xb4, 0x00, 0x00, 0x00,				// FC 0xb400. b--subtype; 4--type&version;
		0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mac addr of the peer
		0x66, 0x55, 0x44, 0x33, 0x22, 0x22, // mac addr of the peer
};

// Generate random string
void gen_rand_str(int size, char *rand_char)
{
	int i, randNum = 0;

	// Seed the random number generator with packet size
	srand(size);
	for (i = 0; i < size; i++)
	{
		// First, pick a number between 0 and 25.
		randNum = 255 * (rand() / (RAND_MAX + 1.0));

		if (randNum == 0)
		{
			i--;
			continue;
		}

		// Type cast to character
		rand_char[i] = (char)randNum;
	}
	rand_char[i] = '\0';
}

int flagHelp = 0;

void usage(void)
{
	printf(
		"(c)2006-2007 Andy Green <andy@warmcat.com>  Licensed under GPL2\n"
		"(r)2020 Michael Tetemke Mehari <michael.mehari@ugent.be>\n"
		"(r)2022 Xianjun Jiao <xianjun.jiao@ugent.be>"
		"\n"
		"Usage: inject_80211 [options] <interface>\n\nOptions\n"
		"-m/--hw_mode <hardware operation mode> (a,g,n)\n"
		"-r/--rate_index <rate/MCS index> (0,1,2,3,4,5,6,7)\n"
		"-t/--packet_type (m/c/d/r for management/control/data/reserved)\n"
		"-e/--sub_type (hex value. example:\n"
		"     8/A/B/C for Beacon/Disassociation/Authentication/Deauth, when packet_type m\n"
		"     A/B/C/D for PS-Poll/RTS/CTS/ACK, when packet_type c\n"
		"     0/1/2/8 for Data/Data+CF-Ack/Data+CF-Poll/QoS-Data, when packet_type d)\n"
		"-a/--addr1 <the last byte of addr1 in hex>\n"
		"-b/--addr2 <the last byte of addr2 in hex>\n"
		"-i/--sgi_flag (0,1)\n"
		"-n/--num_packets <number of packets>\n"
		"-s/--payload_size <payload size in bytes>\n"
		"-d/--delay <delay between packets in usec>\n"
		"-c/--signal_field <hexadecimal representation of signal field for PHY fuzzing> (hex value. example:\n"
		"     0xff2345\n"
		"     WARNING: the signal field is 24 bits, or 3 bytes long, so the value can't be longer than that.\n"
		"     if the value contains less than six hexadecimal values, they will be supplemented with zeros at the front."
		"-g/-mac_fuzz_field <hexadecimal representation of first 4 bytes of MAC hdr> (hex value. example:\n"
		"     0xff012345\n"
		"     WARNING: the fuzzed hdr field is 32 bits, or 4 bytes long, so the value can't be longer than that.\n"
		"     if the value contains less than eight hexadecimal values, they will be supplemented with zeros at the front."
		"     The fields you fuzz are: FC, subtype, type, version, toDS and fromDS"
		"-f/--fuzzing_mode <fuzzing mode> (i[nremental],r[andom])>\n"
		"-q/--signal_field_mode <signal field mode> (l[egacy],g[reenfield/high throughput],h[ybrid])\n"
		"     [NOTE] hybrid mode is not yet supported\n"
		"-j/--jump_size <the value to increment the signal field after every single fuzz>\n"
		"-j/--jump_size_mac <the value to increment the fuzzed mac header field after every single fuzz>\n"
		"-o/--byte_order_is_reversed <in case the signal field uses reverse bit order>\n"
		"-p/--fix_parity_bit <correct invalid parity bit>\n"
		"-h   this menu\n\n"
		"Example:\n"
		"  iw dev wlan0 interface add mon0 type monitor && ifconfig mon0 up\n"
		"  inject_80211 mon0\n"
		"\n");
	exit(1);
}

int inject_packet(pcap_t *ppcap, u8 *buffer, int packet_size, int nDelay, int number_of_packets)
{
	int r;
	r = pcap_inject(ppcap, buffer, packet_size);
	if (r != packet_size)
	{
		perror("Trouble injecting packet");
		return (1);
	}

	printf("number of packets sent = %d\n\r", number_of_packets);
	fflush(stdout);

	if (nDelay)
		usleep(nDelay);

	return (0);
}

int main(int argc, char *argv[])
{
	u8 buffer[BUF_SIZE_TOTAL], addr1 = 1, addr2 = 2, sub_type = 1, *ieee_hdr;
	char szErrbuf[PCAP_ERRBUF_SIZE], rand_char[1484], hw_mode = 'n', packet_type = 'd', fuzzing_mode = 'i', signal_field_mode = 'l';
	int i, nLinkEncap = 0, rate_index = 0, sgi_flag = 0, num_packets = 10, payload_size = 64, packet_size, nDelay = 100000;
	int ieee_hdr_len, payload_len, result;
	pcap_t *ppcap = NULL;

	bool fuzz_phy = false, fuzz_mac = false, fix_parity_bit = false, is_signal_field_reversed = false, is_mac_header_reversed = false, is_legacy_signal_field = true;
	unsigned long long int signal_field, jump_size = 1, max_val_sig, mac_fuzz_field, jump_size_mac = 1;
	u8 signal_field_arr[6]; 

	while (1)
	{
		int nOptionIndex;
		static const struct option optiona[] =
			{
				{"addr1", 					required_argument, 	NULL, 'a'},
				{"addr2", 					required_argument, 	NULL, 'b'},
				{"signal_field", 			required_argument, 	NULL, 'c'},
				{"delay", 					required_argument, 	NULL, 'd'},
				{"sub_type", 				required_argument, 	NULL, 'e'},
				{"fuzzing_mode", 			required_argument, 	NULL, 'f'},
				{"mac_fuzz_field", 			required_argument, 	NULL, 'g'},
				{"sgi_flag", 				no_argument, 		NULL, 'i'},
				{"jump_size", 				required_argument, 	NULL, 'j'},
				{"jump_size_mac", 			required_argument, 	NULL, 'k'},
				{"hw_mode", 				required_argument, 	NULL, 'm'},
				{"num_packets", 			required_argument, 	NULL, 'n'},
				{"is_signal_field_reversed",no_argument, 		NULL, 'o'},
				{"fix_parity_bit", 			no_argument, 		NULL, 'p'},
				{"signal_field_mode", 		required_argument, 	NULL, 'q'},
				{"rate_index", 				required_argument, 	NULL, 'r'},
				{"payload_size", 			required_argument, 	NULL, 's'},
				{"packet_type", 			required_argument, 	NULL, 't'},
				{"is_mac_header_reversed",	no_argument, 		NULL, 'u'},
				{"help", 					no_argument, 		&flagHelp, 1},
				{0, 0, 0, 0}};
		int c = getopt_long(argc, argv, "m:r:t:e:a:b:i:n:s:d:c:f:g:q:j:k:hpou", optiona, &nOptionIndex);

		if (c == -1)
			break;
		switch (c)
		{
		case 0: // long option
			break;

		case 'h':
			usage();

		case 'm':
			hw_mode = optarg[0];
			break;

		case 'r':
			rate_index = atoi(optarg);
			break;

		case 't':
			packet_type = optarg[0];
			break;

		case 'e':
			sub_type = strtol(optarg, NULL, 16);
			break;

		case 'a':
			addr1 = strtol(optarg, NULL, 16);
			break;

		case 'b':
			addr2 = strtol(optarg, NULL, 16);
			break;

		case 'i':
			sgi_flag = atoi(optarg);
			break;

		case 'n':
			num_packets = atoi(optarg);
			break;

		case 's':
			payload_size = atoi(optarg);
			break;

		case 'd':
			nDelay = atoi(optarg);
			break;

		case 'p':
			fix_parity_bit = true;
			break;

		case 'o':
			is_signal_field_reversed = true;
			break;

		case 'u':
			is_mac_header_reversed = true;
			break;

		case 'j':
			jump_size = strtol(optarg, NULL, 0);
			break;

		case 'k':
			jump_size_mac = strtol(optarg, NULL, 0);
			break;

		case 'f':
			fuzzing_mode = optarg[0];
			break;

		case 'q':
			signal_field_mode = optarg[0];
			if (signal_field_mode != 'l' && signal_field_mode != 'g'){
				printf("INVALID SIGNAL FIELD MODE\n");
				usage();
			} 
				
			is_legacy_signal_field = signal_field_mode == 'l';
			break;

		case 'c':
			signal_field = strtol(optarg, NULL, 0);
			fuzz_phy = true;
			break;

		case 'g':
			mac_fuzz_field = strtol(optarg, NULL, 0);
			fuzz_mac = true;
			break;

		default:
			printf("unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	// if mac is fuzzed, check value is valid
	if(fuzz_mac && (mac_fuzz_field > 0xffffffff || jump_size_mac < 1 || jump_size_mac > 0xffffffff ) )
		usage();
	if (fuzz_mac && is_mac_header_reversed)
	{
		mac_fuzz_field = switch_bit_order(mac_fuzz_field, 4);
	}
	
	
	// in case the physical layer should be fuzzed
	if(fuzz_phy){
		// init the max value depending on which signal field is used (legacy or greenfield/HT)
		max_val_sig = (is_legacy_signal_field ? MAX_VALUE_LEGACY_SIGNAL_FIELD : MAX_VALUE_HT_SIGNAL_FIELD);

		if (jump_size < 1 || jump_size > max_val_sig){
			printf("INVALID JUMP VALUE\n");
			usage();
		} 
		if (signal_field > max_val_sig){ 
			printf("INVALID SIGNAL FIELD\n");
			usage();
		} 
	} 

	// open the interface in pcap
	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL)
	{
		printf("Unable to open interface %s in pcap: %s\n", argv[optind], szErrbuf);
		return (1);
	}

	nLinkEncap = pcap_datalink(ppcap);
	switch (nLinkEncap)
	{
	case DLT_PRISM_HEADER:
		printf("DLT_PRISM_HEADER Encap\n");
		break;

	case DLT_IEEE802_11_RADIO:
		printf("DLT_IEEE802_11_RADIO Encap\n");
		break;

	default:
		printf("!!! unknown encapsulation on %s !\n", argv[1]);
		return (1);
	}

	pcap_setnonblock(ppcap, 1, szErrbuf);

	// Fill the IEEE hdr
	if (packet_type == 'd') // data packet
	{
		ieee_hdr_data[0] = (ieee_hdr_data[0] | (sub_type << 4));
		ieee_hdr_data[9] = addr1;
		ieee_hdr_data[15] = addr2;
		ieee_hdr_len = sizeof(ieee_hdr_data);
		ieee_hdr = ieee_hdr_data;
	}
	else if (packet_type == 'm') // managment packet
	{
		ieee_hdr_mgmt[0] = (ieee_hdr_mgmt[0] | (sub_type << 4));
		ieee_hdr_mgmt[9] = addr1;
		ieee_hdr_mgmt[15] = addr2;
		ieee_hdr_len = sizeof(ieee_hdr_mgmt);
		ieee_hdr = ieee_hdr_mgmt;
	}
	else if (packet_type == 'c')
	{
		payload_size = 0;
		if (sub_type == 0xC || sub_type == 0xD)
		{
			ieee_hdr_ack_cts[0] = (ieee_hdr_ack_cts[0] | (sub_type << 4));
			ieee_hdr_ack_cts[9] = addr1;
			ieee_hdr_len = sizeof(ieee_hdr_ack_cts);
			ieee_hdr = ieee_hdr_ack_cts;
		}
		else if (sub_type == 0xA || sub_type == 0xB)
		{
			ieee_hdr_rts[0] = (ieee_hdr_rts[0] | (sub_type << 4));
			ieee_hdr_rts[9] = addr1;
			ieee_hdr_rts[15] = addr2;
			ieee_hdr_len = sizeof(ieee_hdr_rts);
			ieee_hdr = ieee_hdr_rts;
		}
		else
		{
			printf("!!! sub_type %x is not supported yet!\n", sub_type);
			return (1);
		}
	}
	else
	{
		printf("!!! packet_type %c is not supported yet!\n", packet_type);
		return (1);
	}

	// Generate random string
	gen_rand_str(payload_size + 4, rand_char); // 4 for space reserved for crc
	payload_len = strlen(rand_char);

	packet_size = sizeof(u8aRadiotapHeader) + ieee_hdr_len + payload_len;

	printf("\n\nmode = 802.11%c, rate index = %d, SHORT GI = %d, number of packets = %d and packet size = %d bytes, delay = %d usec\n", hw_mode, rate_index, sgi_flag, num_packets, packet_size, nDelay);
	printf("packet_type %c sub_type %x payload_len %d ieee_hdr_len %d addr1 %02x addr2 %02x\n", packet_type, sub_type, payload_len, ieee_hdr_len, addr1, addr2);

	if (packet_size > BUF_SIZE_MAX)
	{
		printf("packet_size %d > %d! Quite\n", packet_size, BUF_SIZE_MAX);
		return (1);
	}

	// Clear storage buffer
	memset(buffer, 0, sizeof(buffer));

	// Insert default radiotap header
	memcpy(buffer, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
	// Update radiotap header (i.e. hw_mode, rate, GI)
	if (hw_mode == 'g' || hw_mode == 'a')
	{
		buffer[OFFSET_RATE] = u8aRatesToUse[rate_index];
		buffer[MCS_OFFSET] = 0x00;
	}
	else
	{
		buffer[MCS_OFFSET] = 0x07;
		if (sgi_flag)
			buffer[GI_OFFSET] = IEEE80211_RADIOTAP_MCS_SGI;
		buffer[MCS_RATE_OFFSET] = rate_index;
	}

	printf("FUZZ PHY: %s\n", fuzz_phy ? "yes" : "no");

	// Insert IEEE DATA header
	memcpy(buffer + sizeof(u8aRadiotapHeader), ieee_hdr, ieee_hdr_len);
	// Insert IEEE DATA payload
	sprintf((char *)(buffer + sizeof(u8aRadiotapHeader) + ieee_hdr_len), "%s", rand_char);

	

	// Inject packets
	if (fuzz_phy)
	{
		if (fuzzing_mode == 'i')
		{

			if (is_signal_field_reversed)
			{
				signal_field = switch_bit_order(signal_field, is_legacy_signal_field ? 3 : 6);
			}
			for (i = 1; i <= num_packets; i++)
			{
				if (fuzz_mac)
				{
					inject_mac(buffer, mac_fuzz_field);
					mac_fuzz_field = mac_fuzz_field + jump_size_mac;
					if (mac_fuzz_field > 0xffffffff)
					{
						printf("mac header field reached the maximum value. Exiting..\n.");
						return (0);
					}				
				}
				if (fix_parity_bit){
					printf("fix parity\n");
					signal_field = correct_parity(signal_field, false, is_legacy_signal_field);
				} 
					

				to_u8_array(signal_field, signal_field_arr, false, is_legacy_signal_field ? 3 : 6);
				inject_signal_field(buffer, signal_field_arr, is_legacy_signal_field);
				result = inject_packet(ppcap, buffer, packet_size, nDelay, 1);

				if(result)
					return (1);

				if (signal_field > max_val_sig - jump_size)
				{
					printf("signal field reached the maximum value. Exiting..\n.");
					return (0);
				}
				signal_field = signal_field + jump_size;
				i++;
			}
		}
		else
		{
			srand(time(NULL));

			for (i = 0; i <= num_packets; i++)
			{
				if (fuzz_mac)
				{
					inject_mac(buffer, mac_fuzz_field);
					mac_fuzz_field = mac_fuzz_field + jump_size_mac;
					if (mac_fuzz_field > 0xffffffff)
					{
						printf("mac header field reached the maximum value. Exiting..\n.");
						return (0);
					}				
				}
				signal_field = (rand() % (max_val_sig + i));
				if (fix_parity_bit)
					signal_field = correct_parity(signal_field, false, is_legacy_signal_field);

				to_u8_array(signal_field, signal_field_arr, false, is_legacy_signal_field ? 3 : 6);
				inject_signal_field(buffer, signal_field_arr, is_legacy_signal_field);
				result = inject_packet(ppcap, buffer, packet_size, nDelay, i);

				if(result)
					return (1);
				i++;
			}
		}
	}
	else
	{
		for (i = 1; i <= num_packets; i++)
		{
			if (fuzz_mac)
			{
				inject_mac(buffer, mac_fuzz_field);
				mac_fuzz_field = mac_fuzz_field + jump_size_mac;
				if (mac_fuzz_field > 0xffffffff)
				{
					printf("mac header field reached the maximum value. Exiting..\n.");
					return (0);
				}				
			}
			
			result = inject_packet(ppcap, buffer, packet_size, nDelay, i);

			if(result)
					return (1);
		}
	}

	printf("\n");

	return (0);
}
