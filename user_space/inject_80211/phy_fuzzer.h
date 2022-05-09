/*
 * Author: Michael Mehari
 * SPDX-FileCopyrightText: 2019 UGent
 * SPDX-License-Identifier: AGPL-3.0-or-later
*/

#include <stdlib.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <errno.h>
#include <time.h>

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef u32 __le32;

#define MAX_PING_COMMAND_SIZE 27 // "ping 255.255.255.255 -c 1\0"
#define LOG_FILE_NAME_LENGTH 40

const char* OPERATION_MODES[] = {"AD-HOC", "AP", "STATION"}; 


// --------------------------------------- START PHY CONFIG ---------------------------------------

// DUMMY MACS
//const u8 DESTINATION_MAC[]  = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11}; // DUMMY Destination address (another STA under the same AP)
//const u8 SOURCE_MAC[]       = {0x66, 0x55, 0x44, 0x33, 0x22, 0x22}; // DUMMY Source address (STA)
//const u8 BSSID_MAC[]        = {0x66, 0x55, 0x44, 0x33, 0x22, 0x33}; // DUMMY BSSID/MAC of AP

const u8 BSSID_MAC[] = {0x30, 0xd3, 0x2d, 0xae, 0x15, 0x67}; 
//const u8 BSSID_MAC[] = {0x30, 0xd3, 0x2d, 0xf3, 0x42, 0x0b}; 
//const u8 BSSID_MAC[] = {0x96, 0xbf, 0x53, 0x85, 0x4e, 0x14}; 
const u8 SOURCE_MAC[] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11}; 
const u8 DESTINATION_MAC[] = {0xb8, 0x27, 0xeb, 0xfe, 0xc5, 0x39}; 

#define TARGET_IP_ADDRESS "192.168.0.202"
#define LOCAL_PING_CMD "ping 192.168.13.2 -c 1 > /dev/null"
#define REMOTE_PING_CMD "ssh mordred@192.168.10.1 'ping 192.168.0.202 -c 1 > /dev/null; echo $?'"
#define LOG_DIR "/root/logs"
#define TX_COUNT_TARGET_CMD "ssh arthur@192.168.20.2 'sudo ifconfig eth0 | grep \"TX packets\" | tr -s \" \" \":\"  | cut -d\":\" -f4'"
#define RX_COUNT_TARGET_CMD "ssh arthur@192.168.20.2 'sudo ifconfig eth0 | grep \"RX packets\" | tr -s \" \" \":\"  | cut -d\":\" -f4'"



// --------------------------------------- END PHY CONFIG ---------------------------------------



#if __BYTE_ORDER == __LITTLE_ENDIAN
#define	le16_to_cpu(x) (x)
#define	le32_to_cpu(x) (x)
#else
#define	le16_to_cpu(x) ((((x)&0xff)<<8)|(((x)&0xff00)>>8))
#define	le32_to_cpu(x) \
((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)&0xff0000)>>8)|(((x)&0xff000000)>>24))
#endif
#define	unlikely(x) (x)




