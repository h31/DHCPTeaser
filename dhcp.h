/*
Copyright (c) 2014, Pierre-Henri Symoneaux
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of LightDhcpClient nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>

#ifndef _DHCP_H
#define _DHCP_H

#define DHCP_MAGIC            htonl(0x63825363)

#define DHCP_MIN_PACK_SIZE    240

#define OP_BOOT_REQUEST    0x01
#define OP_BOOT_REPLY        0x02

#define HW_TYPE_ETHERNET    0x01
#define HW_LENGTH_ETHERNET    0x06

//DHCP options

#define DHCP_END    0xff

#define OPTION_DHCP_MESSAGE_TYPE    53
#define VALUE_MESSAGE_DISCOVER        0x01
#define VALUE_MESSAGE_OFFER        0x02
#define VALUE_MESSAGE_REQUEST        0x03
#define VALUE_MESSAGE_ACK            0x05
#define VALUE_MESSAGE_NAK            0x06
#define VALUE_MESSAGE_INFORM        0x08

#define OPTION_SERVER_IP            54
#define OPTION_LEASE_TIME            51
#define OPTION_REQUESTED_IP        50
#define OPTION_CLIENT_ID            61

#define OPTION_PARAMETER_REQUEST_LIST    55

#define OPTION_SUBNET_MASK        1
#define OPTION_ROUTER            3
#define OPTION_BROADCAST_ADDR    28
#define OPTION_DNS                6
#define OPTION_DOMAIN_NAME        15
#define OPTION_HOST_NAME        12

//These should not really be usefull for what we do
#define OPTION_TIME_OFFSET        2
#define OPTION_STATIC_ROUTE    121
#define OPTION_NIS_DOMAIN        40
#define OPTION_NIS_SERVERS        41
#define OPTION_NTP_SERVERS        42
#define OPTION_MTU                26
#define OPTION_DOMAIN_SEARCH    119

//DHCP options
struct dhcp_opt {
    uint8_t id;       // Option ID
    uint8_t len;      // Option value length
    uint8_t values[]; // Option value(s)
};

//DHCP packet structure
struct dhcp_pkt {
    uint8_t op;     // Message type
    uint8_t htype;  // HW type
    uint8_t hlen;   // HW addr length
    uint8_t hops;   // Hops

    uint32_t xid;    // Transaction ID

    uint16_t secs;   // seconds elapsed
    uint16_t flags;  // Bootp flags

    uint32_t ci_addr; // Client address
    uint32_t yi_addr; // Your address
    uint32_t si_addr; // Next Server IP address
    uint32_t gi_addr; // Relay agent IP address
    uint8_t cm_addr[6];   // Client MAC address
    uint8_t ch_addr[10];  // Client hardware address padding

    uint8_t unused[192];

    uint32_t magic;      // DHCP magic number

    uint8_t opt[128];   // Options padding
//    struct dhcp_opt opt [64];
};

//Build a discover DHCP packet, return packet size
int build_dhcp_request(struct dhcp_pkt *pkt, const unsigned char *src_mac, int mac_len,
                       struct in_addr requested_ip_address, struct in_addr dhcp_server_address,
                       bool add_client_id);

//Check if the packet is a DHCP one
int is_dhcp(struct dhcp_pkt *pkt);

#endif
