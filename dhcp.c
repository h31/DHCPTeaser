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

#include "dhcp.h"

#include <string.h>

int build_dhcp_request(struct dhcp_pkt *pkt, const unsigned char *src_mac, int mac_len,
                       const struct in_addr requested_ip_address, const struct in_addr dhcp_server_address,
                       bool add_client_id) {
    memset(pkt, 0, sizeof(struct dhcp_pkt));
    pkt->op = OP_BOOT_REQUEST;
    pkt->htype = HW_TYPE_ETHERNET;
    pkt->hlen = HW_LENGTH_ETHERNET;
    pkt->hops = 0x00;
    pkt->xid = 0x3903f326; //TODO: Random transaction ID, bit order
    pkt->secs = 0x0000;
    pkt->flags = htons(0x8000); // Broadcast enabled
    pkt->ci_addr = 0x00000000;
    pkt->yi_addr = 0x00000000;
    pkt->si_addr = 0x00000000;
    pkt->gi_addr = 0x00000000;

    memcpy(pkt->cm_addr, src_mac, mac_len);

    pkt->magic = DHCP_MAGIC;

    //Add DHCP options
    int i = 0;
    pkt->opt[i++] = OPTION_DHCP_MESSAGE_TYPE;
    pkt->opt[i++] = 0x01; // length
    pkt->opt[i++] = VALUE_MESSAGE_REQUEST;

    pkt->opt[i++] = OPTION_REQUESTED_IP;
    pkt->opt[i++] = 0x04;
    memcpy(pkt->opt + i, (const void *) &requested_ip_address.s_addr, sizeof(in_addr_t));
    i += sizeof(in_addr_t);

    if (add_client_id) {
        pkt->opt[i++] = OPTION_CLIENT_ID;
        pkt->opt[i++] = 0x07;
        pkt->opt[i++] = 0x01;
        memcpy(pkt->opt + i, (const void *) src_mac, mac_len);
        i += mac_len;
    }

    if (dhcp_server_address.s_addr != 0) {
        pkt->opt[i++] = OPTION_SERVER_IP;
        pkt->opt[i++] = 0x04;
        memcpy(pkt->opt + i, (const void *) &dhcp_server_address.s_addr, sizeof(in_addr_t));
        i += sizeof(in_addr_t);
    }
    pkt->opt[i] = DHCP_END;

    //TODO : Use the same procedure to write options, than the one used to read options
//    pkt->opt[0].id = 53;
//    pkt->opt[0].len = 0x01;
//    pkt->opt[0].values[0] = 0x01;
//
//    pkt->opt[1].id = DHCP_END;

    return sizeof(struct dhcp_pkt);
}

int is_dhcp(struct dhcp_pkt *pkt) {
    // It's a DHCP packet if dhcp magic number is good
    //TODO: check the packet length ?
    return pkt->magic == DHCP_MAGIC;
}

