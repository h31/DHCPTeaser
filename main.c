#include <stdio.h>

#include "dhcp.h"
#include "net.h"

#include <sys/socket.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>

#include <linux/if_arp.h>

/*our MAC address*/
unsigned char src_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*other host MAC address*/
const unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

char *interface = "br-wan";

struct in_addr requested_ip_addr;

struct in_addr dhcp_server_addr;

int decode_mac_string(unsigned char mac[6], const char *mac_string) {
    return sscanf(mac_string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void read_arguments(int argc, char **argv) {
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s IFACE_NAME SRC_MAC_ADDR REQUESTED_IP_ADDR [DHCP_SERVER_ADDR]\n", argv[0]);
        exit(1);
    }

    interface = argv[1];
    const char *src_mac_string = argv[2];
    int conversion_result = decode_mac_string(src_mac, src_mac_string);
    if (conversion_result != 6) {
        fprintf(stderr, "Invalid MAC address: %s\n", src_mac_string);
        exit(1);
    }

    const char *requested_ip_addr_string = argv[3];
    conversion_result = inet_aton(requested_ip_addr_string, &requested_ip_addr);
    if (conversion_result == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", requested_ip_addr_string);
        exit(1);
    }

    printf("Request: \n  Interface = %s\n  MAC address: %s\n  IP address: %s\n", interface, src_mac_string,
           requested_ip_addr_string);

    if (argc == 5) {
        const char* dhcp_server_addr_string = argv[4];
        inet_aton(dhcp_server_addr_string, &dhcp_server_addr);
        printf("  DHCP server IP address: %s\n", dhcp_server_addr_string);
    } else {
        dhcp_server_addr.s_addr = 0;
    }
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "You need root permissions\n");
        exit(1);
    }

    read_arguments(argc, argv);

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (sock < 0) {
        perror("Error while creating a socket");
        exit(1);
    }

    //Set receive timeout
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = 10; //10 seconds in case of latency on the network
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error while creating a socket");
        exit(1);
    }

    //retrieve ethernet NIC index and HW address
    struct hw_eth_iface iface = find_iface(sock,
                                           interface); // TODO : Check interface existency, and print a list of possible NIC

    struct sockaddr_ll target;
    memset(&target, 0, sizeof(target));
    target.sll_family = PF_PACKET;
    target.sll_protocol = htons(ETH_P_IP);
    target.sll_ifindex = iface.index;
    target.sll_hatype = ARPHRD_ETHER;
    target.sll_pkttype = PACKET_HOST;
    target.sll_halen = ETH_ALEN;

    memcpy(target.sll_addr, dest_mac, 6);

    unsigned char *frame_buffer = (void *) malloc(ETH_FRAME_LEN);

    /*userdata in ethernet frame*/
    unsigned char *packet_buffer = frame_buffer + 14;

    /*another pointer to ethernet header*/
    struct ethhdr *eh = (struct ethhdr *) frame_buffer;

    /*set the frame header*/
    memcpy((void *) eh->h_dest, (void *) dest_mac, ETH_ALEN);
    memcpy((void *) eh->h_source, (void *) src_mac, ETH_ALEN);
    eh->h_proto = htons(ETH_P_IP);

//    struct dhcp_pkt *dhcp = (struct dhcp_pkt*)(frame_buffer + sizeof(struct udpheader) + sizeof(struct ipheader));
    struct dhcp_pkt dhcp;
    int dhcp_len = build_dhcp_request(&dhcp, src_mac, iface.addr_len, requested_ip_addr, dhcp_server_addr);

    int len = build_ip4_udp_pkt(packet_buffer, ETH_DATA_LEN, (unsigned char *) &dhcp, dhcp_len, "0.0.0.0",
                                "255.255.255.255", 68,
                                67, IPPROTO_UDP);

    //Send the packet over the network
    if (sendto(sock, frame_buffer, len + ETH_HLEN, 0, (struct sockaddr *) &target, sizeof(target)) < 0) {
        perror("Error while writing to socket");
        exit(1);
    }

    //Now, wait for the server response, and read it

    receive:
    memset(frame_buffer, 0, ETH_FRAME_LEN);

    //Read a packet
    int read_len = recvfrom(sock, frame_buffer, ETH_FRAME_LEN, 0, NULL, NULL);
    if (read_len <= 0) {
        perror("Cannot read");
        exit(1);
    }

    struct ipheader *rip = (struct ipheader *) packet_buffer;
    struct udpheader *rudp = (struct udpheader *) (packet_buffer + sizeof(struct ipheader));
    struct dhcp_pkt *rdhcp = (struct dhcp_pkt *) (packet_buffer + sizeof(struct udpheader) + sizeof(struct ipheader));

    //Check packet validity
    // if dest port isn't our or packet is not a dhcp one, drop the packet
    if (rip->iph_protocol != IPPROTO_UDP || rudp->udph_destport != htons(68) || !is_dhcp(rdhcp) ||
        rdhcp->op != OP_BOOT_REPLY || memcmp(eh->h_dest, dest_mac, ETH_ALEN) != 0) {
//        printf("Skipping a packet \n");
        goto receive;
    }

//    printf("Data Recieved, length = %d\n", read_len);

    printf("Response:\n  MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           rdhcp->cm_addr[0], rdhcp->cm_addr[1], rdhcp->cm_addr[2], rdhcp->cm_addr[3], rdhcp->cm_addr[4], rdhcp->cm_addr[5]);

    //Find the IP attributed to us by the server
    struct in_addr raddr;
    raddr.s_addr = rdhcp->yi_addr;

    printf("  IP address: %s\n", inet_ntoa(raddr));

    struct in_addr server_addr;
    server_addr.s_addr = rdhcp->si_addr;

    printf("  DHCP server IP address: %s\n", inet_ntoa(server_addr));

//    //Now check DHCP options, and process them
//    struct dhcp_opt *opt = NULL;
//    int offs = 0;
//    opt = get_dhcp_option(rdhcp, &offs);
//    while (opt != NULL) {
////        printf("OPT FOUND offset = %d\n", offs);
//        switch (opt->id) {
//            case OPTION_ROUTER: // If the option is the gateway address
//                if (opt->len == 4) {
//                    raddr.s_addr = char_to_ip(opt->values);
//                    printf("GATEWAY=%s\n", inet_ntoa(raddr));
//                }
//                break;
//
//            case OPTION_SUBNET_MASK: // If the option is the netwmask
//                if (opt->len == 4) {
//                    raddr.s_addr = char_to_ip(opt->values);
//                    printf("NETMASK=%s\n", inet_ntoa(raddr));
//                }
//                break;
//
//            case OPTION_DNS: // If option is the DNS addresses
//                if (opt->len % 4 == 0) {
//                    int i = 0;
//                    printf("NAMESERVER=");
//                    int max = opt->len / 4;
//                    for (i = 0; i < max; i++) {
//                        raddr.s_addr = char_to_ip(opt->values + 4 * i);
//                        printf("%s", inet_ntoa(raddr));
//                        if (i < max - 1)
//                            printf(",");
//                    }
//                    printf("\n");
//                }
//                break;
//
//            default:
//                break;
//        }
//        opt = get_dhcp_option(rdhcp, &offs);
//    }

    close(sock);
    exit(0);
}