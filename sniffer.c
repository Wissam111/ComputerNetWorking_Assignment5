#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>

//packet capturing using raw socket
int main()
{

    int sock;
    struct sockaddr saddr;
    struct ifreq ifr;
    struct packet_mreq mr;
    int PACKET_LEN = IP_MAXPACKET;
    mr.mr_type = PACKET_MR_PROMISC;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    char buff[IP_MAXPACKET];
    socklen_t len;
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock == -1)
    {
        printf("cant create socket , EROR!!");
        return 0;
    }
    //start promiscuous mode
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    printf("---------start packet capturing------\n");
    while (1)
    {

        bzero(buff, IP_MAXPACKET);
        len = sizeof(saddr);
        int data_size = recvfrom(sock, buff, PACKET_LEN, 0, &saddr, &len);
        struct iphdr *ipHeader = (struct iphdr *)(buff + sizeof(struct ethhdr));
        struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ipHeader + (4 * ipHeader->ihl));
        struct sockaddr_in from, to;

        if (ipHeader->protocol == IPPROTO_ICMP)
        {
            memset(&from, 0, sizeof(from));
            memset(&to, 0, sizeof(to));
            from.sin_addr.s_addr = ipHeader->saddr;
            to.sin_addr.s_addr = ipHeader->daddr;

            printf("---------Got one ICMP packet---------\n");
            printf("ICMP PACKET SIZE: %d\n", data_size);
            printf("From: %s\n", inet_ntoa(from.sin_addr));
            printf("To: %s\n", inet_ntoa(to.sin_addr));
            printf("ICMP type: %d \n", icmp_hdr->type);
            printf("ICMP code: %d \n", icmp_hdr->code);
        }
    }

    close(sock);

    return 0;
}
