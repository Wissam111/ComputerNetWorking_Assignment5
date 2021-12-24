// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
//
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>

//  linux

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <time.h>
#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short *paddress, int len);
 
// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click
//    menu "Run as administrator"

//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.4.4"

struct pckt
{
    struct iphdr iphdr;
    struct icmphdr icmphdr;
    char data[IP_MAXPACKET];
};

int main()
{

    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = getpid();

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    //  ICMP header
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    inet_pton(AF_INET, DESTINATION_IP, &(dest_in.sin_addr));

    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf(stderr, "socket() failed with error: ");
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // struct timespec start, end;
    // clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    struct timeval start, end;
    gettimeofday(&start, NULL);

    //Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&dest_in, sizeof(dest_in)) == -1)
    {
        fprintf(stderr, "sendto() failed with error: ");
        return -1;
    }

    int len = sizeof(dest_in);
    int b;
    struct pckt pckt;

    while (1)
    {
        if ((b = recvfrom(sock, &pckt, sizeof(pckt), 0, (struct sockaddr *)&dest_in, &len)) > 0)
        {

            //printf("icmp id %d", icmphdr.icmp_id);
            if (icmphdr.icmp_id == pckt.icmphdr.un.echo.id && pckt.icmphdr.type == ICMP_ECHOREPLY)
            {
                struct sockaddr_in from, to;
                memset(&from, 0, sizeof(from));
                memset(&to, 0, sizeof(to));
                from.sin_addr.s_addr = pckt.iphdr.saddr;
                to.sin_addr.s_addr = pckt.iphdr.daddr;

                printf("---------------");
                printf("got message \n");
                printf("ICMP id : %d \n", pckt.icmphdr.un.echo.id);
                printf("ICMP type : %d \n", pckt.icmphdr.type);
                printf("ICMP code : %d \n", pckt.icmphdr.code);
                printf("src ip : %s \n", inet_ntoa(from.sin_addr));
                printf("dest ip : %s \n", inet_ntoa(to.sin_addr));
                printf("data : %s \n", pckt.data);
                break;
            }
            else
            {
                printf("its not my ping request \n");
            }
        }
    }
    gettimeofday(&end, NULL);
    gettimeofday(&end, NULL);
    double rtt_micro = (double)end.tv_usec - start.tv_usec;
    double rtt_milis = rtt_micro / 1000.;

    printf("RTT: %f milliseconds\n", rtt_milis);
    printf("RTT: %.0f microseconds\n", rtt_micro);
    close(sock);
    return 0;
}
    
// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}