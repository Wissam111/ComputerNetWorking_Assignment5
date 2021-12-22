// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
//
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>
#if defined _WIN32
// See at https://msdn.microsoft.com/en-us/library/windows/desktop/ms740506(v=vs.85).aspx
// link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>

/*
* This was a surpise to me...  This stuff is not defined anywhere under MSVC.
* They were taken from the MSDN ping.c program and modified.
*/

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define IP_MAXPACKET 65535

#pragma pack(1)

struct ip
{
    UINT8 ip_hl : 4; // length of the header
    UINT8 ip_v : 4;  // Version of IP
    UINT8 ip_tos;    // Type of service
    UINT16 ip_len;   // total length of the packet
    UINT16 ip_id;    // unique identifier of the flow
    UINT16 ip_off;   // fragmentation flags
    UINT8 ip_ttl;    // Time to live
    UINT8 ip_p;      // protocol (ICMP, TCP, UDP etc)
    UINT16 ip_sum;   // IP checksum
    UINT32 ip_src;
    UINT32 ip_dst;
};

struct icmp
{
    UINT8 icmp_type;
    UINT8 icmp_code; // type sub code
    UINT16 icmp_cksum;
    UINT16 icmp_id;
    UINT16 icmp_seq;
    UINT32 icmp_data; // time data
};

#pragma pack()

// MSVC defines this in winsock2.h
//typedef struct timeval {
//    long tv_sec;
//    long tv_usec;
//} timeval;

int gettimeofday(struct timeval *tp, struct timezone *tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME system_time;
    FILETIME file_time;
    uint64_t time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}

#else //  linux

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
#endif

// IPv4 header len without options
#define IP4_HDRLEN 20

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
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

// #define SOURCE_IP "192.168.56.1"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

int main()
{
    //delete as they ask
    // struct ip iphdr; // IPv4 header
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
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy(packet+ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP); 

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf(stderr, "socket() failed with error: %d"
#if defined _WIN32
                ,
                WSAGetLastError()
#else
                ,
                errno
#endif
        );
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    //starting the ping from here
    struct timeval start, end;
    gettimeofday(&start , NULL);
    // Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&dest_in, sizeof(dest_in)) == -1)
    {
        fprintf(stderr, "sendto() failed with error: %d"
#if defined _WIN32
                ,
                WSAGetLastError()
#else
                ,
                errno
#endif
        );
        return -1;
    }

    // char buffer[IP_MAXPACKET] = {0};
    printf("send to %s \n", DESTINATION_IP);
  
    for (;;)
    {
        char buff[IP_MAXPACKET] = {0};
        int len = sizeof(dest_in);
    


        //recv one time ICMP ECHO REPLY
        if (recvfrom(sock, buff, sizeof(buff), 0, (struct sockaddr *)&dest_in, (socklen_t *)&len) < 0)
        {
            printf("***recvfrom function not Working!!***\n");
        }
        else
        {

          
            gettimeofday(&end, NULL);
            double rtt_micro = (double)end.tv_usec - start.tv_usec;
            double rtt_milis = rtt_micro / 1000.;
            printf("RTT: %f milliseconds\n", rtt_milis);
            printf("RTT: %.0f microseconds\n", rtt_micro);
            break;
        }
  
    }

    // Close the raw socket descriptor.
#if defined _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

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
