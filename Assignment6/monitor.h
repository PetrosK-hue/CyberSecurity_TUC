#ifndef _MONITOR_H
#define _MONITOR_H


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

enum mode
{
    info,
    error,
    success
};

/**
 * @brief A struct to store the asked packet informations
 * 
 */
typedef struct packet{
    char protocol[6];
    char destinationAddr[64];
    char sourceAddr[64];
    uint16_t destinationPort;
    uint16_t sourcePort;
    int headerLenght;
    int payloadLenght;
    int retransmitted;
}packetInfo;

/**
 * @brief A struct to store the network flows found in the traffic
 * 
 */
typedef struct nflow
{
    int protocol;
    char destinationAddr[64];
    char sourceAddr[64];
    uint16_t destinationPort;
    uint16_t sourcePort;
    uint32_t expectedAck;
} netFlow;

typedef struct nflowLinkedList
{
    netFlow *flow;                /** The current file name*/
    struct nflowLinkedList *nextFlow; /** Pointer to the next file of File list */

} netFlowLinkedList;

typedef struct nFlowList
{
    int sum;                      /** The sum of files from list head until the end of the list */
    netFlowLinkedList *flows; /** Pointer to the next file of File list */

} netFlowList;

/* **************************** Flow list methods **************************** */

/**
 * @brief Check if two given network flows are identicals 
 */
int isFlowsame(netFlow *currentFlow, netFlow *givenFlow);

/**
 * @brief Push the given flow to the given networkFlowList 
 */
netFlowList *pushFlowInList(netFlowList *head, netFlow *newFlow);


/* **************************** PCAP methods **************************** */

void offline_capture(const char *fname);
void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void handle_sigint(int sig);

/* **************************** Decoding Headers methods **************************** */

/**
 * @brief Decodes the given ipv6 header (protocol, destination Addr, source Addr)
 */
void decodeIpv6Header(const struct ip6_hdr *ipv6Header, netFlow *newFlow, packetInfo *pInfo);

/**
 * @brief Decodes the given ipv4 header (protocol, destination Addr, source Addr)
 * 
 */
void decodeIpv4Header(const struct iphdr *ipHeader, netFlow *newFlow, packetInfo *pInfo);

/**
 * @brief Decodes the given TCP header (tcp_hdr length, payload length, destination port, source port)
 */
void decodeTcpHeader(const  struct tcphdr * header, int packetSize, netFlow *newFlow, packetInfo *pInfo);

/**
 * @brief Decodes the given TCP header (udp_hdr length, payload length, destination port, source port)
 */
void decodeUdpHeader(const struct udphdr *udph, int udpAndPayloadSize, netFlow *newFlow, packetInfo *pInfo);

/* **************************** Print methods **************************** */

void printPacket(packetInfo *pInfo);
void printFinalStats();
void print(char *str, enum mode md);

#endif /* _MONITOR_H */