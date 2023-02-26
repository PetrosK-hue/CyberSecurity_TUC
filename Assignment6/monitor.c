#include "monitor.h"

int tcpPackets = 0, udpPackets = 0, tcpBytes = 0, udpBytes = 0, otherPackets = 0, retransmissions = 0;
netFlowList *TCPList, *UDPList;
netFlow *newFlow;
packetInfo *pInfo;

/**************** Packet Capture Methods [offline_capture] ****************/
void offline_capture(const char *fname)
{
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */
    pcap_t *handle;                      /* Device handle to capture */
    int packet_cnt = 0;                /* Counter of packets to capture ( 0 for unlimited packets) */

    // receiving packets form pcap file
    handle = pcap_open_offline(fname, error_buffer);

    // if handle NULL error
    if (handle == NULL)
        print(error_buffer, error);

    /* libcap function that reads all packets and calls callback_func( gotPacket). (terminates itself) */
    pcap_loop(handle, packet_cnt, gotPacket, NULL);
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int size = header->len;
    newFlow = malloc(sizeof(netFlow));
    pInfo = malloc(sizeof(packetInfo));
    // Getting the ethernet header and ethernet type
    struct ether_header *eth = (struct ether_header *)packet;
    // if ip version is 4 or 6
    if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        // Getting the ipv4 header and passing it in decodeIpv4Header function
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        // decoding the ipv4 header to collect every info needed
        decodeIpv4Header(ip_header, newFlow, pInfo);

        // ----------------------- next header -----------------------
        unsigned short iphdrlen = ip_header->ihl * 4;
        int protocolAndPayloadSize = ntohs(ip_header->tot_len) - iphdrlen;
        switch (ip_header->protocol)
        {
        case 6:               // TCP Protocol
            tcpPackets++;     // increase tcp packet counter by 1
            tcpBytes += size; // increase tcp bytes counter by the total package size
            // Getting the tcp header and passing it in decodeTcpHeader function
            struct tcphdr *tcph = (struct tcphdr *)(packet + iphdrlen + sizeof(struct ether_header));
            // decoding the tcp header to collect every info needed
            decodeTcpHeader(tcph, protocolAndPayloadSize, newFlow, pInfo);
            // Add the specific network flow in the TCP network flows list if not already exist
            TCPList = pushFlowInList(TCPList, newFlow);
            // Print the collected packet's info
            printPacket(pInfo);
            break;
        case 17:              // UDP Protocol
            udpPackets++;     // increase tcp packet counter by 1
            udpBytes += size; // increase tcp bytes counter by the total package size
            // Getting the udp header and passing it in decodeUdpHeader function
            struct udphdr *udph = (struct udphdr *)(packet + iphdrlen + sizeof(struct ether_header));
            // decoding the udp header to collect every info needed
            decodeUdpHeader(udph, protocolAndPayloadSize, newFlow, pInfo);
            // Add the specific network flow in the UDP network flows list if not already exist
            UDPList = pushFlowInList(UDPList, newFlow);
            // Print the collected packet's info
            printPacket(pInfo);
            break;
        default:            // Every other protocol apart from tcp udp
            otherPackets++; // increase otherpackets' counter by 1
            break;
        }
    }
    else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6)
    {
        // Getting the ipv6 header and passing it in decodeIpv6Header function
        struct ip6_hdr *ipv6_h = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
        // decoding the ipv6 header to collect every info needed
        decodeIpv6Header(ipv6_h, newFlow, pInfo);

        // ----------------------- next header -----------------------
        int protocolAndPayloadSize = size - sizeof(struct ether_header) - sizeof(struct ip6_hdr);
        switch (ipv6_h->ip6_nxt)
        {
        case 6:               // TCP Protocol
            tcpPackets++;     // increase tcp packet counter by 1
            tcpBytes += size; // increase tcp bytes counter by the total package size
            // Getting the tcp header and passing it in decodeTcpHeader function
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip6_hdr) + sizeof(struct ether_header));
            // decoding the tcp header to collect every info needed
            decodeTcpHeader(tcph, protocolAndPayloadSize, newFlow, pInfo);
            // Add the specific network flow in the TCP network flows list if not already exist
            TCPList = pushFlowInList(TCPList, newFlow);
            // Print the collected packet's info
            printPacket(pInfo);
            break;
        case 17:              // UDP Protocol
            udpPackets++;     // increase tcp packet counter by 1
            udpBytes += size; // increase tcp bytes counter by the total package size
            // Getting the udp header and passing it in decodeUdpHeader function
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip6_hdr) + sizeof(struct ether_header));
            // decoding the udp header to collect every info needed
            decodeUdpHeader(udph, protocolAndPayloadSize, newFlow, pInfo);
            // Add the specific network flow in the UDP network flows list if not already exist
            UDPList = pushFlowInList(UDPList, newFlow);
            // Print the collected packet's info
            printPacket(pInfo);
            break;
        default:            // Every other protocol apart from tcp udp
            otherPackets++; // increase otherpackets' counter by 1
            break;
        }
    }
    else
        otherPackets++; // increase otherpackets' counter by 1
}

netFlow *findconversationOtherPart(netFlow *newFlow)
{
    netFlowList *list = TCPList;
    netFlowLinkedList *currFlow;
    // If list does not exists init one, else get the current flow.
    if (list == NULL)
    {
        list = malloc(sizeof(netFlowList));
        list->sum = 1;
        list->flows = malloc(sizeof(netFlowLinkedList));
        list->flows->flow = newFlow;
        list->flows->nextFlow = NULL;
        return NULL;
    }
    else
        currFlow = list->flows;
    // Parse the list to check if flow exists
    while (currFlow->nextFlow != NULL)
    {
        // By the time we found the flow we return the head and do nothing
        if (isFlowsame(currFlow->flow, newFlow))
            return currFlow->flow;
        // get the next flow
        currFlow = currFlow->nextFlow;
    }
    if (isFlowsame(currFlow->flow, newFlow))
        return currFlow->flow;
    // If flow not found, add it and increase list->sum
    return NULL;
}

int isRetransmitted(const struct tcphdr *header, netFlow *newFlow)
{
    netFlow *otherFlow = malloc(sizeof(netFlow));
    strcpy(otherFlow->destinationAddr, newFlow->sourceAddr);
    strcpy(otherFlow->sourceAddr, newFlow->destinationAddr);
    otherFlow->destinationPort = newFlow->sourcePort;
    otherFlow->sourcePort = newFlow->destinationPort;
    otherFlow->protocol = newFlow->protocol;

    if (header->th_flags == TH_ACK)
    {
        netFlow *found = findconversationOtherPart(otherFlow);
        if (found != NULL)
        {
            if (ntohl(header->th_ack) != found->expectedAck)
            {
                retransmissions++;
                return 1;
            }
        }
    }
    return 0;
}

/**************** Network Flow List Methods ****************/

int isFlowsame(netFlow *currentFlow, netFlow *givenFlow)
{
    int sameProtocol = currentFlow->protocol == givenFlow->protocol;
    int sameDestAddr = strcmp(currentFlow->destinationAddr, givenFlow->destinationAddr) == 0 ? 1 : 0;
    int sameSourceAddr = strcmp(currentFlow->sourceAddr, givenFlow->sourceAddr) == 0 ? 1 : 0;
    int sameDestPort = (unsigned long)currentFlow->destinationPort == (unsigned long)givenFlow->destinationPort;
    int sameSourcePort = (unsigned long)currentFlow->sourcePort == (unsigned long)givenFlow->sourcePort;

    return sameDestAddr && sameSourceAddr && sameDestPort && sameSourcePort && sameProtocol;
}

netFlowList *pushFlowInList(netFlowList *head, netFlow *newFlow)
{
    netFlowList *list = head;
    netFlowLinkedList *currentFlow;
    // If list does not exists init one, else get the current flow.
    if (list == NULL)
    {
        list = malloc(sizeof(netFlowList));
        list->sum = 1;
        list->flows = malloc(sizeof(netFlowLinkedList));
        list->flows->flow = newFlow;
        list->flows->nextFlow = NULL;
        return list;
    }
    else
        currentFlow = list->flows;
    // Parse the list to check if flow exists
    while (currentFlow->nextFlow != NULL)
    {
        // By the time we found the flow we return the head and do nothing
        if (isFlowsame(currentFlow->flow, newFlow))
        {
            currentFlow->flow->expectedAck = newFlow->expectedAck;
            return head;
        }
        // get the next flow
        currentFlow = currentFlow->nextFlow;
    }
    if (isFlowsame(currentFlow->flow, newFlow))
    {
        currentFlow->flow->expectedAck = newFlow->expectedAck;
        return head;
    }
    // If flow not found, add it and increase list->sum
    currentFlow->nextFlow = malloc(sizeof(netFlowLinkedList));
    currentFlow->nextFlow->flow = newFlow;
    currentFlow->nextFlow->nextFlow = NULL;
    list->sum++;
    return head;
}
/* **************************** Headers' Decoders **************************** */
void decodeTcpHeader(const struct tcphdr *header, int tcpAndPayloadSize, netFlow *newFlow, packetInfo *pInfo)
{
    // add info to packet Info
    pInfo->sourcePort = ntohs(header->source);
    pInfo->destinationPort = ntohs(header->dest);
    pInfo->headerLenght = (unsigned int)header->doff * 4;
    pInfo->payloadLenght = tcpAndPayloadSize - pInfo->headerLenght;
    // add info to network flow
    newFlow->destinationPort = ntohs(header->dest);
    newFlow->sourcePort = ntohs(header->source);
    newFlow->expectedAck = ntohl(header->seq) + pInfo->payloadLenght;
    if (((header->th_flags >> 1) & 1) == 1) // shift AND 1
        newFlow->expectedAck++;
    pInfo->retransmitted = isRetransmitted(header, newFlow);
}

void decodeUdpHeader(const struct udphdr *udph, int udpAndPayloadSize, netFlow *newFlow, packetInfo *pInfo)
{
    // add info to packet Info
    pInfo->sourcePort = ntohs(udph->source);
    pInfo->destinationPort = ntohs(udph->dest);
    pInfo->headerLenght = sizeof(udph);
    pInfo->payloadLenght = udpAndPayloadSize - pInfo->headerLenght;
    // add info to network flow
    newFlow->destinationPort = ntohs(udph->dest);
    newFlow->sourcePort = ntohs(udph->source);
}

void decodeIpv6Header(const struct ip6_hdr *ipv6Header, netFlow *newFlow, packetInfo *pInfo)
{
    // create 2 sockaddr_in to get destination's and source's addresses
    char buffer[INET6_ADDRSTRLEN];
    struct in6_addr source = ipv6Header->ip6_src;
    struct in6_addr dest = ipv6Header->ip6_dst;
    char src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &source, src, INET6_ADDRSTRLEN);
    char dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dest, dst, INET6_ADDRSTRLEN);
    char *prt;
    if (ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6)
        prt = "TCP";
    else if (ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17)
        prt = "UDP";
    else
        prt = "OTHER";

    // packet Info
    strcpy(pInfo->protocol, prt);
    strcpy(pInfo->sourceAddr, src);
    strcpy(pInfo->destinationAddr, dst);
    // network flow info
    newFlow->protocol = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    strcpy(newFlow->sourceAddr, src);
    strcpy(newFlow->destinationAddr, dst);
}

void decodeIpv4Header(const struct iphdr *ipHeader, netFlow *newFlow, packetInfo *pInfo)
{
    // create 2 sockaddr_in to get destination's and source's addresses
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ipHeader->saddr;
    dest.sin_addr.s_addr = ipHeader->daddr;

    // protocol to TCP/UDP
    char *prt;
    if ((unsigned int)ipHeader->protocol == 6)
        prt = "TCP";
    else if ((unsigned int)ipHeader->protocol == 17)
        prt = "UDP";
    else
        prt = "OTHER";

    // packet Info
    strcpy(pInfo->protocol, prt);
    strcpy(pInfo->sourceAddr, inet_ntoa(source.sin_addr));
    strcpy(pInfo->destinationAddr, inet_ntoa(dest.sin_addr));
    // network flow info
    newFlow->protocol = ipHeader->protocol;
    strcpy(newFlow->sourceAddr, inet_ntoa(source.sin_addr));
    strcpy(newFlow->destinationAddr, inet_ntoa(dest.sin_addr));
}

/*************** USAGE [print] ***************/
void usage(void)
{
    printf(
        "\nusage:\n"
        "./monitor \n"
        " Options:\n"
        "-r <pcap_file>,\tThe Packet Capture File to use.\n"
        "-h, \tHelp message\n\n");

    exit(1);
}

/***************  MAIN  ************** */
int main(int argc, char *argv[])
{
    signal(SIGINT, handle_sigint);
    const char *fname;
    const char *device;

    int ch;
    if (argc < 2 || argc > 3)
        usage();
    while ((ch = getopt(argc, argv, "r:h")) != -1)
    {
        switch (ch)
        {
        case 'r':
            offline_capture(optarg);
            printFinalStats();
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    return 0;
}

void handle_sigint(int sig)
{
    printFinalStats();
    exit(1);
}

/* **************************** Print methods **************************** */

void printPacket(packetInfo *pInfo)
{
    printf("+-----------------------------------------------------------+\n");
    printf("| Packet Info:\n");
    printf("|  ->|-Source IP         : %s |\n", pInfo->sourceAddr);
    printf("|    |-Destination IP    : %s |\n", pInfo->destinationAddr);
    printf("|    |-Source Port       : %u |\n", pInfo->sourcePort);
    printf("|    |-Destination Port  : %u |\n", pInfo->destinationPort);
    printf("|    |-Protocol          : %s |\n", pInfo->protocol);
    printf("|    |-Header Length     : %d BYTES |\n", pInfo->headerLenght);
    printf("|    |-Payload Length    : %d BYTES |\n", pInfo->payloadLenght);

    if (strcmp(pInfo->protocol, "TCP") == 0)
        printf("|    |-Retransmitted     : %d |\n", pInfo->retransmitted);
    printf("+-----------------------------------------------------------+\n");
    printf("+                                                           +\n");
}
void printFinalStats()
{
    int tcpFlows = 0, udpFlows = 0;
    if (TCPList != NULL)
        tcpFlows = TCPList->sum;
    if (UDPList != NULL)
        udpFlows = UDPList->sum;

    printf("+-----------------------------------------------------------+\n");
    printf("|                    Final Statistics:                      |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("Total number of network flows captured:  %d\n", tcpFlows + udpFlows);
    printf("Number of TCP network flows captured:  %d\n", tcpFlows);
    printf("Number of UDP network flows captured:  %d\n", udpFlows);
    printf("Total number of packets received:  %d\n", otherPackets + udpPackets + tcpPackets);
    printf("Total number of TCP packets received: %d\n", tcpPackets);
    printf("Total number of UDP packets received: %d\n", udpPackets);
    printf("Total bytes of TCP packets received : %d\n", tcpBytes);
    printf("Total bytes of UDP packets received : %d\n", udpBytes);
    printf("Retransmissions : %d\n", retransmissions);
}

//  Print failure mode
void print(char *str, enum mode md)
{
    switch (md)
    {
    case error:
        printf("\033[1;31m");
        printf("[ERROR]: \033[0m %s\n", str);
        exit(EXIT_FAILURE);
        break;
    case info:
        printf("\033[0;36m");
        printf("[INFO]: \033[0m %s\n", str);
        break;
    case success:
        printf("\033[0;32m");
        printf("%s\033[0m\n", str);
        break;
    default:
        printf("%s\n", str);
        break;
    }
}