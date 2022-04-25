#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

#define DEBUG

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(iphdr.tot_len) - (iphdr.ihl<<2);
    unsigned short *ipPayload = (unsigned short *)&tcphdr;
    // add pseudo header
    //src ip
    sum += (iphdr.saddr >> 16)&0xFFFF;
    sum += (iphdr.saddr)&0xFFFF;
    //dst ip
    sum += (iphdr.daddr >> 16)&0xFFFF;
    sum += (iphdr.daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    // length
    sum += htons(tcpLen);
    // add th IP payload
    while ( tcpLen > 1)
    {
        sum += *ipPayload++;
        tcpLen -= 2;
    }
    if ( tcpLen > 0)
    {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    while ( sum >> 16)
    {
        sum += ( sum & 0xFFFF) + ( sum << 16);
    }
    sum = ~sum;
    return ((u_int16_t)sum);
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
    struct tcphdr *tcp = (struct tcphdr *)segm;
    memcpy(&self->thdr, tcp, sizeof(struct tcphdr));

#ifdef DEBUG
   	printf("\nTCP Header\n");
   	printf("\t|-Source Port          : %u\n",ntohs(tcp->source));
   	printf("\t|-Destination Port     : %u\n",ntohs(tcp->dest));
   	printf("\t|-Sequence Number      : %u\n",ntohl(tcp->seq));
   	printf("\t|-Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
   	printf("\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
	printf("\t|----------Flags-----------\n");
	printf("\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
	printf("\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
	printf("\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
	printf("\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
	printf("\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
	printf("\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
	printf("\t|-Window size          : %d\n",ntohs(tcp->window));
	printf("\t|-Checksum             : %d\n",ntohs(tcp->check));
	printf("\t|-Urgent Pointer       : %d\n",tcp->urg_ptr);
    printf("self->thdr.ack_seq: %u\n", ntohl(self->thdr.ack_seq));
    printf("self->thdr.psh: %d\n", (unsigned int)(self->thdr.psh));
#endif
    return  segm + sizeof(struct tcphdr);
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

