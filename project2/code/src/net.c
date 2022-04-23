#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

#define DEBUG

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    unsigned short *addr = (unsigned short *)&iphdr;
    unsigned int count = iphdr.ihl<<2;
    register unsigned long sum = 0;
    while ( count > 1)
    {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0)
    {
        sum += ((*addr)&htons(0xFF00));
    }
    while ( sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    return ((u_int16_t)sum);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    // struct net {
    //     char *src_ip;
    //     char *dst_ip;

    //     char *x_src_ip; /* Expected src IP addr */
    //     char *x_dst_ip; /* Expected dst IP addr */

    //     struct iphdr ip4hdr;

    //     size_t hdrlen;
    //     uint16_t plen;
    //     Proto pro;

    //     uint8_t *(*dissect)(Net *self, uint8_t *pkt, size_t pkt_len);
    //     Net *(*fmt_rep)(Net *self);
    // };
    struct iphdr *iph = (struct iphdr *)pkt;
    self->ip4hdr = *iph;
    self->hdrlen = sizeof(struct iphdr);
    self->plen = pkt_len - self->hdrlen;
    self->src_ip = iph->saddr;
    self->dst_ip = iph->daddr;
    
    switch (iph->protocol)
    {
    case ESP:
        self->pro = ESP;
        break;
    case IPv4:
        self->pro = IPv4;
        break;
    case TCP:
        self->pro = TCP;
        break;
    default:
        self->pro = UNKN_PROTO;
        break;
    }

#ifdef DEBUG
    printf("IP pkt srcIP: %d", self->src_ip);
    printf("IP pkt dstIP: %d", self->dst_ip);
    printf("IP pkt protocol: %d", self->pro);
#endif

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    // struct iphdr
    // {
    // #if __BYTE_ORDER == __LITTLE_ENDIAN
    //     unsigned int ihl:4;
    //     unsigned int version:4;
    // #elif __BYTE_ORDER == __BIG_ENDIAN
    //     unsigned int version:4;
    //     unsigned int ihl:4;
    // #else
    // # error	"Please fix <bits/endian.h>"
    // #endif
    //     uint8_t tos;
    //     uint16_t tot_len;
    //     uint16_t id;
    //     uint16_t frag_off;
    //     uint8_t ttl;
    //     uint8_t protocol;
    //     uint16_t check;
    //     uint32_t saddr;
    //     uint32_t daddr;
    //     /*The options start here. */
    // };

    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
