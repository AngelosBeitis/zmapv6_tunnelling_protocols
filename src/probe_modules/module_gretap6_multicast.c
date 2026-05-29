/* heavily copied from module_udp.c */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_gretap6_multicast;

typedef struct __attribute__((packed)) {
	uint16_t gre_bitfield;
	uint16_t protocol;
} gre_header_t;

static gre_header_t gre_header_default;

int gretap6_multicast_global_initialize(struct state_conf *conf)
{
	return EXIT_SUCCESS;

}

macaddr_t * generate_random_mac_gretap() {
    macaddr_t * mac = (macaddr_t*)malloc(6 * sizeof(unsigned char));
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
    // Ensure it's a unicast
    mac[0] = (mac[0] & 0xFC) | 0x02;

    return mac;
}

macaddr_t * mac_from_string_gretap(const char *mac_str) {
    macaddr_t * mac = (macaddr_t*)malloc(6 * sizeof(unsigned char));
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    return mac;
}

int gretap6_multicast_init_perthread(void *buf, macaddr_t *src,
					macaddr_t *gw, UNUSED port_h_t dst_port,
					UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct ether_header) + sizeof(gre_header_t) + sizeof(struct icmp6_hdr));
	make_ip_header(ip_header, IPPROTO_GRE, len);

    gre_header_t *gre_header = (gre_header_t *)&ip_header[1];
	memcpy(gre_header, &gre_header_default, sizeof(gre_header_default));
	gre_header->protocol = htons(0x6558); //ETHERNET_ENCAPSULATION

    struct ether_header *ether_header2 = (struct ether_header *)&gre_header[1];
    // make_eth_header(ether_header2, generate_random_mac(), mac_from_string("01:00:5E:00:00:01"));
	// Use broadcast MAC address instead of multicast
	make_eth_header_ethertype(ether_header2, generate_random_mac_gretap(), mac_from_string_gretap("33:33:00:00:00:01"),ETHERTYPE_IPV6);

	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&ether_header2[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	len = sizeof(struct icmp6_hdr);
	make_ip6_header(ip6_header, IPPROTO_ICMPV6, len);

	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);
	make_icmp6_header(icmp6_header, ICMP6_ECHO_REQUEST);

	return EXIT_SUCCESS;
}

int gretap6_multicast_make_packet(void *buf, size_t *buf_len,
				     ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				     uint8_t ttl, uint32_t *validation,
				     UNUSED int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
    gre_header_t *gre_header = (gre_header_t *)(&ip_header[1]);
    struct ether_header *eth_header2 = (struct ether_header *)(&gre_header[1]);
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header2[1]);
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)&ip6_header[1];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = MAXTTL;

	ip6_header->ip6_src =
	    ((struct in6_addr *)arg)[1]; // External IPv6 address
	ip6_header->ip6_dst =
	    ((struct in6_addr *)arg)[0]; //multicast IPv6 address ff02::1
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = MAXTTL;


    ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	icmp6_header->icmp6_seq = (ip_header->ip_dst.s_addr >> 16) & 0xFFFF;
	icmp6_header->icmp6_id = (ip_header->ip_dst.s_addr & 0xFFFF);

	icmp6_header->icmp6_cksum = ipv6_payload_checksum(
	    sizeof(struct icmp6_hdr), &ip6_header->ip6_src,
	    &ip6_header->ip6_dst, (unsigned short *)icmp6_header,
	    IPPROTO_ICMPV6);


	// Output the total length of the packet
	*buf_len = sizeof(struct ether_header)*2 + sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(gre_header_t )+ sizeof(struct icmp6_hdr);
	return EXIT_SUCCESS;
}

void gretap6_multicast_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
    gre_header_t *gre = (gre_header_t *)&iph[1];
	struct ip *iph2 = (struct ip *)&gre[1];
	struct icmp *icmp_header = (struct icmp *)(&iph2[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp_header->icmp_type, icmp_header->icmp_code,
		ntohs(icmp_header->icmp_cksum), ntohs(icmp_header->icmp_id),
		ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_ip_header(fp, iph2);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, PRINT_PACKET_SEP);
}

void gretap6_multicast_process_packet(const u_char *packet, UNUSED uint32_t len,
			 fieldset_t *fs, UNUSED uint32_t *validation,
			 UNUSED const struct timespec ts)
{
	
	struct ip6_hdr *ip6_hdr =
	    (struct ip6_hdr *)&packet[sizeof(struct ether_header)];
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(&ip6_hdr[1]);
	struct ip6_hdr *ip6_inner_hdr = (struct ip6_hdr *)&icmp6_hdr[1];

	uint32_t address = ((uint32_t)icmp6_hdr->icmp6_seq << 16 | icmp6_hdr->icmp6_id);
	fs_add_uint64(fs, "type", icmp6_hdr->icmp6_type);
	fs_add_string(fs, "actual_src", make_ip_str(address), 1);
	fs_add_uint64(fs, "code", icmp6_hdr->icmp6_code);
	fs_add_uint64(fs, "icmp_id", ntohs(icmp6_hdr->icmp6_id));
	fs_add_uint64(fs, "seq", ntohs(icmp6_hdr->icmp6_seq));
	fs_add_string(fs, "outersaddr", make_ipv6_str(&(ip6_hdr->ip6_src)), 1);
	if (icmp6_hdr->icmp6_type == ICMP6_ECHO_REPLY) {
		fs_add_string(fs, "classification", (char *)"echoreply", 0);
		fs_add_uint64(fs, "success", 1);
	} else {
		// Use inner IP header values for unsuccessful ICMP replies
		struct ip6_hdr *ip6_inner_hdr = (struct ip6_hdr *)&icmp6_hdr[1];
		fs_modify_string(fs, "saddr",
				 make_ipv6_str(&(ip6_inner_hdr->ip6_dst)), 1);
		fs_modify_string(fs, "daddr",
				 make_ipv6_str(&(ip6_inner_hdr->ip6_src)), 1);

		switch (icmp6_hdr->icmp6_type) {
		case ICMP6_DST_UNREACH:
			switch (icmp6_hdr->icmp6_code) {
			case ICMP6_DST_UNREACH_NOROUTE:
				fs_add_string(fs, "classification",
					      (char *)"unreach_noroute", 0);
				break;
			case ICMP6_DST_UNREACH_ADMIN:
				fs_add_string(fs, "classification",
					      (char *)"unreach_admin", 0);
				break;
			case ICMP6_DST_UNREACH_BEYONDSCOPE:
				fs_add_string(fs, "classification",
					      (char *)"unreach_beyondscope", 0);
				break;
			case ICMP6_DST_UNREACH_ADDR:
				fs_add_string(fs, "classification",
					      (char *)"unreach_addr", 0);
				break;
			case ICMP6_DST_UNREACH_NOPORT:
				fs_add_string(fs, "classification",
					      (char *)"unreach_noport", 0);
				break;
			case 5:
				fs_add_string(fs, "classification",
					      (char *)"unreach_policy", 0);
				break;
			case 6:
				fs_add_string(fs, "classification",
					      (char *)"unreach_rejectroute", 0);
				break;
			case 7:
				fs_add_string(fs, "classification",
					      (char *)"unreach_err_src_route",
					      0);
				break;
			default:
				fs_add_string(fs, "classification",
					      (char *)"unreach", 0);
				break;
			}
			break;
		case ICMP6_PACKET_TOO_BIG:
			fs_add_string(fs, "classification", (char *)"toobig",
				      0);
			break;
		case ICMP6_PARAM_PROB:
			fs_add_string(fs, "classification", (char *)"paramprob",
				      0);
			break;
		case ICMP6_TIME_EXCEEDED:
			fs_add_string(fs, "classification", (char *)"timxceed",
				      0);
			break;
		default:
			fs_add_string(fs, "classification", (char *)"other", 0);
			break;
		}
		fs_add_uint64(fs, "success", 0);
	}
}

static int gretap6_multicast_validate_packet(const struct ip *ip_hdr, uint32_t len,
				UNUSED uint32_t *src_ip, uint32_t *validation)
{
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ip_hdr;

	if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
		return PACKET_INVALID;
	}

	// offset iphdr by ip header length of 40 bytes to shift pointer to ICMP6 header
	struct icmp6_hdr *icmp6_h = (struct icmp6_hdr *)(&ip6_hdr[1]);

	if (icmp6_h->icmp6_type != ICMP6_ECHO_REPLY) {
		return PACKET_INVALID;
	}

	return PACKET_VALID;
}

static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
	{.name = "actual_src",
		.type = "string",
		.desc = "the actual source address embedded in the reply"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "icmp id number"},
    {.name = "seq", .type = "int", .desc = "icmp sequence number"},
    {.name = "outersaddr",
     .type = "string",
     .desc = "outer src address of icmp reply packet"},
    {.name = "classification",
     .type = "string",
     .desc = "probe module classification"},
    {.name = "success",
     .type = "int",
     .desc = "did probe module classify response as success"}};

probe_module_t module_gretap6_multicast = {
    .name = "gretap6_multicast",
    .max_packet_length = sizeof(struct ether_header)*2 + sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(gre_header_t) +
		     sizeof(struct icmp6_hdr),
    .pcap_filter = "icmp6",
    .pcap_snaplen = 1500,
    .port_args = 0,
    .thread_initialize = &gretap6_multicast_init_perthread,
    .global_initialize = &gretap6_multicast_global_initialize,
    .make_packet = &gretap6_multicast_make_packet,
    .print_packet = &gretap6_multicast_print_packet,
    .validate_packet = &gretap6_multicast_validate_packet,
    .process_packet = &gretap6_multicast_process_packet,
    .close = NULL,
    .fields = fields,
    .numfields = 8};
