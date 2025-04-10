/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

// Needed for asprintf
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

probe_module_t module_6in4_multicast;

int sixin4_multicast_global_initialize(struct state_conf *conf)
{
	if (!zconf.external_address_v6 || !zconf.spoofing_address_v6) {
		log_error(
		    "6in4",
		    "External IPv6 address and/or spoofing address were not given. Add --external-ipv6-address and --spoofing-address-v6");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int sixin4_multicast_init_perthread(void *buf, macaddr_t *src,
					   macaddr_t *gw,
					   UNUSED port_h_t dst_port,
					   UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	uint16_t payload_len =
	    htons(sizeof(struct ip) + sizeof(struct ip6_hdr) +
		  sizeof(struct icmp6_hdr));
	make_ip_header(ip_header, IPPROTO_IPV6, payload_len);

	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&ip_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	payload_len = sizeof(struct icmp6_hdr);
	make_ip6_header(ip6_header, IPPROTO_ICMPV6, payload_len);

	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);
	make_icmp6_header(icmp6_header, ICMP6_ECHO_REQUEST);

	return EXIT_SUCCESS;
}

static int sixin4_multicast_make_packet(void *buf, size_t *buf_len,
					ipaddr_n_t src_ip,
					UNUSED ipaddr_n_t dst_ip, uint8_t ttl,
					uint32_t *validation,
					UNUSED int probe_num, void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&ip_header[1]);
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);

	// Include validation in ICMPv6 payload data

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	icmp6_header->icmp6_data32[1] =
	    (ip_header->ip_src.s_addr << 16) & 0xFFFF;
	icmp6_header->icmp6_data32[2] = ip_header->ip_src.s_addr & 0xFFFF;

	ip6_header->ip6_src =
	    ((struct in6_addr *)arg)[1]; // External IPv6 address
	ip6_header->ip6_dst =
	    ((struct in6_addr *)arg)[0]; //multicast IPv6 address ff02::1

	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 2;

	icmp6_header->icmp6_cksum = 0;

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	icmp6_header->icmp6_seq = (ip_header->ip_dst.s_addr >> 16) & 0xFFFF;
	icmp6_header->icmp6_id = (ip_header->ip_dst.s_addr & 0xFFFF);

	icmp6_header->icmp6_cksum = ipv6_payload_checksum(
	    sizeof(struct icmp6_hdr), &ip6_header->ip6_src,
	    &ip6_header->ip6_dst, (unsigned short *)icmp6_header,
	    IPPROTO_ICMPV6);

	// 8 bytes of data are used in ICMPv6 for validation

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
		   sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);

	return EXIT_SUCCESS;
}

static void sixin4_multicast_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip6_hdr *iph = (struct ip6_hdr *)&ethh[1];
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&iph[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp6_header->icmp6_type, icmp6_header->icmp6_code,
		ntohs(icmp6_header->icmp6_cksum), ntohs(icmp6_header->icmp6_id),
		ntohs(icmp6_header->icmp6_seq));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int sixin4_multicast_validate_packet(const struct ip *ip_hdr,
					    uint32_t len,
					    __attribute__((unused))
					    uint32_t *src_ip,
					    uint32_t *validation)
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

	//Validate based on data
	if ((icmp6_h->icmp6_data32[1] != (ip_hdr->ip_dst.s_addr >> 16) &
		0xFFFF) ||
	    (icmp6_h->icmp6_data32[2] != ip_hdr->ip_dst.s_addr & 0xFFFF))
		{
			return PACKET_INVALID;
		}

		return PACKET_VALID;
}

static void sixin4_multicast_process_packet(
    const u_char *packet, __attribute__((unused)) uint32_t len, fieldset_t *fs,
    __attribute__((unused)) uint32_t *validation)
{
	struct ip6_hdr *ip6_hdr =
	    (struct ip6_hdr *)&packet[sizeof(struct ether_header)];
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(&ip6_hdr[1]);
	struct ip6_hdr *ip6_inner_hdr = (struct ip6_hdr *)&icmp6_hdr[1];

	uint32_t address = ((uint32_t)icmp6_hdr->icmp6_seq << 16 | icmp6_hdr->icmp6_id);
	fs_add_uint64(fs, "type", icmp6_hdr->icmp6_type);
	fs_add_string(fs, "actual_src", make_ip_str(address), 1);
	fs_add_uint64(fs, "code", icmp6_hdr->icmp6_code);
	fs_add_uint64(fs, "icmp-id", ntohs(icmp6_hdr->icmp6_id));
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

static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
	{.name = "actual_src",
		.type = "string",
		.desc = "the actual source address embedded in the reply"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp-id", .type = "int", .desc = "icmp id number"},
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

probe_module_t module_6in4_multicast = {
    .name = "6in4_multicast",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
			 sizeof(struct ip6_hdr) + ICMP_MINLEN,
    .pcap_filter = "icmp6",
    "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1 || ip6[40] == 2 || ip6[40] == 4)", // and icmp6[0]=!8",
    .pcap_snaplen =
	118, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
    .port_args = 0,
    .global_initialize = &sixin4_multicast_global_initialize,
    .thread_initialize = &sixin4_multicast_init_perthread,
    .make_packet = &sixin4_multicast_make_packet,
    .print_packet = &sixin4_multicast_print_packet,
    .process_packet = &sixin4_multicast_process_packet,
    .validate_packet = &sixin4_multicast_validate_packet,
    .close = NULL,
    .fields = fields,
    .numfields = 8};