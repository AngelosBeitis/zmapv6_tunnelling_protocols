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

probe_module_t module_6in4_mapped;

int sixIn4_mapped_global_initialize(struct state_conf *conf)
{
	if(!zconf.external_address_v6){
		log_error("6in4_mapped", "External IPv6 address was not given. Add --external-ipv6-address");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int sixIn4_mapped_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				     UNUSED port_h_t dst_port,
				     UNUSED void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	uint16_t payload_len = htons(
	    sizeof(struct ip) + sizeof(struct ip6_hdr) +
	    sizeof(struct icmp6_hdr) + 2 * sizeof(uint32_t) + INET_ADDRSTRLEN);
	make_ip_header(ip_header, IPPROTO_IPV6, payload_len);

	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&ip_header[1]);
	// ICMPv6 header plus 8 bytes of data (validation)
	payload_len =
	    sizeof(struct icmp6_hdr) + 2 * sizeof(uint32_t) + INET_ADDRSTRLEN;
	make_ip6_header(ip6_header, IPPROTO_ICMPV6, payload_len);

	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);
	make_icmp6_header(icmp6_header, ICMP6_ECHO_REPLY);

	char *payload = (char *)(&icmp6_header);

	return EXIT_SUCCESS;
}

static int sixIn4_mapped_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
				  ipaddr_n_t dst_ip, uint8_t ttl,
				  uint32_t *validation, UNUSED int probe_num,
				  UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&ip_header[1]);
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(&ip6_header[1]);
	char *payload = (char *)(&icmp6_header[1]);

	uint16_t icmp_idnum = validation[2] & 0xFFFF;

	// Include validation in ICMPv6 payload data
	icmp6_header->icmp6_data32[1] = validation[0];
	icmp6_header->icmp6_data32[2] = validation[1];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	ip6_header->ip6_dst = ((struct in6_addr *)arg)[0]; // External IPv6 address
	four_to_six(dst_ip, &ip6_header->ip6_src);

	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	icmp6_header->icmp6_id = icmp_idnum;
	icmp6_header->icmp6_seq = 10;
	icmp6_header->icmp6_cksum = 0;

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	inet_ntop(AF_INET, &ip_header->ip_dst.s_addr, payload, INET_ADDRSTRLEN);
	icmp6_header->icmp6_cksum = ipv6_payload_checksum(
	    sizeof(struct icmp6_hdr) + 2 * sizeof(uint32_t) + INET_ADDRSTRLEN,
	    &ip6_header->ip6_src, &ip6_header->ip6_dst,
	    (unsigned short *)icmp6_header, IPPROTO_ICMPV6);

	// 8 bytes of data are used in ICMPv6 for validation

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
		   sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
		   2 * sizeof(uint32_t) + INET_ADDRSTRLEN;

	return EXIT_SUCCESS;
}

static void sixIn4_mapped_print_packet(FILE *fp, void *packet)
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

static int sixIn4_mapped_validate_packet(const struct ip *ip_hdr, uint32_t len,
				      __attribute__((unused)) uint32_t *src_ip,
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
	if (icmp6_h->icmp6_seq != 10)
	{
		return PACKET_INVALID;
	}
	

	return PACKET_VALID;
}

static void sixIn4_mapped_process_packet(const u_char *packet,
				      __attribute__((unused)) uint32_t len,
				      fieldset_t *fs,
				      __attribute__((unused))
				      uint32_t *validation)
{
	struct ip6_hdr *ip6_hdr =
	    (struct ip6_hdr *)&packet[sizeof(struct ether_header)];
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(&ip6_hdr[1]);
	struct ip6_hdr *ip6_inner_hdr = (struct ip6_hdr *)&icmp6_hdr[1];

	fs_add_uint64(fs, "type", icmp6_hdr->icmp6_type);
	fs_add_uint64(fs, "code", icmp6_hdr->icmp6_code);
	fs_add_uint64(fs, "icmp-id", ntohs(icmp6_hdr->icmp6_id));
	fs_add_uint64(fs, "seq", ntohs(icmp6_hdr->icmp6_seq));
	fs_add_string(fs, "outersaddr", make_ipv6_str(&(ip6_hdr->ip6_src)), 1);
	fs_modify_string(fs, "saddr", make_ipv6_str(&(ip6_hdr->ip6_src)), 1);
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

probe_module_t module_6in4_mapped = {
    .name = "6in4_mapped",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
			 sizeof(struct ip6_hdr) + ICMP_MINLEN + INET_ADDRSTRLEN,
    .pcap_filter = "icmp6",
    "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1 || ip6[40] == 2 || ip6[40] == 4)", // and icmp6[0]=!8",
    .pcap_snaplen =
	118, // 14 ethernet header + 40 IPv6 header + 8 ICMPv6 header + 40 inner IPv6 header + 8 inner ICMPv6 header + 8 payload
    .port_args = 0,
    .global_initialize = &sixIn4_mapped_global_initialize,
    .thread_initialize = &sixIn4_mapped_init_perthread,
    .make_packet = &sixIn4_mapped_make_packet,
    .print_packet = &sixIn4_mapped_print_packet,
    .process_packet = &sixIn4_mapped_process_packet,
    .validate_packet = &sixIn4_mapped_validate_packet,
    .close = NULL,
    .fields = fields,
    .numfields = 7};