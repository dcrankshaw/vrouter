/**********************************************************************
 * Group name: jhugroup1
 * Members: Daniel Crankshaw, Maddie Stone, Adam Gross
 * CS344
 * 4/01/2011
 **********************************************************************/

#ifndef BUFFER_H
#define BUFFER_H


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp.h"


struct packet_buffer
{
	uint8_t* packet;            /*Packet that wants to be forwarded. */
	uint16_t pack_len;
	char *interface;            /*Interface to send packet out of. */
	uint8_t* arp_req;           /*ARP Request sent for this packet. */
	uint16_t arp_len;
	struct in_addr ip_dst;      /* Ultimate Destination IP Address */
	struct packet_buffer *next;
	int num_arp_reqs; 	        /* The number of arp requests already sent. */
	uint32_t gw_IP;             /* IP address where packet will be sent to. (Next hop based on interface). */
	struct sr_ethernet_hdr* old_eth; /*Original ethernet header*/
};


void update_buffer(struct packet_state*,struct packet_buffer*);
struct packet_buffer *buf_packet(struct packet_state *, uint8_t*, const struct in_addr, 
                                    const struct sr_if*, struct sr_ethernet_hdr*);
struct packet_buffer* delete_from_buffer(struct packet_state*, struct packet_buffer*);

#endif