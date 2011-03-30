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
	uint8_t* packet;
	uint16_t pack_len;
	char *interface;
	uint8_t* arp_req;
	uint16_t arp_len;
	struct in_addr ip_dst;
	time_t entry_time; /* the time at which the last ARP request for this packet 
							was sent, fill with time(NULL) */
	struct packet_buffer *next;
	int num_arp_reqs; 	/* The number of arp requests already sent. */
};


void update_buffer(struct packet_state*,struct packet_buffer*);
struct packet_buffer *buf_packet(struct packet_state *, uint8_t*, const struct in_addr, const struct sr_if*);
struct packet_buffer* search_buffer(struct packet_state*,const uint32_t );

#endif