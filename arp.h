/****** Header file for ARP functions 
 */
#ifndef ARP_H
#define ARP_H

#include <time.h>

#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

struct arp_cache_entry
{
uint32_t ip_add; 
unsigned char mac[ETHER_ADDR_LEN];
time_t timenotvalid; /*The time when this entry is no longer valid*/
struct arp_cache_entry* next;
};


void handle_arp(struct packet_state*);
void got_Request(struct packet_state*, struct sr_arphdr *);
void add_cache_entry(struct packet_state*, uint32_t, const unsigned char*);
void print_cache_entry(struct arp_cache_entry*);


#endif


