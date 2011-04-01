/**********************************************************************
 * Group name: jhugroup1
 * Members: Daniel Crankshaw, Maddie Stone, Adam Gross
 * CS344
 * 4/01/2011
 **********************************************************************/
 
#ifndef ARP_H
#define ARP_H

#include <time.h>

#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

#define ARP_TIMEOUT 15  /*ARP Cache entries are valid for 15 seconds. */

struct arp_cache_entry
{
    uint32_t ip_add; 
    unsigned char mac[ETHER_ADDR_LEN];
    time_t timenotvalid;                /*The time when this entry is no longer valid*/
    struct arp_cache_entry* next;
};


struct arp_cache_entry* handle_ARP(struct packet_state*, struct sr_ethernet_hdr*);
void got_Request(struct packet_state*, struct sr_arphdr*, const struct sr_ethernet_hdr*);
struct arp_cache_entry* got_Reply(struct packet_state *, struct sr_arphdr *);
void add_cache_entry(struct packet_state*,const uint32_t, const unsigned char*);
struct arp_cache_entry* delete_entry(struct packet_state*,struct arp_cache_entry* );
struct arp_cache_entry* search_cache(struct packet_state*,const uint32_t);
struct arp_cache_entry* delete_entry(struct packet_state*,struct arp_cache_entry* );
struct arp_cache_entry* search_cache(struct packet_state*,const uint32_t);
void print_cache_entry(struct arp_cache_entry*);
void print_cache(struct sr_instance*);
void construct_reply(struct packet_state*, const struct sr_arphdr*, const unsigned char*, const struct sr_ethernet_hdr*);
void send_request(struct packet_state*, const uint32_t);
void testing(struct packet_state*, struct sr_arphdr *);

#endif