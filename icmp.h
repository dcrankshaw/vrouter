/**********************************************************************
 * Group name: jhugroup1
 * Members: Daniel Crankshaw, Maddie Stone, Adam Gross
 * CS344
 * 4/01/2011
 **********************************************************************/

#ifndef ICMP_H
#define ICMP_H

#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

/* -- icmp.c --*/
void handle_icmp(struct packet_state *, struct ip *);
void icmp_response(struct packet_state *, struct ip *, unsigned int, unsigned int);
struct icmp_hdr* create_icmp_hdr(struct packet_state *, unsigned int, unsigned int);
void create_icmp_data(struct packet_state *, struct ip *);
void copy_echo_data(struct packet_state *);


#endif /*definition of ICMP_H*/