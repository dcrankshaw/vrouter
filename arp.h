/****** Header file for ARP functions 
 */
#ifndef ARP_H
#define ARP_H


#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

void handle_arp(struct packet_state*);
void got_Request(struct packet_state*, struct sr_arphdr *);




#endif


