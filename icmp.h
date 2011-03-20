#ifndef ICMP_H
#define ICMP_H

#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

/* -- icmp.c --*/
void handle_icmp(struct sr_instance *, uint8_t *, unsigned int, char *, struct ip *);
void icmp_response(struct ip *, unsigned int, unsigned int);


#endif /*definition of ICMP_H*/