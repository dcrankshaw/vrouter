
/*-------------------------------------------------------------
*
*Method:
*Handle recieved ICMP packets
ICMP Functionality:
-traceroutes through and to router
-Can respond to ICMP echo requests
-
*
*
*-------------------------------------------------------------*/

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "icmp.h"

void handle_icmp(struct packet_state *ps, struct ip *ip_hdr)
{
	int icmp_offset = sizeof(struct icmp_hdr);
	if(ps->len < icmp_offset)
	{
		printf("improperly formatted icmp packet\n");
	}
	else
	{
		struct icmp_hdr *icmp = (struct icmp_hdr *)ps->packet;
		if(icmp->icmp_type == ICMPT_ECHOREQUEST)
		{
			icmp_response(ps, ip_hdr, ICMPT_ECHOREPLY, ICMPT_ECHOREPLY);
			/* the icmp code and type are the same for an echo reply */
		}
		else
		{
			printf("router not configured to handle icmp type: %u\n", icmp->icmp_type);
		}
	}
}

/* TODO: packets are built (including IP header), need to figure out what to do with them now
		I'm worried about memory allocation issues
		Possible fix is to pass in header to already allocated memory (max packet size maybe)
		and then return the length of the packet. */
		
		/*
		   -Change appropriate fields in the IP header */

void icmp_response(struct packet_state *ps, struct ip *ip_hdr, unsigned int type, unsigned int code)
{

	switch(type)
	{
		case ICMPT_ECHOREPLY:
			create_icmp_hdr(ps, type, code);
			break;
		
		case ICMPT_DESTUN:
			create_icmp_hdr(ps, type, code);
			create_icmp_data(ps, ip_hdr);
			break;
		
		case ICMPT_TIMEEX:
			create_icmp_hdr(ps, type, code);
			create_icmp_data(ps, ip_hdr);
			break;
		
		case ICMPT_TRACERT:
			printf("Traceroute ICMP message response is unimplemented at this time");
			break;
		
		default:
			printf("ICMP type %d is unimplemented at this time", type);
			break;
	}
	
	printf("icmp_response() currently unimplemented");
}

void create_icmp_data(struct packet_state *ps, struct ip* ip_hdr)
{
	memcpy(ps->response, ip_hdr, sizeof(struct ip));
	ps->res_len += sizeof(struct ip);
	ps->response += sizeof(struct ip);
	if(ps->len < ICMP_DATA_RES)
	{
		memcpy(ps->response, ps->packet, ps->len);
		ps->res_len += ps->len;
		ps->response += ps->len;
	}	
	else
	{
		memcpy(ps->response, ps->packet, ICMP_DATA_RES);
		ps->res_len += ICMP_DATA_RES;
		ps->response += ICMP_DATA_RES;
	}
}

void create_icmp_hdr(struct packet_state *ps, unsigned int type, unsigned int code)
{
	struct icmp_hdr *res_head = (struct icmp_hdr *)ps->response;
	res_head->icmp_type = type;
	res_head->icmp_code = code;
	res_head->icmp_sum = 0; /* not filled in until checksum is calculate */
	res_head->opt1 = 0;
	res_head->opt2 = 0;
	ps->res_len += sizeof(struct icmp_hdr);
	ps->response += sizeof(struct icmp_hdr);
	/* comp_checksum(); */
}