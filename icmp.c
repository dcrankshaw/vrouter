/**********************************************************************
 * Group name: jhugroup1
 * Members: Daniel Crankshaw, Maddie Stone, Adam Gross
 * CS344
 * 4/01/2011
 * 
 * Description:
 * This file handles all ICMP functionality. It's functions are called
 * functions in sr_router.c and arp.c.
 *
 **********************************************************************/




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


/**********************************************************************
 * METHOD: icmp_response(struct packet_state *ps, struct ip *ip_hdr,
 *						 unsigned int type, unsigned int code)
 * 
 * Called when we receive an ICMP packet. If it is an echo request, we
 * create an echo response to send back. Otherwise, we send an ICMP
 * port unreachable error (similar to the response to a TCP or UDP
 * packet being directed at one of the router's interfaces).
 * 
 *********************************************************************/

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
			icmp_response(ps, ip_hdr, ICMPT_DESTUN, ICMPC_PORTUN);
		}
	}
}

/**********************************************************************
 * METHOD: icmp_response(struct packet_state *ps, struct ip *ip_hdr,
 *						 unsigned int type, unsigned int code)
 * 
 * Used to construct ICMP packets, given a type and code.
 * 
 *********************************************************************/

void icmp_response(struct packet_state *ps, struct ip *ip_hdr, unsigned int type, unsigned int code)
{
	
	struct icmp_hdr *res_head = NULL;
	struct icmp_hdr* orig = (struct icmp_hdr *) ps->packet;
	int len = 0;
	switch(type)
	{
		case ICMPT_ECHOREPLY:
			res_head = create_icmp_hdr(ps, type, code);
			res_head->opt1 = orig->opt1;
			res_head->opt2 = orig->opt2;
			copy_echo_data(ps);
			len = ps->res_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
			res_head->icmp_sum = 0;
			res_head->icmp_sum = ntohs(cksum((uint8_t *) res_head, len));
			
			
			break;

		case ICMPT_DESTUN:
			res_head = create_icmp_hdr(ps, type, code);
			create_icmp_data(ps, ip_hdr);
			len = ps->res_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
			res_head->icmp_sum = 0;
			res_head->icmp_sum = ntohs(cksum((uint8_t *)res_head, len));
			break;

		case ICMPT_TIMEEX:
			res_head = create_icmp_hdr(ps, type, code);
			create_icmp_data(ps, ip_hdr);
			len = ps->res_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
			res_head->icmp_sum = 0;
			res_head->icmp_sum = ntohs(cksum((uint8_t *) res_head, len));
			break;

		case ICMPT_TRACERT:
			printf("Traceroute ICMP message response is unimplemented at this time\n");
			break;

		default:
			printf("ICMP type %d is unimplemented at this time\n", type);
			break;
	}

}

/**********************************************************************
 * METHOD: create_icmp_data(struct packet_state *ps, struct ip* ip_hdr)
 * 
 * Called when sending an ICMP error message.
 * Used to copy the IP header and first 8 bytes of packet causing the error
 * into the ICMP error message data portion of the packet.
 * 
 *********************************************************************/
 
 
void create_icmp_data(struct packet_state *ps, struct ip* ip_hdr)
{
	if(memcpy(ps->response, ip_hdr, sizeof(struct ip)) == 0)
	{
		/*ERROR CHECKING*/
		printf("memcpy error\n");
	}
	ps->res_len += sizeof(struct ip);
	ps->response += sizeof(struct ip);
	if(ps->len < ICMP_DATA_RES)
	{
		if(memcpy(ps->response, ps->packet, ps->len) == 0)
		{
			/*ERROR CHECKING*/
			printf("memcpy error\n");
		}
		ps->res_len += ps->len;
		ps->response += ps->len;
	}	
	else
	{
		if(memcpy(ps->response, ps->packet, ICMP_DATA_RES) == 0)
		{
			printf("memcpy error\n");
		}
		ps->res_len += ICMP_DATA_RES;
		ps->response += ICMP_DATA_RES;
	}
}

/* Called when router receives an ICMP echo request.
 * Used to copy the payload data from the request into the reply */
void copy_echo_data(struct packet_state *ps)
{
	ps->len -= sizeof(struct icmp_hdr);
	ps->packet += sizeof(struct icmp_hdr);
	ps->res_len += ps->len;
	if(memcpy(ps->response, ps->packet, ps->len) == 0)
	{
		printf("memcpy error\n");
	}
}

/* Construct an ICMP header with the given type and code */
struct icmp_hdr* create_icmp_hdr(struct packet_state *ps, unsigned int type, unsigned int code)
{
	struct icmp_hdr *res_head = (struct icmp_hdr *)ps->response;
	res_head->icmp_type = type;
	res_head->icmp_code = code;
	res_head->icmp_sum = 0; /* not filled in until checksum is calculate */
	res_head->opt1 = 0;
	res_head->opt2 = 0;
	ps->res_len += sizeof(struct icmp_hdr);
	ps->response += sizeof(struct icmp_hdr);
	res_head->icmp_sum = 0;
	return res_head;
}
