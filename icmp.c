
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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "icmp.h"

void handle_icmp(struct sr_instance *sr,
				uint8_t *packet,
				unsigned int len,
				char *interface,
				struct ip *ip_hdr)
{
	int icmp_offset = size(struct icmp_hdr);
	if(len < icmp_offset)
	{
		printf("improperly formatted icmp packet\n");
	}
	else
	{
	
		struct icmp_hdr *icmp = (struct icmp_hdr *)packet;
		uint8_t *data = packet + icmp_offset;
		len -= icmp_offset;
		if(icmp->icmp_type == ICMPT_ECHOREQUEST)
		{
			icmp_response(len, ip_hdr, ICMPT_ECHOREPLY, ICMPT_ECHOREPLY);
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
		and then return the length of the packet.

void icmp_response(unsigned int len, uint8_t *packet, struct ip *ip_hdr, unsigned int type, unsigned int code)
{

	uint8_t *response = 0;
	struct icmp_hdr *res_head;
	response = (uint8_t *)malloc(sizeof(icmp_hdr) + 2*(sizeof(uint16_t)));
	res_head = (icmp_hdr *)response;
	res_head->icmp_type = type;
	res_head->icmp_code = code;
	res_head->icmp_sum = 0; /* not filled in until checksum is calculate */
	switch(type)
	{
		case ICMPT_ECHOREPLY:
			response = (uint8_t *)malloc(sizeof(icmp_hdr));
			res_head = (icmp_hdr *)response;
			res_head->icmp_type = type;
			res_head->icmp_code = code;
			res_head->icmp_sum = 0; /* not filled in until checksum is calculate */
			res_head->opt1 = 0;
			res_head->opt2 = 0;
			
			
			
			break;
		
		case ICMPT_DESTUN:
			response = (uint8_t *)malloc(sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) +
										ICMP_DATA_RES*sizeof(uint8_t));
			res_head = (icmp_hdr *)response;
			res_head->icmp_type = type;
			res_head->icmp_code = code;
			res_head->icmp_sum = 0; /* not filled in until checksum is calculated */
			res_head->opt1 = 0;
			res_head->opt2 = 0;
			uint8_t *pointer = response + sizeof(struct icmp_hdr);
			pointer = ip_hdr;
			uint16t_temp = ip_hdr->ip_src;
			ip_hdr->ip_src = ip_hdr->ip_dst;
			ip_hdr->ip_dst = temp;
			pointer += sizeof(struct ip_hdr);
			if(len < ICMP_DATA_RES)
				memcpy(pointer, packet, len);	
			else
				memcpy(pointer, packet, ICMP_DATA_RES);
			
			break;
		
		case ICMPT_TIMEEX:
			response = (uint8_t *)malloc(sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) +
										ICMP_DATA_RES*sizeof(uint8_t));
			res_head = (icmp_hdr *)response;
			res_head->icmp_type = type;
			res_head->icmp_code = code;
			res_head->icmp_sum = 0; /* not filled in until checksum is calculated */
			res_head->opt1 = 0;
			res_head->opt2 = 0;
			uint8_t *pointer = response + sizeof(struct icmp_hdr);
			pointer = ip_hdr;
			uint16t_temp = ip_hdr->ip_src;
			ip_hdr->ip_src = ip_hdr->ip_dst;
			ip_hdr->ip_dst = temp;
			pointer += sizeof(struct ip_hdr);
			if(len < ICMP_DATA_RES)
				memcpy(pointer, packet, len);	
			else
				memcpy(pointer, packet, ICMP_DATA_RES);
			
			break;
		
		case ICMPT_TRACERT:
			printf("Traceroute ICMP message response is unimplemented at this time");
			break;
		
		default:
			printf("ICMP type %d is unimplemented at this time", type);
	}
	
	printf("icmp_response() currently unimplemented");
}