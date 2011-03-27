/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "icmp.h"
#include "arp.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t *packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

/*********************************************************
Careful about memory allocation issues with incrementing packet

***********************************************************/
    printf("\n*** -> Received packet of length %d \n",len);
    
	struct packet_state current;
	current.sr = sr;
	current.packet = packet;
	current.len = len;
	current.interface = interface;
	current.response = (uint8_t *)malloc(MAX_PAC_LENGTH);
	uint8_t *head = current.response; /*keep a pointer to the head of allocated memory */
	current.res_len = MAX_PAC_LENGTH;
    struct sr_ethernet_hdr *eth = 0;
    int eth_offset = sizeof(struct sr_ethernet_hdr);
    
    if(len < eth_offset)
    {
    	printf("Error, malformed packet recieved");
    }
    else
    {
		eth = (struct sr_ethernet_hdr *)packet;
		switch(ntohs(eth->ether_type))
		{
			leave_hdr_room(&current, eth_offset);
			case (ETHERTYPE_IP):
				handle_ip(&current);
				printf("GOT an IP packet");
				break;
			case (ETHERTYPE_ARP):
				handle_ARP(&current);
				printf("Got an ARP packet");
				break;
			default:
				printf("%x", eth->ether_type);
		}
	}
	
	char *out_iface;
	
	if(create_eth_hdr(head, &current, out_iface) > 0)
	{
		sr_send_packet(sr, head, current.res_len, out_iface);
	}
	
	free(head);
    

}/* end sr_ForwardPacket */

int create_eth_hdr(uint8_t *newpacket, struct packet_state *ps, char *iface)
{
	printf("Ethernet header creation unimplemented at this time");
	return -1;

}

void handle_ip(struct packet_state *ps)
{
	/*Load IP header*/
	
	if(ps->len < sizeof(struct ip))
	{
		printf("malformed IP packet");
		/*TODO: send an icmp malformed packet message to 
		the source host from the ethernet header?????*/
	}
	else
	{
		struct ip *ip_hdr = (struct ip *)ps->packet;
		/* indicates IP header has options, which we don't care about */
		if(ip_hdr->ip_len > sizeof(struct ip))
		{
			ps->packet = ps->packet + (ip_hdr->ip_len - sizeof(struct ip));
		}
		int ip_offset = sizeof(struct ip);
		
		
		
		int found_case = 0;	/*used to determine which loops to go into*/
		/*Deals with router as destination*/
		if(!found_case)
		{
			struct sr_if *iface = ps->sr->if_list;
			while(iface != NULL)
			{
				/* TODO: This will need rigorous testing */
				if(iface->ip == ntohl(ip_hdr->ip_dst.s_addr))
				{
					printf("reached sr_router.c, print statement #1");
					found_case = 1;
					uint8_t *iph_start = ps->response; /* mark where the ip header should go */
					leave_hdr_room(ps, ip_offset);
					if(ip_hdr->ip_p == IPPROTO_ICMP)
					{
						handle_icmp(ps, ip_hdr);
						/* TODO: Reconfigure IP header */
					}
					else
					{
						icmp_response(ps, ip_hdr, ICMPT_DESTUN, ICMPC_PORTUN);
					}
					/* TODO: create the IP header */
					ip_hdr->ip_len = htons(ps->response - iph_start);
					ip_hdr->ip_ttl = 64;
					ip_hdr->ip_p = IPPROTO_ICMP;
					struct in_addr temp = ip_hdr->ip_src;
					ip_hdr->ip_src = ip_hdr->ip_dst;
					ip_hdr->ip_dst = temp;
					/*checksum();*/
					break;
				}
				else
				{
					iface = iface->next;
				}
			}
		}
		
		/*Deals with forwarding*/
		if(!found_case)
		{
			struct sr_rt *found = NULL;
			if(ip_hdr->ip_ttl < 1)
			{
				/*packet expired*/
				icmp_response(ps, ip_hdr, ICMPT_TIMEEX, ICMPC_INTRANSIT);
			}
			else /* FORWARD */
			{
				get_routing_if(ps->sr, found, ip_hdr);
				assert(found != NULL);
				update_ip_hdr(ip_hdr);
			}
		}
	}
			
}

void leave_hdr_room(struct packet_state *ps, int hdr_size)
{
	ps->packet += hdr_size;
	ps->len -= hdr_size;
	ps->response += hdr_size;
	ps->res_len += hdr_size;
}

void update_ip_hdr(struct ip *ip_hdr)
{
	ip_hdr->ip_ttl--;
	uint16_t temp = ntohs(ip_hdr->ip_sum);
	temp += -1;
	ip_hdr->ip_sum = htons(temp);
	
	/*The change in ip_ttl was -1 so we subtract 1 (see RFC 1071.2.4). Because it was
	subtraction, there can be no overflow*/
}

/*METHOD: Get the correct entry in the routing table*/
void get_routing_if(struct sr_instance *sr, struct sr_rt *found, struct ip *ip_hdr)
{
	struct sr_rt *current = sr->routing_table;
	struct in_addr min_mask;
	min_mask.s_addr = 0;
	/*Iterate through routing table linked list*/
	while(current != NULL)
	{
		/*If the bitwise AND of current ip and sought ip is greater than the current mask*/
		if((current->dest.s_addr & ntohl(ip_hdr->ip_dst.s_addr)) >= current->mask.s_addr)
		{
			/*And if this is the closest fitting match so far
				***To make sure that internally destinations that fit a mask better than 0.0.0.0
				get to the right place****/
			if(min_mask.s_addr <= current->mask.s_addr)
			{
				/*update the best fitting mask to the current one, and point found to current*/
				found = current;
				min_mask = found->mask;
			}
		}
		current = current->next;
	}
}


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
