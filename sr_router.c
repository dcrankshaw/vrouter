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
    
    struct sr_ethernet_hdr *eth = 0;
    int eth_offset = sizeof(struct sr_ethernet_hdr);
    
    if(len < eth_offset)
    {
    	printf("Error, malformed packet recieved");
    }
    else
    {
		eth = (struct sr_ethernet_hdr *)packet;
		
	   
		uint16_t temp = *front++;
		temp = temp*256 + *front++;
		eth->ether_type = temp;*/
		
		switch(eth->ether_type)
		{
			case htons(ETHERTYPE_IP):
				handle_ip(sr, packet + eth_offset, len - eth_offset, interface);
				printf("GOT an IP packet");
				break;
			case htons(ETHERTYPE_ARP):
				/*handle_ARP();*/
				printf("Got an ARP packet");
				break;
			default:
				printf("%x", eth->ether_type);
		}
	}
    

}/* end sr_ForwardPacket */


struct ip* load_ip_hdr(uint8_t *packet)
{
	struct ip *ip_hdr = (struct ip *)malloc(sizeof(struct ip));
	
	ip_hdr->ip_v = (*packet)/16; /*assign 4 MSB of 1st byte to version*/
	
	ip_hdr->ip_hl = *packet++;
	
	ip_hdr->ip_tos = *packet++;
	
	ip_hdr->ip_len = *packet++;
	ip_hdr->ip_len = (ip_hdr->ip_len)*256 + *packet++;
	ip_hdr->ip_len = ntohs(ip_hdr->ip_len);
	
	ip_hdr->ip_id = *packet++;
	ip_hdr->ip_id = (ip_hdr->ip_id)*256 + *packet++;
	ip_hdr->ip_id = ntohs(ip_hdr->ip_id);
	
	ip_hdr->ip_id = *packet++;
	ip_hdr->ip_id = (ip_hdr->ip_id)*256 + *packet++;
	ip_hdr->ip_id = ntohs(ip_hdr->ip_id);
	
	ip_hdr->ip_off = *packet++;
	ip_hdr->ip_off = (ip_hdr->ip_off)*256 + *packet++;
	ip_hdr->ip_off = ntohs(ip_hdr->ip_off);
	
	ip_hdr->ip_ttl = *packet++;
	
	ip_hdr->ip_p = *packet++;
	
	ip_hdr->ip_sum = *packet++;
	ip_hdr->ip_sum = (ip_hdr->ip_sum)*256 + *packet++;
	ip_hdr->ip_sum = ntohs(ip_hdr->ip_sum);
	
	/*Merge four bytes into one in_addr_t integer (really a 32 bit unsigned integer
	representing an IP address in NETWORK byte order)*/
	ip_hdr->ip_src.s_addr = *packet++;
	int i;
	for(i = 1; i < 4; i++)
	{
		ip_hdr->ip_src.s_addr = (ip_hdr->ip_src.s_addr)*256 + *packet++;
	}
	
	ip_hdr->ip_dst.s_addr = *packet++;
	for(i = 1; i < 4; i++)
	{
		ip_hdr->ip_dst.s_addr = (ip_hdr->ip_dst.s_addr)*256 + *packet++;
	}
	
	return ip_hdr;
}

void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
	/*Load IP header*/
	struct ip *ip_hdr = load_ip_hdr(packet);
	
	/*End IP header*/
	
	
	int found_case = 0;	/*used to determine which loops to go into*/
	/*Deals with router as destination*/
	if(!found_case)
	{
		struct sr_if *iface = sr->if_list;
		while(iface != NULL)
		{
			if(iface->ip == ip_hdr->ip_dst.s_addr)
			{
				found_case = 1;
				if(ip_hdr->ip_p == IPPROTO_ICMP)
					handle_icmp(sr, packet, len, interface, ip_hdr);
				else
					icmp_response(ip_hdr, ICMPT_DESTUN, ICMPC_PORTUN);
			}
			else
				iface = iface->next;
		}
	}
	
	/*Deals with forwarding*/
	if(!found_case)
	{
		struct sr_rt *found = NULL;
		if(ip_hdr->ip_ttl < 1)
		{
			/*packet expired*/
			icmp_response(ip_hdr, ICMPT_TIMEEX, ICMPC_INTRANSIT);
		}
		get_routing_if(sr, found, ip_hdr);
		assert(found != NULL);
		update_ip_hdr(ip_hdr);
	}
			
}

void update_ip_hdr(struct ip *ip_hdr)
{
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum += - 1; /*The change in ip_ttl was -1 so we subtract 1 (see
							RFC 1071.2.4). Because it was subtraction, there can be no
							overflow*/
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
		if((current->dest.s_addr & ip_hdr->ip_dst.s_addr) >= current->mask.s_addr)
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
