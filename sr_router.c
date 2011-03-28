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
#include <unistd.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "icmp.h"
#include "arp.h"

struct packet_buffer* queue;
struct flow_control *flow_tbl; /*Here or in init??*/


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
	sr->arp_cache=0;
	queue=0;
	flow_tbl=0;

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
	current.rt_entry = 0;
	current.interface = interface;
	current.response = (uint8_t *)malloc(MAX_PAC_LENGTH);
	if(current.response == NULL)
	{
		printf("Out of memory");

	}
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
		leave_hdr_room(&current, eth_offset);

		switch(ntohs(eth->ether_type))
		{
			case (ETHERTYPE_IP):
				handle_ip(&current);
				printf("GOT an IP packet");
				break;

			case (ETHERTYPE_ARP):
				handle_ARP(&current, eth);
				printf("Got an ARP packet");
				break;
			default:
				printf("%x", eth->ether_type);
		}
	}

	char *out_iface = (char *)malloc(IF_LEN +1); /*plus 1 for null termination*/

	if(create_eth_hdr(head, &current, out_iface) > 0)
	{
		sr_send_packet(sr, head, current.res_len, out_iface);
	}
	free(out_iface);

	free(head);
    

}/* end sr_ForwardPacket */

int create_eth_hdr(uint8_t *newpacket, struct packet_state *ps, char *iface)
{

	/*check ARP cache to see if the MAC address for the outgoing IP address is there*/
	/* if not present, sleep(5), check again. Repeat 5 times, then send ICMP
		host unreachable message */

	/* This method must also figure out the interface to send the packet out of */


	/*when buffering packet, memmove() the packet to the buffer, then maddie can use the
	response field in packet_state to build her arp_request*/
	printf("Ethernet header creation unimplemented at this time");
	return -1;
}

int handle_ip(struct packet_state *ps)
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
			/*ps->packet = ps->packet + (ip_hdr->ip_len - sizeof(struct ip));*/
			printf("IP packet has options and has been dropped\n");
		}
		int ip_offset = sizeof(struct ip);
		
		char *if0 = "eth0";
		char *if1 = "eth1";
		char *if2 = "eth2";
		
		struct in_addr ipdst_host_order;
		ipdst_host_order.s_addr = ntohl(ip_hdr->ip_dst.s_addr);
		get_routing_if(ps, ipdst_host_order);
		
		/*TODO: make sure interface matching incoming interface ???*/

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
					
					
					if(strcmp(ps->interface, if0) == 0)
					{
						if(strcmp(&iface->name[0], if1) == 0 || strcmp(&iface->name[0], if2) == 0)
						{ return -1; /* Dropped packet */ }
					}
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
					// ip_hdr->ip_ttl = INI_TTL; /*WHAT IS INI_TTL AND WHERE DEFINED?*/
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
			/*check if interface==eth0*/
			
			if(strcmp(ps->interface, if0) == 0)
			{
				if(strcmp(&ps->rt_entry->interface[0], if1) == 0 
					|| strcmp(&ps->rt_entry->interface[0], if2) == 0)
				{
					leave_hdr_room(ps, ip_offset);
					/*need at least 4 bytes for the dest and source ports */
					if(ip_hdr->ip_p == IPPROTO_ICMP)
					{
						if(ft_contains(ps->sr, ntohl(ip_hdr->ip_src.s_addr),
							ntohl(ip_hdr->ip_dst.s_addr), ip_hdr->ip_p, 0, 0) == 0)
							/*send 0 if it's an ICMP packet because they don't 
							have port numbers */
						{ return 0; }
					}
					else if(ip_hdr->ip_p == IPPROTO_TCP 
						||ip_hdr->ip_p == IPPROTO_UDP)
					{
						if(ps->len >= 4)	/* Need at least 4 bytes for the 2 port numbers */
						{
							uint16_t src_port = 0;
							memmove(&src_port, ps->packet, 2);
							uint16_t dst_port = 0;
							memmove(&dst_port, (ps->packet + 2), 2);
							if(ft_contains(ps->sr, ntohl(ip_hdr->ip_src.s_addr),
							ntohl(ip_hdr->ip_dst.s_addr), ip_hdr->ip_p, src_port, dst_port) == 0)
							{ return 0; }
						}
						else { return 0; }
					}
					else { return 0; }
					
				}
			}
			else
			{
				if(ip_hdr->ip_p == IPPROTO_ICMP)
					{
						if(sr_add_ft_entry(ps->sr, ntohl(ip_hdr->ip_src.s_addr),
							ntohl(ip_hdr->ip_dst.s_addr), ip_hdr->ip_p, 0, 0) == 0)
						{ return 0; }
						if(sr_add_ft_entry(ps->sr, ntohl(ip_hdr->ip_dst.s_addr),
							ntohl(ip_hdr->ip_src.s_addr),ip_hdr->ip_p, 0, 0) == 0)
						{ return 0; }
					}
					else if(ip_hdr->ip_p == IPPROTO_TCP 
						|| ip_hdr->ip_p == IPPROTO_UDP)
					{
						if(ps->len >= 4)	/* Need at least 4 bytes for the 2 port numbers */
						{
							uint16_t src_port = 0;
							memmove(&src_port, ps->packet, 2);
							uint16_t dst_port = 0;
							memmove(&dst_port, (ps->packet + 2), 2);
							if(sr_add_ft_entry(ps->sr, ntohl(ip_hdr->ip_src.s_addr),
								ntohl(ip_hdr->ip_dst.s_addr), ip_hdr->ip_p, src_port, dst_port) == 0)
							{ return 0; }
							if(sr_add_ft_entry(ps->sr, ntohl(ip_hdr->ip_dst.s_addr),
								ntohl(ip_hdr->ip_src.s_addr), ip_hdr->ip_p, src_port, dst_port) == 0)
							{ return 0; }
							
						}
						else { return 0; }
					}
					else { return 0; }
			}
			
				if(ip_hdr->ip_ttl < 1)
				{
					/*packet expired*/
					icmp_response(ps, ip_hdr, ICMPT_TIMEEX, ICMPC_INTRANSIT);
				}
				else /* FORWARD */
				{
					update_ip_hdr(ip_hdr);
				}
			}
		}
	return 1;
}

void leave_hdr_room(struct packet_state *ps, int hdr_size)
{
	ps->packet += hdr_size;
	ps->len -= hdr_size;
	ps->response += hdr_size;
	//ps->res_len += hdr_size; 	/*I DON'T THINK WE WANT TO DO THIS*/
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
void get_routing_if(struct packet_state *ps, struct in_addr ip_dst)
{
	struct sr_rt *current = ps->sr->routing_table;
	struct in_addr min_mask;
	min_mask.s_addr = -1;
	/*Iterate through routing table linked list*/
	while(current != NULL)
	{
		/*If the bitwise AND of current ip and sought ip is greater than the current mask*/
		if((current->mask.s_addr & ip_dst.s_addr) == current->dest.s_addr)
		{
			/*And if this is the closest fitting match so far
				***To make sure that internally destinations that fit a mask better than 0.0.0.0
				get to the right place****/
			if(min_mask.s_addr <= current->mask.s_addr)
			{
				/*update the best fitting mask to the current one, and point found to current*/
				ps->rt_entry=current;
				min_mask=ps->rt_entry->mask;
			}
		}
		current = current->next;
	}
}

/*Temporary implementations of firewall functions for the compiler */
int ft_contains(struct sr_instance *a, uint32_t b, uint32_t c, uint8_t d, uint8_t f, uint8_t e)
{
	return -1;
}
int sr_add_ft_entry(struct sr_instance *a, uint32_t b, uint32_t c, uint8_t d, uint8_t e, uint8_t f)
{
	return -1;
}


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
