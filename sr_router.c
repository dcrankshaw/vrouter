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
 * Group name: jhugroup1
 * Members: Daniel Crankshaw, Maddie Stone, Adam Gross
 * CS344
 * 4/01/2011 
 * This file also contains all the functions that interact with the packet
 * at the IP datagram level.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>


#include "fw.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "icmp.h"
#include "arp.h"
#include "buffer.h"

#define DEF_RULE_TABLE "rules"
#define IFACE_CONFIG	"if_config"

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
	sr->queue=0;
	sr->flow_table = 0;
	sr->rules = 0;
	sr->ft_size = 0;
	sr->exter = 0;
	sr->inter = 0;
	char* rule_config = DEF_RULE_TABLE;
	assert(init_rules_table(sr, rule_config));
	char *if_config = IFACE_CONFIG;
	assert(init_if_config(sr, if_config));
	print_if_config(sr);
	
	
	printf("\n\n");
	print_rule_table(sr);
	printf("\n\n");

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
 * JHUGROUP1:
 * This function now strips off the ethernet header from the packet, decides
 * whether the packet is an IP or ARP request, and passes it to the appropriate
 * handler. It then attempts to create an ethernet header for the packet, and if
 * that is successful, it sends the packet. Finally, it tells the router to update
 * the buffer.
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

    printf("\n*** -> Received packet of length %d \n",len);
    
	struct packet_state current;
	current.sr = sr;
	current.packet = packet;
	current.len = len;
	current.rt_entry = 0;
	current.interface = interface;
	current.forward = 0;
	uint8_t *head = (uint8_t *)malloc(MAX_PAC_LENGTH);
	if(head == NULL)
	{
		printf("Out of memory");
	}
	current.response = head; /*keep a pointer to the head of allocated memory */
	current.res_len = 0;
    struct sr_ethernet_hdr *eth = 0;
    int eth_offset = sizeof(struct sr_ethernet_hdr);
    struct sr_ethernet_hdr *perm_eth = 0;
    
    if(len < eth_offset)
    {
    	printf("Error, malformed packet received");
    }
    else
    {
		perm_eth = (struct sr_ethernet_hdr *)malloc(eth_offset);
		eth = (struct sr_ethernet_hdr *)packet;
		memmove(perm_eth, eth, eth_offset);
		leave_hdr_room(&current, eth_offset);

		switch(ntohs(eth->ether_type))
		{
			case (ETHERTYPE_IP):
			{
				if(handle_ip(&current) != 0)
				{
					if(create_eth_hdr(head, &current, perm_eth) > 0)
					{
						sr_send_packet(sr, head, current.res_len, current.rt_entry->interface);
					}
				}
			}
			break;
			case (ETHERTYPE_ARP):
			{
				struct arp_cache_entry *new_entry = handle_ARP(&current, eth);
				if(new_entry == NULL)
				{
					if(current.res_len >0)
					    sr_send_packet(sr, head, current.res_len, interface);
				}
			}
			break;
			default:
				printf("%x\n", eth->ether_type);
		}
		
	}
    if(head)
	    free(head);
	if(perm_eth)
	    free(perm_eth);
	/* Reset the response packet for updating the packet buffer */    
	current.response = (uint8_t *)malloc(MAX_PAC_LENGTH);
	current.res_len = 0;
	update_buffer(&current, current.sr->queue);
    if(current.response)
	    free(current.response);

    
}

/*---------------------------------------------------------------------
 * Method: int create_eth_hdr(uint8_t *newpacket, struct packet_state *ps, 
 *							struct sr_ethernet_hdr *eth_rec)
 * 
 * This method attempts to create an ethernet header for the packet
 * with the ip header argument provided. If the MAC address we need
 * is in the cache, we create the header. Otherwise we buffer the packet
 * and create an ARP request to get the MAC address.
 *
 *---------------------------------------------------------------------*/
int create_eth_hdr(uint8_t *newpacket, struct packet_state *ps, struct sr_ethernet_hdr *eth_rec)
{

	/*check ARP cache to see if the MAC address for the outgoing IP address is there*/
	
	struct ip *new_iphdr = (struct ip*)(newpacket+sizeof(struct sr_ethernet_hdr));
	struct sr_if *sif = 0;
	if(ps->forward)
	{
		assert(ps->rt_entry);
		sif = sr_get_interface(ps->sr, ps->rt_entry->interface);
	}
	else
	{
		sif = sr_get_interface(ps->sr, ps->interface);
		struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) newpacket;
		memmove(eth->ether_dhost, eth_rec->ether_shost, ETHER_ADDR_LEN);
		memmove(eth->ether_shost, sif->addr, ETHER_ADDR_LEN);
		eth->ether_type = htons(ETHERTYPE_IP);
		return 1;
		
	}
	struct arp_cache_entry *ent = search_cache(ps, ps->rt_entry->gw.s_addr);
	if(ent != NULL)
	{
		struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) newpacket;
		memmove(eth->ether_dhost, ent->mac, ETHER_ADDR_LEN);
		memmove(eth->ether_shost, sif->addr, ETHER_ADDR_LEN);
		eth->ether_type = htons(ETHERTYPE_IP);
		return 1;
	}
	else
	{
		ps->response = newpacket;
		struct packet_buffer* current = buf_packet(ps,newpacket, new_iphdr->ip_dst,sif, eth_rec);
		ps->response = newpacket;
		send_request(ps,new_iphdr->ip_dst.s_addr);
		current->num_arp_reqs=0;
		current->arp_req=(uint8_t*)malloc(ps->res_len);
		assert(current->arp_req);
		memmove(current->arp_req, ps->response, ps->res_len);
		current->arp_len = ps->res_len;
		return 0;
	}
	return 0;
}

/*---------------------------------------------------------------------
 * Method: int handle_ip(struct packet_state *ps)
 * 
 * This is the main method for handling IP packets. After error checking,
 * it enters one of two control blocks, either responding to a packet
 * or forwarding a packet.
 * 
 * If responding (the destination IP address in the IP header matches one
 * of the IP address in the interface list): the router determines whether
 * it is a valid request by asking the firewall, then determines whether it
 * is an ICMP echo request (the only packets the router itself response to).
 * Finally, it either creates the ICMP response packet, or creates an ICMP
 * Port Unreachable ICMP packet, and returns true.
 *
 * If forwarding: The router checks to make sure it is a valid request with the
 * firewall if the source is external, or adds the connection to the firewall
 * valid connections list (i.e. the flow table) if the source is internal. It then
 * updates the IP header and returns true.
 *
 * Note: If at any point the router detects an invalid request from the firewall,
 * handle_ip returns false and the router silently drops the packet.
 *
 *---------------------------------------------------------------------*/
int handle_ip(struct packet_state *ps)
{
	/*Load IP header*/

	if(ps->len < sizeof(struct ip))
	{
		printf("malformed IP packet");
		return 0;
	}
	else
	{
		struct ip *ip_hdr = (struct ip *)ps->packet;
		uint16_t src_port = 0;
		uint16_t dst_port = 0;
		/* indicates IP header has options, which we don't care about */
		if((ip_hdr->ip_hl)*4 > sizeof(struct ip)) /* x 4 because there are 4 bytes per 32 bit word */
		{
			printf("struct length: %zu\npacketlength: %u\n", sizeof(struct ip), ntohs(ip_hdr->ip_len));
			return 0;
		}
		int ip_offset = sizeof(struct ip);
		
		ps->rt_entry = get_routing_if(ps, ip_hdr->ip_dst);
		struct ip *iph = (struct ip*)ps->response; /* mark where the ip header should go */
		

		int found_case = 0;	/*used to determine which loops to go into*/
		
		/*Deals with router as destination*/
		if(!found_case)
		{
			struct sr_if *iface = ps->sr->if_list;
			
			while(iface != NULL)
			{
				if(iface->ip == ip_hdr->ip_dst.s_addr)
				{
					/*verify valid packet with firewall*/
					if(is_external(ps->sr, ps->interface))
					{	
						if(is_internal(ps->sr, iface->name))
						{ 
							if(ip_hdr->ip_p == IPPROTO_ICMP)
							{
								if(check_connection(ps->sr, ip_hdr->ip_src.s_addr,
								ip_hdr->ip_dst.s_addr, ip_hdr->ip_p, 0, 0) == 0)
								/*send 0 if it's an ICMP packet because they don't 
								have port numbers */
								{ return 0; }
							}
							else if(ip_hdr->ip_p == IPPROTO_TCP 
								||ip_hdr->ip_p == IPPROTO_UDP)
							{
								if(ps->len >= 4)	/* Need at least 4 bytes for the 2 port numbers */
								{
									src_port = *((uint16_t*)ps->packet);
									dst_port = *((uint16_t*)(ps->packet + 2));
									
									if(check_connection(ps->sr, ip_hdr->ip_src.s_addr,
									ip_hdr->ip_dst.s_addr, ip_hdr->ip_p, src_port, dst_port) == 0)
									{
										return 0;
									}
								}
								else { return 0; }
							}
							else { return 0; }
						}
					}
					
					found_case = 1;
					leave_hdr_room(ps, ip_offset);
					if(ip_hdr->ip_p == IPPROTO_ICMP)
					{
						handle_icmp(ps, ip_hdr);
					}
					else
					{
						icmp_response(ps, ip_hdr, ICMPT_DESTUN, ICMPC_PORTUN);
					}
					
					memmove(iph, ip_hdr, sizeof(struct ip));
					
					/*subtract outer ethernet header wrapping the IP datagram */
					iph->ip_len = htons(ps->res_len - sizeof(struct sr_ethernet_hdr));
					
					iph->ip_ttl = INIT_TTL;
					iph->ip_tos = ip_hdr->ip_tos;
					iph->ip_p = IPPROTO_ICMP;
					iph->ip_src = ip_hdr->ip_dst;
					iph->ip_dst = ip_hdr->ip_src;
					iph->ip_sum = 0;
					iph->ip_sum = cksum((uint8_t *)iph, sizeof(struct ip));
					iph->ip_sum = htons(iph->ip_sum);
					return 1;
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
			
			if(is_external(ps->sr, ps->interface))
			{
				if(is_internal(ps->sr, ps->rt_entry->interface))
				{
					leave_hdr_room(ps, ip_offset);
					/*need at least 4 bytes for the dest and source ports */
					if(ip_hdr->ip_p == IPPROTO_ICMP)
					{
						if(check_connection(ps->sr, ip_hdr->ip_src.s_addr,
							ip_hdr->ip_dst.s_addr, ip_hdr->ip_p, 0, 0) == 0)
							/*send 0 if it's an ICMP packet because they don't 
							have port numbers */
						{ return 0; }
					}
					else if(ip_hdr->ip_p == IPPROTO_TCP 
						||ip_hdr->ip_p == IPPROTO_UDP)
					{
						if(ps->len >= 4)	/* Need at least 4 bytes for the 2 port numbers */
						{
							
							
							/*memmove(&src_port, ps->packet, 2);
							memmove(&dst_port, (ps->packet + 2), 2);*/
							
							src_port = 0;
							dst_port = 0;
							src_port = *((uint16_t*)ps->packet);
							dst_port = *((uint16_t*)(ps->packet + 2));
							//src_port = ntohs(src_port);
							//dst_port = ntohs(dst_port);
							
							
							if(check_connection(ps->sr, ip_hdr->ip_src.s_addr,
							ip_hdr->ip_dst.s_addr, ip_hdr->ip_p, src_port, dst_port) == 0)
							{
								return 0;
							}
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
						if(!tell_valid(ps->sr, ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr,ip_hdr->ip_p, 0, 0))
						{
							return 0;
						}
					}
					else if(ip_hdr->ip_p == IPPROTO_TCP 
						|| ip_hdr->ip_p == IPPROTO_UDP)
					{
						if(ps->len >= 4)	/* Need at least 4 bytes for the 2 port numbers */
						{
							
							src_port = 0;
							dst_port = 0;
							src_port = *((uint16_t*)ps->packet);
							dst_port = *((uint16_t*)(ps->packet + 2));
							
							if(!tell_valid(ps->sr, ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr, 
											ip_hdr->ip_p, dst_port, src_port))
							{
								return 0;
							}
							
							
							
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
				memmove(iph, ip_hdr, (ps->len + sizeof(struct ip)));
				ps->forward = 1;
				ps->res_len += ps->len;
			}
		}
		else
		{
			printf("ResLen 1: %i\n", ps->res_len);
		}
	}
	return 1;
}

/*Updates all values in the received packet and the response packet (that we are creating)
 * so that we are dealing with the packet at the right layer (e.g. IP, ICMP, etc)
 */
void leave_hdr_room(struct packet_state *ps, int hdr_size)
{
	ps->packet += hdr_size;
	ps->len -= hdr_size;
	ps->response += hdr_size;
	ps->res_len += hdr_size;
}



/*adapted from: http://web.eecs.utk.edu/~cs594np/unp/checksum.html */
/*Computes the IP or ICMP checksum*/
uint16_t cksum(uint8_t *buff, int len)
{
	uint16_t word16;
	uint32_t sum = 0;
	uint16_t i;
	
	
	for(i = 0; i < len; i = i + 2)
	{
		word16 = ((buff[i]<<8) & 0xff00) + (buff[i+1] & 0xff);
		sum = sum + (uint32_t) word16;
	}
	
	while(sum>>16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	
	sum = ~sum;
	return ((uint16_t) sum);

}

/* METHOD: Decrements ttl and recomputes IP header checksum */
void update_ip_hdr(struct ip *ip_hdr)
{
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = htons(cksum((uint8_t *) ip_hdr, sizeof(struct ip)));
}

/* METHOD: Get the entry in the routing table corresponding to the IP address given */
struct sr_rt* get_routing_if(struct packet_state *ps, struct in_addr ip_dst)
{
	struct sr_rt* response= NULL;

	struct sr_rt *current = ps->sr->routing_table;
	struct in_addr min_mask;
	min_mask.s_addr = 0;
	/*Iterate through routing table linked list*/
	while(current != NULL)
	{
		/*If the bitwise AND of current mask and sought ip is equal to the current mask*/
		
		if((current->mask.s_addr & ip_dst.s_addr) == current->dest.s_addr)
		{
			/*And if this is the closest fitting match so far
				***To make sure that internally destinations that fit a mask better than 0.0.0.0
				get to the right place****/
			if(min_mask.s_addr <= current->mask.s_addr)
			{
				/*update the best fitting mask to the current one, and point found to current*/
				min_mask=current->mask;
				response=current;
			}
		}
		current = current->next;
	}
	return response;
}

