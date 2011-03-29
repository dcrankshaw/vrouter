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
	sr->flow_tbl=0;

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
    unsigned int orig_len = len;

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
				printf("GOT an IP packet");
				handle_ip(&current);
				if(create_eth_hdr(head, &current) > 0)
				{
					printf("\n\nres_len%u\n\n", current.res_len);
					sr_send_packet(sr, head, current.res_len, current.rt_entry->interface);
				}
				/*TODO: temporary*/
				else
				{
					struct sr_ethernet_hdr *temp = (struct sr_ethernet_hdr *) head;
					/*
					temp->ether_shost[0] = 0x00;
					temp->ether_shost[1] = 0x3d;
					temp->ether_shost[2] = 0x41;
					temp->ether_shost[3] = 0x82;
					temp->ether_shost[4] = 0x83;
					temp->ether_shost[5] = 0x7a;
					temp->ether_dhost[0] = 0xff;
					temp->ether_dhost[1] = 0xff;
					temp->ether_dhost[2] = 0xff;
					temp->ether_dhost[3] = 0xff;
					temp->ether_dhost[4] = 0xff;
					temp->ether_dhost[5] = 0xff;
					temp->ether_type = htons(ETHERTYPE_IP);
					printf("\n\nres_len%u\n\n", current.res_len);
					char *if1 = "eth1";
					sr_send_packet(sr, head, orig_len, if1);
					test_ip_gen(head, current.res_len, interface);
					*/
					
					memmove(temp->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
					temp->ether_shost[0] = 0x00;
					temp->ether_shost[1] = 0xd8;
					temp->ether_shost[2] = 0xb3;
					temp->ether_shost[3] = 0x90;
					temp->ether_shost[4] = 0x1f;
					temp->ether_shost[5] = 0x5b;
					temp->ether_type = htons(ETHERTYPE_IP);
					
					printf("\n\nres_len%u\n\n", current.res_len);
					sr_send_packet(sr, head, current.res_len, interface);
					test_ip_gen(head, current.res_len, interface);
					
					
				}
				break;

			case (ETHERTYPE_ARP):
				printf("Got an ARP packet");
				struct arp_cache_entry *new_entry = handle_ARP(&current, eth);
				if(new_entry == NULL)
				{
					sr_send_packet(sr, head, current.res_len, interface);
				}
				else
				{
					search_buffer(new_entry->ip_add);
				}
				break;
			default:
				printf("%x", eth->ether_type);
		}
	}
	update_buffer();

	free(head);
    
}/* end sr_ForwardPacket */

int test_ip_gen(uint8_t *packet, unsigned int len, char *interface)
{
	int hdr_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmp_hdr);
	if(len < hdr_len)
	{
		printf("packet too short");
		return 0;
	}
	struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) packet;
	packet += sizeof(struct sr_ethernet_hdr);
	struct ip *ip_hdr = (struct ip *) packet;
	packet += sizeof(struct ip);
	struct icmp_hdr *icmp = (struct icmp_hdr *) packet;
	printf("hl: %u, version: %u, type: %u, len: %u, id: %u, ttl: %u, prot: %u, sum %u",
		ip_hdr->ip_hl, ip_hdr->ip_v, ip_hdr->ip_tos, ip_hdr->ip_len, ip_hdr->ip_id,
		ip_hdr->ip_ttl, ip_hdr->ip_p, ip_hdr->ip_sum);
	char *current_address = (char *) malloc((INET_ADDRSTRLEN+1)*sizeof(char));
	char *dest_address = (char *) malloc((INET_ADDRSTRLEN+1)*sizeof(char));
	uint32_t temporary = ip_hdr->ip_dst.s_addr;
	inet_ntop(AF_INET, &temporary, dest_address, (INET_ADDRSTRLEN+1)*sizeof(char));
	temporary = ip_hdr->ip_src.s_addr;
	inet_ntop(AF_INET, &temporary, current_address, (INET_ADDRSTRLEN+1)*sizeof(char));
	free(current_address);
	free(dest_address);
	
	printf("\n\nICMP HEADER:\ntype: %u, code %u, sum: %u\n\n\n", icmp->icmp_type, icmp->icmp_code, icmp->icmp_sum);
	return 0;
}


/*Maddie*/
void search_buffer(uint32_t dest_ip)
{
	printf("Unimplemented");
}

/* MADDIE */
void update_buffer()
{
	/*while(next_entry != null)
	{
		if(check cache for ip address)
		{
			send packet;
			return;
		}
		else if(num_arp_requests >= 5)
		{
			remove from buffer;
			send icmp_port_unreachable;
		}
		else
		{
			num_arp_requests++;
			send_packet(buffered_arp_request);
		}*/
		printf("Unimplemented");
	
}

/* MADDIE */
struct packet_buffer *buf_packet(struct packet_state *ps)
{
	/*copy packet into buffer */
	/*go through same process as add to ARP cache
	return the pointer to the new buffer entry */
	ps->res_len = 0;
	return NULL;
}



int create_eth_hdr(uint8_t *newpacket, struct packet_state *ps)
{

	/*check ARP cache to see if the MAC address for the outgoing IP address is there*/
	/* if not present, sleep(5), check again. Repeat 5 times, then send ICMP
		host unreachable message */

	/* This method must also figure out the interface to send the packet out of */


	/*when buffering packet, memmove() the packet to the buffer, then maddie can use the
	response field in packet_state to build her arp_request*/
	
	struct ip *new_iphdr = (struct ip*)(newpacket+sizeof(struct sr_ethernet_hdr));
	
	struct arp_cache_entry *ent = search_cache(ps, new_iphdr->ip_dst.s_addr);
	if(ent != NULL)
	{
		struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) newpacket;
		memmove(eth->ether_dhost, ent->mac, ETHER_ADDR_LEN);
		struct sr_if *sif = sr_get_interface(ps->sr, ps->rt_entry->interface);
		memmove(eth->ether_shost, sif->addr, ETHER_ADDR_LEN);
		eth->ether_type = htons(ETHERTYPE_IP);
		return 1;
	}
	else
	{
		/*ps->response = newpacket;
		struct packet_buffer* current = buf_packet(ps);
		send_request(ps);
		memmove(current->arp_req, ps->response, ps->res_len);
		current->arp_len = ps->res_len;
		sr_send_packet(ps->sr, ps->response, ps->res_len, ps->rt_entry->interface);*/
		printf("no ethernet header\n");
		return 0;
	}
	return 0;
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
		if((ip_hdr->ip_hl)*4 > sizeof(struct ip)) /* x 4 because there are 4 bytes per 32 bit word */
		{
			/*ps->packet = ps->packet + (ip_hdr->ip_len - sizeof(struct ip));*/
			printf("struct length: %zu\npacketlength: %u\n", sizeof(struct ip), ntohs(ip_hdr->ip_len));
		}
		int ip_offset = sizeof(struct ip);
		printf("section a\n");
		char *if0 = "eth0";
		char *if1 = "eth1";
		char *if2 = "eth2";
		
		/*struct in_addr ipdst_host_order;
		ipdst_host_order.s_addr = ntohl(ip_hdr->ip_dst.s_addr);*/ /*may need to remove ntohl*/
		get_routing_if(ps, ip_hdr->ip_dst);
		struct ip *iph = (struct ip*)ps->response; /* mark where the ip header should go */
		
		printf("section b\n");
		
		/*TODO: make sure interface matching incoming interface ???*/

		int found_case = 0;	/*used to determine which loops to go into*/
		/*Deals with router as destination*/
		if(!found_case)
		{
			struct sr_if *iface = ps->sr->if_list;
			char *current_address = (char *) malloc((INET_ADDRSTRLEN+1)*sizeof(char));
			char *dest_address = (char *) malloc((INET_ADDRSTRLEN+1)*sizeof(char));
			while(iface != NULL)
			{
				
				inet_ntop(AF_INET, &iface->ip, current_address, (INET_ADDRSTRLEN+1)*sizeof(char));
				uint32_t temporary = ip_hdr->ip_dst.s_addr;
				inet_ntop(AF_INET, &temporary, dest_address, (INET_ADDRSTRLEN+1)*sizeof(char));
				printf("current address: %s\n destination address: %s\n", current_address, dest_address);
				/* TODO: This will need rigorous testing */
				if(iface->ip == ip_hdr->ip_dst.s_addr)
				{
					printf("reached sr_router.c, print statement #1");
					
					
					if(strcmp(ps->interface, if0) == 0)
					{
						if(strcmp(&iface->name[0], if1) == 0 || strcmp(&iface->name[0], if2) == 0)
						{ return -1; /* Dropped packet */ }
					}
					found_case = 1;
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
					
					memmove(iph, ip_hdr, sizeof(struct ip));
					/*iph->ip_hl = sizeof(struct ip)/4;*/
					/*iph->ip_hl = 5;
					iph->ip_v = 4;*/
					iph->ip_len = htons(ps->res_len - sizeof(struct sr_ethernet_hdr));
					/*subtract outer ethernet header wrapping the IP datagram */
					/*iph->ip_len = ps->res_len;*/
					iph->ip_ttl = INIT_TTL;
					iph->ip_tos = ip_hdr->ip_tos;
					iph->ip_p = IPPROTO_ICMP;
					iph->ip_src = ip_hdr->ip_dst;
					iph->ip_dst = ip_hdr->ip_src;
					iph->ip_sum = 0;
					iph->ip_sum = cksum((uint8_t *)iph, sizeof(struct ip));
					iph->ip_sum = htons(iph->ip_sum);
					break;
				}
				else
				{
					printf("section c");
					iface = iface->next;
					printf("section d");
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
				memmove(iph, ip_hdr, ps->len); /*TODO: double check that this is right */
				ps->forward = 1;
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
	ps->res_len += hdr_size; 	/*I DON'T THINK WE WANT TO DO THIS*/
}

/*adapted from: http://web.eecs.utk.edu/~cs594np/unp/checksum.html */
uint16_t cksum(uint8_t *buff, int len)
{
	uint16_t word16;
	uint32_t sum = 0;
	uint16_t i;
	
	for(i = 0; i < len; i++)
	{
		printf("%x  ", buff[i]);
		if(i%10 == 0)
		{
			printf("\n");
		}
	}
	
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
	printf("\n\n\nSum: %x\nLen: %d\n\n", sum, len);
	return ((uint16_t) sum);

	
	/*uint32_t sum = 0;  
	uint16_t answer = 0;
	printf("%d\n", len);

	while(len > 1)
	{
	 sum += *(ip_hdr)++;
	 if(sum & 0x80000000)   
	   	sum = (sum & 0xFFFF) + (sum >> 16);
	 	len -= 2;
	 	printf("%d\n", len);
	}
	
	if(len)      
	{
		sum += (uint16_t) *(uint8_t *)ip_hdr;
	}
	while(sum>>16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	answer = (uint16_t) ~sum;
	return answer;*/

}

void update_ip_hdr(struct ip *ip_hdr)
{
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((uint8_t *) ip_hdr, sizeof(struct ip));
}

/*METHOD: Get the correct entry in the routing table*/
void get_routing_if(struct packet_state *ps, struct in_addr ip_dst)
{	
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
	return 1;
}
int sr_add_ft_entry(struct sr_instance *a, uint32_t b, uint32_t c, uint8_t d, uint8_t e, uint8_t f)
{
	return 1;
}


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
