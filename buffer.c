
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp.h"
#include "buffer.h"
#include "icmp.h"


/*******************************************************************
*   Every time handle_packet() is called, update_buffer() is called. The function walks through
*   the packet buffer and checks if the necessary mac address is now in the arp cache. If it is,
*   then the MAC address is added to the ethernet header and the packet is send and removed 
*   from the buffer. If the address is not in the cache and less than 5 arp requests have already
*   been sent, then another arp request is sent. Otherwise the packet is deleted from the buffer 
*   and an ICMP port unreachable is sent.
*******************************************************************/
void update_buffer(struct packet_state* ps,struct packet_buffer* queue)
{
	struct packet_buffer* buf_walker=0;
	buf_walker=queue;
	
	while(buf_walker)
	{
		uint32_t search_ip=buf_walker->gw_IP;
		struct arp_cache_entry* ent=search_cache(ps, search_ip);
		if(ent!=NULL)                   /*MAC Address is in ARP Cache. Send packet. */
		{
			struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)(buf_walker->packet);
			memmove(eth->ether_dhost, ent->mac, ETHER_ADDR_LEN);
			struct sr_if *iface=sr_get_interface(ps->sr, buf_walker->interface);
			memmove(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
			eth->ether_type = htons(ETHERTYPE_IP);
			
		    sr_send_packet(ps->sr, buf_walker->packet, buf_walker->pack_len, buf_walker->interface);
			buf_walker=delete_from_buffer(ps,buf_walker);
		}
		else if(buf_walker->num_arp_reqs < 5)   /*Send another arp request. */
		{
			buf_walker->num_arp_reqs++;
			sr_send_packet(ps->sr, buf_walker->arp_req, buf_walker->arp_len, buf_walker->interface);
			buf_walker=buf_walker->next;
		}
		else    /* 5 ARP Request already sent, send ICMP Port Unreachable and Delete from Buffer.*/
		{
			int off = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip);
			ps->res_len=off;
			
			ps->response += sizeof(struct sr_ethernet_hdr);
			
			struct ip *res_ip = (struct ip*) ps->response; /*IP Header for ICMP Port Unreachable*/
			ps->response += sizeof(struct ip);
			
			ps->packet = buf_walker->packet;
			ps->packet += sizeof(struct sr_ethernet_hdr);
			
			struct ip *ip_hdr = (struct ip*) (ps->packet);  /*IP Header from original packet. */
			ps->packet += sizeof(struct ip);
			
			icmp_response(ps, ip_hdr, ICMPT_DESTUN, ICMPC_HOSTUN); /*Construct ICMP */
			memmove(res_ip, ip_hdr, sizeof(struct ip));
			res_ip->ip_len = htons(ps->res_len - sizeof(struct sr_ethernet_hdr));
			res_ip->ip_ttl = INIT_TTL;
			res_ip->ip_tos = ip_hdr->ip_tos;
			res_ip->ip_p = IPPROTO_ICMP;
			
			/* Finding interface to send ICMP out of*/
			struct sr_rt* iface_rt_entry=get_routing_if(ps, ip_hdr->ip_src);
			struct sr_if* iface=sr_get_interface(ps->sr, iface_rt_entry->interface);
			
			res_ip->ip_src.s_addr = iface->ip;
			res_ip->ip_dst = ip_hdr->ip_src;
			res_ip->ip_sum = 0;
			res_ip->ip_sum = cksum((uint8_t *)res_ip, sizeof(struct ip));
			res_ip->ip_sum = htons(res_ip->ip_sum);
			
			ps->response = (uint8_t *) res_ip - sizeof(struct sr_ethernet_hdr);
			struct sr_ethernet_hdr* eth_resp=(struct sr_ethernet_hdr*)ps->response;
			memmove(eth_resp->ether_dhost,buf_walker->old_eth->ether_shost,ETHER_ADDR_LEN);
			
			memmove(eth_resp->ether_shost,iface->addr, ETHER_ADDR_LEN);
			eth_resp->ether_type=htons(ETHERTYPE_IP);
			
			sr_send_packet(ps->sr, ps->response, ps->res_len, iface_rt_entry->interface);

			buf_walker=delete_from_buffer(ps,buf_walker);	
		}
	}
}

/*******************************************************************
*   Deletes item from buffer.
*******************************************************************/
struct packet_buffer* delete_from_buffer(struct packet_state* ps, struct packet_buffer* want_deleted)
{
	struct packet_buffer* prev=0;
	struct packet_buffer* walker=0;
	walker=ps->sr->queue;
	while(walker)
	{
		if(walker==want_deleted)
		{
			if(prev==0)
			{
			    if(ps->sr->queue->next)
				ps->sr->queue=ps->sr->queue->next;
				else
				{
				    ps->sr->queue=NULL;
				 }   
				break;
			}
			else if(!prev->next->next)
			{
                prev->next=NULL;
                break;
			}
			else
			{
				prev->next=prev->next->next;
				break;
			}
		}
		else
		{
			prev=walker;
			walker=walker->next;
		}
	}
	if(walker->packet)
	    free(walker->packet);
	if(walker->interface)
	    free(walker->interface);
	if(walker->arp_req)
	    free(walker->arp_req);
	if(walker->old_eth)
	    free(walker->old_eth);
	if(walker)
	    free(walker);
	
	if(prev!=NULL)
        return prev->next;
    else
        return NULL;
}

/*******************************************************************
*   Buffers a packet that is waiting on destination MAC address from ARP.
*******************************************************************/
struct packet_buffer * buf_packet(struct packet_state *ps, uint8_t* pac, const struct in_addr dest_ip, 
                                    const struct sr_if* iface, struct sr_ethernet_hdr *orig_eth)
{
	struct packet_buffer* buf_walker=0;
	
	assert(ps);
	assert(pac);
	
	if(ps->sr->queue==0) /* If Buffer is Empty.*/
	{
		ps->sr->queue=(struct packet_buffer*)malloc(sizeof(struct packet_buffer));
		assert(ps->sr->queue);
		
		ps->sr->queue->next=0;
		ps->sr->queue->packet=(uint8_t*)malloc(ps->res_len);
		memmove(ps->sr->queue->packet, pac, ps->res_len);
		ps->sr->queue->pack_len=ps->res_len;
		
		struct sr_rt* rt_entry=get_routing_if(ps, dest_ip);
		ps->sr->queue->gw_IP=rt_entry->gw.s_addr;
		ps->sr->queue->interface=(char *)malloc(sr_IFACE_NAMELEN);
		
		memmove(ps->sr->queue->interface, rt_entry->interface, sr_IFACE_NAMELEN);
		ps->sr->queue->ip_dst=dest_ip;
		ps->sr->queue->num_arp_reqs=0;
		ps->sr->queue->old_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
		memmove(ps->sr->queue->old_eth, orig_eth, sizeof(struct sr_ethernet_hdr));
		return ps->sr->queue;
	}
	else /* Buffer is not Empty so Add to End. */
	{
		buf_walker=ps->sr->queue;
		while(buf_walker->next)
		{
			buf_walker=buf_walker->next;
		}
		buf_walker->next=(struct packet_buffer*)malloc(sizeof(struct packet_buffer));
		assert(buf_walker->next);
		buf_walker=buf_walker->next;
		buf_walker->next=0;
		
		buf_walker->packet=(uint8_t*)malloc(ps->res_len);
		memmove(buf_walker->packet, pac, ps->res_len);
		buf_walker->pack_len=ps->res_len;
		buf_walker->interface=(char *)malloc(sr_IFACE_NAMELEN);
		memmove(buf_walker->interface, iface->name, sr_IFACE_NAMELEN); 
		buf_walker->ip_dst=dest_ip;
		ps->sr->queue->gw_IP=ps->rt_entry->gw.s_addr;
		buf_walker->num_arp_reqs=0;
		buf_walker->old_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
		memmove(buf_walker->old_eth, orig_eth, sizeof(struct sr_ethernet_hdr));
		return buf_walker;
	}
	ps->res_len = 0; /* Reset packet state's response length to 0 */
	return NULL;
}
