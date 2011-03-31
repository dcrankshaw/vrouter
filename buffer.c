
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


/*Maddie--prolly don't need*/
/*
struct packet_buffer* search_buffer(struct packet_state* ps,const uint32_t dest_ip)
{
	struct packet_buffer* buf_walker=0;
	buf_walker=ps->sr->queue;
	
	while(buf_walker)
	{
		if(buf_walker->gw_IP==dest_ip)
		{
			return buf_walker;
		}
		buf_walker=buf_walker->next;
	}
	return NULL;
}
*/

void update_buffer(struct packet_state* ps,struct packet_buffer* queue)
{
	struct packet_buffer* buf_walker=0;
	buf_walker=queue;
	
	while(buf_walker)
	{
		uint32_t search_ip=buf_walker->gw_IP;
		struct arp_cache_entry* ent=search_cache(ps, search_ip);
		if(ent!=NULL)
		{
			struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)(buf_walker->packet);
			memmove(eth->ether_dhost, ent->mac, ETHER_ADDR_LEN);
			struct sr_if *iface=sr_get_interface(ps->sr, buf_walker->interface);
			memmove(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
			eth->ether_type = htons(ETHERTYPE_IP);
			
		    sr_send_packet(ps->sr, buf_walker->packet, buf_walker->pack_len, buf_walker->interface);
			printf("Found in cache and sent.\n");
			buf_walker=delete_from_buffer(ps,buf_walker);
			
			printf("Survived delete.\n");
		}
		else if(buf_walker->num_arp_reqs < 5)
		{
			printf("Sending ARP Request\n");
			buf_walker->num_arp_reqs++;
			printf("SENT.");
			sr_send_packet(ps->sr, buf_walker->arp_req, buf_walker->arp_len, buf_walker->interface);
			buf_walker=buf_walker->next;
		}
		else
		{
			printf("Deleting buf packet and sending ICMP port unreachable\n");
			int off = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip);
			ps->res_len=off;
			ps->response += sizeof(struct sr_ethernet_hdr);
			struct ip *res_ip = (struct ip*) ps->response;
			ps->response += sizeof(struct ip);
			ps->packet = buf_walker->packet;
			
			struct sr_ethernet_hdr* eth=(struct sr_ethernet_hdr*)(ps->packet);
			ps->packet += sizeof(struct sr_ethernet_hdr);
			struct ip *ip_hdr = (struct ip*) (ps->packet);
			ps->packet += sizeof(struct ip);
			icmp_response(ps, ip_hdr, ICMPT_DESTUN, ICMPC_PORTUN);
			memmove(res_ip, ip_hdr, sizeof(struct ip));
			res_ip->ip_len = htons(ps->res_len - sizeof(struct sr_ethernet_hdr));
			res_ip->ip_ttl = INIT_TTL;
			res_ip->ip_tos = ip_hdr->ip_tos;
			res_ip->ip_p = IPPROTO_ICMP;
			
			/* Finding interface to send icmp out of*/
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
			
			
			printf("SR: %p\n", ps->sr);
			printf("RESPONSE: %p\n", ps->response);
			printf("RESLEN: %d\n", ps->res_len);
			printf("IFACE: %p", iface_rt_entry->interface);
			sr_send_packet(ps->sr, ps->response, ps->res_len, iface_rt_entry->interface);
			
		
	
			buf_walker=delete_from_buffer(ps,buf_walker);
			
		}
		
	}
	
}

struct packet_buffer* delete_from_buffer(struct packet_state* ps, struct packet_buffer* want_deleted)
{
	struct packet_buffer* prev=0;
	struct packet_buffer* walker=0;
	walker=ps->sr->queue;
	while(walker)
	{
		if(walker==want_deleted)
		{
		    printf("Found matching thing to be del in buffer.\n");
			if(prev==0)
			{
			    if(ps->sr->queue->next)
				    ps->sr->queue=ps->sr->queue->next;
				else
				{
				    ps->sr->queue=NULL;
				    printf("Want to return Null\n");
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

/*
void testing_buffer(struct packet_state * ps)
{
	struct packet_buffer* buf=buf_packet(ps, ps->packet, ps->

}
*/
/* MADDIE */
struct packet_buffer * buf_packet(struct packet_state *ps, uint8_t* pac, const struct in_addr dest_ip, const struct sr_if* iface, struct sr_ethernet_hdr *orig_eth)
{
	struct packet_buffer* buf_walker=0;
	
	assert(ps);
	assert(pac);
	
	if(ps->sr->queue==0)
	{
		ps->sr->queue=(struct packet_buffer*)malloc(sizeof(struct packet_buffer));
		assert(ps->sr->queue);
		
		ps->sr->queue->next=0;
		ps->sr->queue->packet=(uint8_t*)malloc(ps->res_len);
		memmove(ps->sr->queue->packet, pac, ps->res_len);
		ps->sr->queue->pack_len=ps->res_len;
		printf("BBBB");
		
		struct sr_rt* rt_entry=get_routing_if(ps, dest_ip);
		printf("Interface name: %s\n", rt_entry->interface);
		ps->sr->queue->gw_IP=rt_entry->gw.s_addr;
		ps->sr->queue->interface=(char *)malloc(sr_IFACE_NAMELEN);
		
		memmove(ps->sr->queue->interface, rt_entry->interface, sr_IFACE_NAMELEN); 
		printf("Buffered Interface name: %s\n", ps->sr->queue->interface);
		ps->sr->queue->ip_dst=dest_ip;
		//time
		ps->sr->queue->num_arp_reqs=0;
		ps->sr->queue->old_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
		memmove(ps->sr->queue->old_eth, orig_eth, sizeof(struct sr_ethernet_hdr));
		return ps->sr->queue;
	}
	else
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
		/*struct sr_rt* rt_entry=get_routing_if(ps, dest_ip);*/
		printf("Interface name: %s\n", ps->rt_entry->interface);
		ps->sr->queue->gw_IP=ps->rt_entry->gw.s_addr;
		printf("Buffered Interface name: %s\n", buf_walker->interface);
		//time
		buf_walker->num_arp_reqs=0;
		buf_walker->old_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
		memmove(buf_walker->old_eth, orig_eth, sizeof(struct sr_ethernet_hdr));
		return buf_walker;
	}
	
	
	ps->res_len = 0;
	return NULL;
}
