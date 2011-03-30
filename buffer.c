
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


/*Maddie*/
struct packet_buffer* search_buffer(struct packet_state* ps,const uint32_t dest_ip)
{
	struct packet_buffer* buf_walker=0;
	buf_walker=ps->sr->queue;
	
	while(buf_walker)
	{
		if(buf_walker->ip_dst.s_addr==dest_ip)
		{
			return buf_walker;
		}
		buf_walker=buf_walker->next;
	}
	return NULL;
}

/* MADDIE */
void update_buffer(struct packet_state* ps,struct packet_buffer* queue)
{
	
	struct packet_buffer* buf_walker=0;
	buf_walker=queue;
	
	while(buf_walker)
	{
		uint32_t search_ip=buf_walker->ip_dst.s_addr;
		struct arp_cache_entry* ent=search_cache(ps, search_ip);
		if(ent!=NULL)
		{
			struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)(buf_walker->packet);
			memmove(eth->ether_dhost, ent->mac, ETHER_ADDR_LEN);
			struct sr_if* iface=(struct sr_if*)malloc(sizeof(struct sr_if));
			iface=sr_get_interface(ps->sr, buf_walker->interface);
			memmove(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
			eth->ether_type = htons(ETHERTYPE_IP);
		}
		else if(buf_walker->num_arp_reqs < 5)
		{
			buf_walker->num_arp_reqs++;
			printf("SENT.");
			sr_send_packet(ps->sr, buf_walker->arp_req, buf_walker->arp_len, buf_walker->interface);
		}
		else
		{
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
			memmove(eth_resp->ether_dhost,eth->ether_shost,ETHER_ADDR_LEN);
			memmove(eth_resp->ether_shost,iface->addr, ETHER_ADDR_LEN);
			eth_resp->ether_type=htons(ETHERTYPE_IP);
			
			/* MADDIE NEEDS TO CHANGE ^^^^^^^ THIS LINE */
			
			sr_send_packet(ps->sr, ps->response, ps->res_len, iface_rt_entry->interface);
			
		
	
			delete_from_buffer(ps,buf_walker);
		}
	}
	
}

void delete_from_buffer(struct packet_state* ps, struct packet_buffer* want_deleted)
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
				ps->sr->queue=ps->sr->queue->next;
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
	free(walker);

}

/*
void testing_buffer(struct packet_state * ps)
{
	struct packet_buffer* buf=buf_packet(ps, ps->packet, ps->

}
*/
/* MADDIE */
struct packet_buffer * buf_packet(struct packet_state *ps, uint8_t* pac, const struct in_addr dest_ip, const struct sr_if* iface)
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
		
		ps->sr->queue->interface=(char *)malloc(sr_IFACE_NAMELEN);
		
		memmove(ps->sr->queue->interface, iface->name, sr_IFACE_NAMELEN); 
		ps->sr->queue->ip_dst=dest_ip;
		//time
		ps->sr->queue->num_arp_reqs=0;
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
		//time
		buf_walker->num_arp_reqs=0;
		return buf_walker;
	}
	
	
	ps->res_len = 0;
	return NULL;
}
