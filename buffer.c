
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
			//send packet with matching mac address
		}
		else if(buf_walker->num_arp_reqs<5)
		{
			buf_walker->num_arp_reqs++;
			//send_packet(buf_walker->sr, );
		}
		else
		{
			//delete_from_buffer()
			//send icmp_port_unreachable
		}
	
	
	}
		printf("Unimplemented");
	
}
/*
void testing_buffer(struct packet_state * ps)
{
	struct packet_buffer* buf=buf_packet(ps, ps->packet, ps->

}
*/
/* MADDIE */
struct packet_buffer *buf_packet(struct packet_state *ps, uint8_t* pac, const struct in_addr dest_ip)
{
	struct packet_buffer* buf_walker=0;
	
	assert(ps);
	assert(pac);
	
	if(ps->sr->queue==0)
	{
		ps->sr->queue=(struct packet_buffer*)malloc(sizeof(struct packet_buffer));
		assert(ps->sr->queue);
		ps->sr->queue->next=0;
		ps->sr->queue->packet=pac;
		ps->sr->queue->pack_len=sizeof(ps->sr->queue->packet);
		ps->sr->queue->interface= "eth0"; /*What is interface supposed to be?? Source?? -MS"*/
		memmove(ps->sr->queue->sr, ps->sr, sizeof(ps->sr));
		ps->sr->queue->ip_dst=dest_ip;
		//TIME when sent
		ps->sr->queue->num_arp_reqs=0;
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
		ps->sr->queue->next=0;
		
		ps->sr->queue->packet=pac;
		ps->sr->queue->pack_len=sizeof(ps->sr->queue->packet);
		ps->sr->queue->interface= "eth0"; /*What is interface supposed to be?? Source?? -MS"*/
		//ps->sr->queue->sr=ps->sr; /*We don't need this right?? -MS"*/
		ps->sr->queue->ip_dst=dest_ip;
		//TIME when sent
		ps->sr->queue->num_arp_reqs=0;
	}
	
	
	/*copy packet into buffer */
	/*go through same process as add to ARP cache
	return the pointer to the new buffer entry */
	ps->res_len = 0;
	return NULL;
}
