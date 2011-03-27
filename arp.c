/*** ARP File
 */

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp.h"

void handle_ARP(struct packet_state * ps)
{
  struct sr_arphdr *arp =0;

  int arp_offset=sizeof(struct sr_arphdr);

  if(ps->len <sizeof(struct sr_arphdr))
    {
      printf("Malformed ARP Packet.");
      /*TODO: What needs to be done now? */
    }
  else
    {
      	arp=(struct sr_arphdr *)(ps->packet);
      	switch (ntohs(arp->ar_op))
	{
	case (ARP_REQUEST):
	  printf("Got an ARP Request.\n");
	  got_Request(ps, arp);
	  break;
	case (ARP_REPLY):
	  printf("Got an ARP Reply.\n");
	  break;
	default:
	  printf("ARP: Not Request nor Reply\n");
	  printf("%hu", arp->ar_op);
	  
	}
	
    }
}

void got_Request(struct packet_state * ps, struct sr_arphdr * arp_hdr)
{
	uint32_t targetIP=arp_hdr->ar_tip;
	struct sr_if * iface=ps->sr->if_list;
	
	while(iface!=NULL)
	{
			sr_print_if(iface);
		if(iface->ip==targetIP)
		{
			printf("IP matches interface: %s\n", iface->name);
			//ADD IP ADDRESS and MAC ADDRESS TO CACHE
			add_cache_entry(ps, targetIP, iface->addr);
			break;
		}
		else
		{
			iface=iface->next;
		}
	}
	printf("Didn't find matching IP Address for interface.\n");
}

void add_cache_entry(struct packet_state* ps, uint32_t ip, const unsigned char* mac)
{
struct arp_cache_entry* cache_walker=0;
/*
struct arp_cache_entry ent; /*=(struct arp_cache_entry)malloc(sizeof(struct arp_cache_entry));*/
/*strncpy(ent.mac, mac,ETHER_ADDR_LEN);
ent.ip_add=ip;
*/
assert(ps);
    assert(mac);
    assert(ip);
    
    if(ps->sr->arp_cache ==0)	/*If there are no entries in cache */
    {
    	ps->sr->arp_cache=(struct arp_cache_entry*)malloc(sizeof(struct arp_cache_entry));
    	assert(ps->sr->arp_cache);
    	ps->sr->arp_cache->next=0;
    	ps->sr->arp_cache->ip_add=ip;
    	memcpy(ps->sr->arp_cache->mac, mac,ETHER_ADDR_LEN);
    	ps->sr->arp_cache->timenotvalid=time(NULL) +20;	/* Each cache entry is valid for 20 seconds */
    	print_cache_entry(ps->sr->arp_cache);
    }
    else
    {
    
    
    }

}

void print_cache_entry(struct arp_cache_entry * ent)
{
	struct in_addr ip_addr;
	assert(ent);
	ip_addr.s_addr = ent->ip_add;
	printf("IP: %s MAC: ", inet_ntoa(ip_addr));
	DebugMAC(ent->mac); 
	printf(" Time when Invalid: %u\n",ent->timenotvalid);
}