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


struct arp_cache_entry* handle_ARP(struct packet_state * ps, struct sr_ethernet_hdr* eth)
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
	  got_Request(ps, arp, eth);
	  
	  return NULL;
	  break;
	case (ARP_REPLY):
	  printf("Got an ARP Reply.\n");
	  break;
	default:
	  printf("ARP: Not Request nor Reply\n");
	  printf("%hu", arp->ar_op);
	}
	return NULL;
}
}
void got_Request(struct packet_state * ps, struct sr_arphdr * arp_hdr, const struct sr_ethernet_hdr* eth)
{
	assert(ps);
	assert(arp_hdr);
	assert(eth);
	
	uint32_t targetIP = arp_hdr->ar_tip;
	struct sr_if * iface = ps->sr->if_list;

	while(iface!=NULL)
	{
		sr_print_if(iface);
		if(iface->ip == targetIP)
		{
			printf("IP matches interface: %s\n", iface->name);
			construct_reply(ps, arp_hdr, iface->addr, eth);
			//testing(ps, arp_hdr);
			
			break;
		}
		else
		{
			iface=iface->next;
		}
	}
	if(iface==NULL)
		printf("Didn't find matching IP Address for interface.\n");
	
}

void testing(struct packet_state* ps, struct sr_arphdr *arp)
{
	printf("\n---JUST TESTING STUFF---\n");
	printf("PRINT CACHE FIRST:::\n");
	print_cache(ps->sr);
	struct sr_if * iface=ps->sr->if_list;
	while(iface)
	{
	add_cache_entry(ps, iface->ip, iface->addr);
	printf("%s Added To Cache.\n", iface->name);
	iface=iface->next;
	printf("HERE\n");
	}
	iface=sr_get_interface(ps->sr, "eth0");
	struct in_addr ip_addr;
	ip_addr.s_addr = iface->ip;
	printf("IP: %s\n", inet_ntoa(ip_addr));
	struct arp_cache_entry* ent=search_cache(ps, iface->ip);
	printf("---FOUND ENTRY:----\n");
	print_cache_entry(ent);
	print_cache(ps->sr);
	delete_entry(ps, ent);
	print_cache(ps->sr);
	
}

struct arp_cache_entry* got_Reply(struct packet_state * ps, struct sr_arphdr * arp, const struct sr_ethernet_hdr* eth)
{
	//Add IP and address to cache
	add_cache_entry(ps, arp->ar_sip, arp->ar_sha);
	
	//Return newly added entry
	return search_cache(ps, arp->ar_sip);
	
}

void add_cache_entry(struct packet_state* ps,const uint32_t ip, const unsigned char* mac)
{
	struct arp_cache_entry* cache_walker=0;

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
    /*DO WE WANT TO CLEAN OUT INVALID ENTRIES NOW TOO 
    OR ONLY WHEN SEARCHING FOR AN ENTRY??*/
    cache_walker = ps->sr->arp_cache;
    while(cache_walker->next)
    {
    	cache_walker=cache_walker->next;
    	//CHECK IF PAST TIME INVALID AND DELETE IF INALID??
    }
    cache_walker->next=(struct arp_cache_entry*)malloc(sizeof(struct arp_cache_entry));
    assert(cache_walker->next);
    cache_walker=cache_walker->next;
    cache_walker->ip_add=ip;
    memcpy(cache_walker->mac, mac,ETHER_ADDR_LEN);
   cache_walker->timenotvalid=time(NULL) +15;	/* Each cache entry is valid for 15 seconds */
   cache_walker->next=0;
    print_cache(ps->sr);
    }

}

struct arp_cache_entry* search_cache(struct packet_state* ps,const uint32_t ip)
{
	struct arp_cache_entry* cache_walker=0;
	cache_walker=ps->sr->arp_cache;
	//struct arp_cache_entry* prev=0;
	while(cache_walker)
	{
		if(cache_walker->timenotvalid > time(NULL))
		{
		if(ip==cache_walker->ip_add)
			return cache_walker;
		}
		else
		{
			delete_entry(ps, cache_walker);
		}
			cache_walker=cache_walker->next;
	}
	//IP Address is not in cache
	printf("The IP address is not in cache.");
	return NULL;
}

void delete_entry(struct packet_state* ps,const struct arp_cache_entry* want_deleted)
{
	struct arp_cache_entry* prev=0;
	struct arp_cache_entry* walker=0;
	walker=ps->sr->arp_cache;
	
	while(walker)
	{
		if(walker==want_deleted)
		{
			if(prev==0)
			{
				ps->sr->arp_cache=ps->sr->arp_cache->next;
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
	
}


void print_cache(struct sr_instance* sr)
{
	printf("---ARP CACHE---\n");
	struct arp_cache_entry* cache_walker=0;
	if(sr->arp_cache==0)
	{
		printf(" ARP Cache is Empty.\n");
		return;
	}
	cache_walker=sr->arp_cache;
	while(cache_walker)
	{
		print_cache_entry(cache_walker);
		cache_walker=cache_walker->next;
	}
}

void print_cache_entry(struct arp_cache_entry * ent)
{
	struct in_addr ip_addr;
	assert(ent);
	ip_addr.s_addr = ent->ip_add;
	printf("IP: %s MAC: ", inet_ntoa(ip_addr));
	DebugMAC(ent->mac); 
	printf(" Time when Invalid: %lu\n",(long)ent->timenotvalid);
}

//HAS NOT BEEN TESTED
void construct_reply(struct packet_state* ps, const struct sr_arphdr* arp_hdr, const unsigned char* mac, const struct sr_ethernet_hdr* eth)
{
	struct sr_arphdr *reply;
	reply = (struct sr_arphdr*)malloc(sizeof(struct sr_arphdr));
	reply->ar_hrd = arp_hdr->ar_hrd;
	reply->ar_pro = arp_hdr->ar_pro;
	reply->ar_hln= ETHER_ADDR_LEN;
	reply->ar_pln = arp_hdr->ar_pln;
	reply->ar_op = htons(ARP_REPLY);
	memmove(reply->ar_sha, mac,ETHER_ADDR_LEN);
	reply->ar_sip=arp_hdr->ar_tip;
	memmove(reply->ar_tha, arp_hdr->ar_sha,ETHER_ADDR_LEN);
	reply->ar_tip=arp_hdr->ar_sip;
	
	//ARP Constructed, Now Add Ethernet Header
	struct sr_ethernet_hdr* new_eth;
	new_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
	memcpy(new_eth->ether_dhost, eth->ether_shost,ETHER_ADDR_LEN);
	memcpy(new_eth->ether_shost, mac,ETHER_ADDR_LEN);
	new_eth->ether_type=htons(ETHERTYPE_ARP);
	
	int eth_offset=sizeof(struct sr_ethernet_hdr);
	memmove(ps->response, reply, sizeof(struct sr_arphdr));
	ps->response-=eth_offset;
	memmove(ps->response, new_eth, eth_offset);
	free(reply);
	free(new_eth);
	ps->res_len=eth_offset + sizeof(struct sr_arphdr);
	printf("Response was constructed.\n");
}
