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


#ifndef ARP_IP_LEN
#define ARP_IP_LEN 4
#endif

#ifndef ARP_HRD_ETH
#define ARP_HRD_ETH 0x0001
#endif

#ifndef ARP_PRO_IP
#define ARP_PRO_IP 0x0800
#endif

#ifndef BROADCAST_ETH
#define BROADCAST_ETH 0xFF
#endif

/*******************************************************************
*   Called when handle_packet() receives and ARP packet.
*   
*   If received a request, calls got_Request() and returns NULL. 
*   If received a reply, calls got_Reply() and returns the ARP cache entry constructed from the 
*   reply received.
*
********************************************************************/
struct arp_cache_entry* handle_ARP(struct packet_state * ps, struct sr_ethernet_hdr* eth)
{
	struct sr_arphdr *arp =0;

	if(ps->len <sizeof(struct sr_arphdr))
	{
		printf("Malformed ARP Packet.");
		ps->res_len=0;
	}
	else
	{
		arp=(struct sr_arphdr *)(ps->packet);
		switch (ntohs(arp->ar_op))
		{
			case (ARP_REQUEST):
			{
	  			got_Request(ps, arp, eth);
	  			return NULL;
	  		}
	  			break;
			case (ARP_REPLY):
			{
	  			return got_Reply(ps, arp); 
	  		}
	  			break;
			default:
			{
	  			printf("ARP: Not Request nor Reply\n");
	  			printf("%hu", arp->ar_op);
	  		}
	  			return NULL;
		}
	}
	return NULL;
}

/*******************************************************************
*   Finds interface the ARP Request was received from and constructs ARP Reply to send back out of 
*   the received interface. 
*******************************************************************/
void got_Request(struct packet_state * ps, struct sr_arphdr * arp_hdr, const struct sr_ethernet_hdr* eth)
{
	assert(ps);
	assert(arp_hdr);
	assert(eth);
	
	struct sr_if *iface = sr_get_interface(ps->sr, ps->interface);
	assert(iface);
	construct_reply(ps, arp_hdr, iface->addr, eth);
}

/*******************************************************************
*   Adds information from received ARP Reply to ARP Cache and returns newly added ARP Cache entry.
*******************************************************************/
struct arp_cache_entry* got_Reply(struct packet_state * ps, struct sr_arphdr * arp)
{
	add_cache_entry(ps, arp->ar_sip, arp->ar_sha); /*Add IP and MAC address from reply to cache */
	return search_cache(ps, arp->ar_sip); /*Return the newly added entry. */	
}

/*******************************************************************
*   Adds entry to ARP Cache if not already in Cache. Also deletes any entries that are past 
*   their expiration time.
*******************************************************************/
void add_cache_entry(struct packet_state* ps,const uint32_t ip, const unsigned char* mac)
{
	if(search_cache(ps, ip)==NULL) /*Entry is not already in cache so add. */
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
            memmove(ps->sr->arp_cache->mac, mac,ETHER_ADDR_LEN);
            ps->sr->arp_cache->timenotvalid=time(NULL) +ARP_TIMEOUT;
        }
        else
        {
            cache_walker = ps->sr->arp_cache;
            while(cache_walker->next)
            {
                if(cache_walker->timenotvalid < time(NULL))
                {
                    cache_walker = delete_entry(ps,cache_walker);
                }
                else
                {
               		cache_walker=cache_walker->next;
               	}	
            }
            cache_walker->next=(struct arp_cache_entry*)malloc(sizeof(struct arp_cache_entry));
            assert(cache_walker->next);
            cache_walker=cache_walker->next;
            cache_walker->ip_add=ip;
            memmove(cache_walker->mac, mac,ETHER_ADDR_LEN);
            cache_walker->timenotvalid=time(NULL) +ARP_TIMEOUT;
            cache_walker->next=0;
        }
	}

}

/*******************************************************************
*   Searches cache for entry based on IP address. Deletes any entries past expiration time. Returns 
*   matching entry.
*******************************************************************/
struct arp_cache_entry* search_cache(struct packet_state* ps,const uint32_t ip)
{
	struct arp_cache_entry* cache_walker=0;
	cache_walker=ps->sr->arp_cache;
	while(cache_walker) 
	{
	    time_t curr_time=time(NULL);
		if(cache_walker->timenotvalid > curr_time)  /*Check if entry has expired. */
		{
			if(ip==cache_walker->ip_add)
				return cache_walker;
			else
				cache_walker = cache_walker->next;
		}
		else                                        /*If the ARP entry has expired, delete. */
		{
			cache_walker = delete_entry(ps, cache_walker);
		}
	}
	
	/*IP Address is not in cache. */
	return NULL;
}

/*******************************************************************
*   Deletes entry from cache.
*******************************************************************/
struct arp_cache_entry* delete_entry(struct packet_state* ps, struct arp_cache_entry* want_deleted)
{
	struct arp_cache_entry* prev=0;
	struct arp_cache_entry* walker=0;
	walker=ps->sr->arp_cache;
	
	while(walker)
	{
		if(walker==want_deleted)    /* On item to be deleted in cache. */
		{
			if(prev==0)             /* Item is first in cache. */  
			{
				if(ps->sr->arp_cache->next)
				{
					ps->sr->arp_cache=ps->sr->arp_cache->next;
				}	
				else
				{
					ps->sr->arp_cache = NULL;
				}
				break;
			}
			else if(!walker->next) /* Item is last in cache. */
			{
                prev->next=NULL;
                break;
			}
			else                    /* Item is in the middle of cache. */
			{
				prev->next=walker->next;
				break;
			}
		}
		else
		{
			prev=walker;
			walker=walker->next;
		}
	}
	
	/* Walker is still on item to be deleted so free that item. */
	if(walker)
		free(walker);
		
	/*Return next item in cache after deleted item. */
	if(prev!=NULL)
		return prev->next;
	return NULL;
	
}

/*******************************************************************
*   Prints all of ARP Cache.
*******************************************************************/
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

/*******************************************************************
*   Prints single ARP Cache Entry.
*******************************************************************/
void print_cache_entry(struct arp_cache_entry * ent)
{
	struct in_addr ip_addr;
	assert(ent);
	ip_addr.s_addr = ent->ip_add;
	printf("IP: %s MAC: ", inet_ntoa(ip_addr));
	DebugMAC(ent->mac); 
	printf(" Time when Invalid: %lu\n",(long)ent->timenotvalid);
}

/*******************************************************************
*   Constructs Reply to an ARP Request.
*******************************************************************/
void construct_reply(struct packet_state* ps, const struct sr_arphdr* arp_hdr, const unsigned char* mac, const struct sr_ethernet_hdr* eth)
{
    /* Construct ARP Reply Header*/
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
	
	/*ARP Constructed, Now Add Ethernet Header */
	struct sr_ethernet_hdr* new_eth;
	new_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
	memmove(new_eth->ether_dhost, eth->ether_shost,ETHER_ADDR_LEN); /*Moving original ether_shost to new ether_dhost);*/
	memmove(new_eth->ether_shost, mac,ETHER_ADDR_LEN); /* Set new ether_shost to mac */
	new_eth->ether_type=htons(ETHERTYPE_ARP);
	
	int eth_offset=sizeof(struct sr_ethernet_hdr);
	memmove(ps->response, reply, sizeof(struct sr_arphdr)); /*Put ARP Header in Response */
	ps->response-=eth_offset;
	memmove(ps->response, new_eth, eth_offset); /*Put Ethernet Header in Response */
	
	/* Free arp header and eth header we constructed. */
	if(reply)
		free(reply);
	if(new_eth)
		free(new_eth);

	ps->res_len=eth_offset + sizeof(struct sr_arphdr);
}

/*******************************************************************
*   Constructs appropriate ARP Request based on a packet to be forwarded.
*******************************************************************/
void send_request(struct packet_state* ps, const uint32_t dest_ip)
{
	/*Construct ARP Header*/
	struct sr_arphdr* request;
	request=(struct sr_arphdr*)malloc(sizeof(struct sr_arphdr));
	request->ar_hrd=htons(ARP_HRD_ETH);
	request->ar_pro=htons(ARP_PRO_IP);
	request->ar_hln=ETHER_ADDR_LEN;
	request->ar_pln=ARP_IP_LEN;
	request->ar_op=htons(ARP_REQUEST);
	
	/* Find source interface */
	struct in_addr ip_d;
	ip_d.s_addr=dest_ip;
	struct sr_rt* iface_rt_entry=get_routing_if(ps, ip_d);          /*Find rt entry to send request from. */
	struct sr_if* iface=sr_get_interface(ps->sr, iface_rt_entry->interface); /*Find iface associated with rt entry */
	assert(iface); 
	memmove(request->ar_sha, iface->addr, ETHER_ADDR_LEN); /*Set ARP source address to interface's hardware address */
	request->ar_sip=iface->ip;  /*Set ARP source IP address to interface's IP address */
	
	/* Set ARP dest MAC address to 00:00:00:00:00:00 */
	int i=0;
	for(i=0; i<ETHER_ADDR_LEN; i++)
	{
		request->ar_tha[i]=0x00;
	}
	
	/*Set ARP target IP address to interface's gateway IP address */
	request->ar_tip=iface_rt_entry->gw.s_addr; 
	
	
	/*ARP Constructed, Now Construct Ethernet Header */
	struct sr_ethernet_hdr* new_eth;
	new_eth=(struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
	memmove(new_eth->ether_shost, iface->addr,ETHER_ADDR_LEN); /*Ethernet Source Address is Interface's Address */
	
	
	ps->rt_entry = iface_rt_entry; /*******************/
	
	/*Set Ethernet dest MAC address to ff:ff:ff:ff:ff:ff (Broadcast) */
	for(i=0; i<ETHER_ADDR_LEN; i++)
	{
		new_eth->ether_dhost[i]=0xff;
	}
	
	new_eth->ether_type=htons(ETHERTYPE_ARP);
	
	int eth_offset=sizeof(struct sr_ethernet_hdr);
	
	/* Put new Ethernet and ARP Header in Response */
	memmove(ps->response, new_eth, eth_offset);
	memmove((ps->response + eth_offset), request, sizeof(struct sr_arphdr));
	
	/*Free Construct ARP and Ethernet Headers */
	if(request)
		free(request);
	if(new_eth)	
		free(new_eth);
		
	ps->res_len=eth_offset + sizeof(struct sr_arphdr);
}


