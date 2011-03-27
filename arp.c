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
	uint32_t targetIP=ntohl(arp_hdr->ar_tip);
	struct sr_if * iface=ps->sr->if_list;
	while(iface!=NULL)
	{
			sr_print_if(iface);
		if(htonl(iface->ip)==targetIP)
		{
			printf("IP matches interface: %s\n", iface->name);
			break;
		}
		else
		{
			iface=iface->next;
		}
	}
	printf("Didn't find matching IP Address for interface.\n");
}


