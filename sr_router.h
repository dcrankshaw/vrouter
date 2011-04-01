/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>

#include "sr_protocol.h"


/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
    struct arp_cache_entry* arp_cache;
    struct packet_buffer* queue;
    struct ft_entry* flow_table;
    struct ft_entry* rules;
    int ft_size;
    struct if_cat_list* inter;
    struct if_cat_list* exter;
};

/* -----------------------------------------------------------------------
* struct packet_state
*
* Encapsulation of the state information for all methods used to generate
* and forward a packet received by sr_handlepacket().
* ----------------------------------------------------------------------- */
struct packet_state
{
	struct sr_instance *sr; /* the instance */
	uint8_t *packet;		/* the remnants of the original packet as it is stripped */
	unsigned int len;		/* the length of the original packet (decreased as lower layer headers
							   get stripped away). This length ensures no unallocated memory
							   gets accessed */
	char *interface;		/* interface at which the packet was received */
	uint8_t *response;		/* the response packet (ethernet header included) */
	unsigned int res_len;	/* the length of the response packet */
	struct sr_rt *rt_entry;
	short forward;			/* 1 if forwarding, 0 if return to sender */
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
int handle_ip(struct packet_state *);
void update_ip_hdr(struct ip*);
struct sr_rt* get_routing_if(struct packet_state*, struct in_addr);
void leave_hdr_room(struct packet_state *, int);
int create_eth_hdr(uint8_t *, struct packet_state *, struct sr_ethernet_hdr *);
uint16_t cksum(uint8_t *, int);


/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
