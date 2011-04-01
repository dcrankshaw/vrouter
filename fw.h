/**********************************************************************
 * Group name: jhugroup1
 * Members: Daniel Crankshaw, Maddie Stone, Adam Gross
 * CS344
 * 4/01/2011
 **********************************************************************/

#ifndef FW_H
#define FW_H

#include <stdlib.h>
#include <time.h>

#include "sr_if.h"
#include "sr_router.h"

#define FW_EXTERNAL	"external"
#define FW_INTERNAL "internal"
#define CAT_NAME_LEN 32




#define TTL_INCREMENT	50
#define	MAX_TTL_UPDATES	80
#define MAX_FT_SIZE	30


/* the struct containing the list of all internal/external interfaces */
struct if_cat_list
{
	char name[sr_IFACE_NAMELEN];
	struct if_cat_list *next; /* Should be either "external" or "internal" */
};

struct ft_entry
{
	uint32_t ip_s;
	uint32_t ip_d;
	uint8_t protocol;
	uint16_t port_s;
	uint16_t port_d;
	time_t exp_time;
	unsigned int ttl_updates;
	struct ft_entry *next;
};


void add_rule(struct sr_instance *, uint32_t, uint32_t, uint8_t, uint16_t, uint16_t);
void print_rule_table(struct sr_instance *sr);
int init_rules_table(struct sr_instance* , const char* );
int init_if_config(struct sr_instance* , const char* );
void print_if_config(struct sr_instance*);
int is_external(struct sr_instance* , char *);
int is_internal(struct sr_instance*, char *);
int check_connection(struct sr_instance *, uint32_t , uint32_t ,uint8_t , uint16_t , uint16_t );
int tell_valid(struct sr_instance *, uint32_t , uint32_t , uint8_t , uint16_t , uint16_t );
void add_connect(struct sr_instance *, uint32_t , uint32_t , uint8_t , uint16_t , uint16_t );
void remove_stale_entries(struct sr_instance *);
struct ft_entry* ft_contains(struct sr_instance *, uint32_t , uint32_t ,uint8_t , uint16_t , uint16_t );
int rule_contains(struct sr_instance *, uint32_t , uint32_t , uint8_t , uint16_t , uint16_t );
void print_flow_table(struct sr_instance* );
void print_ft_entry(const struct ft_entry* );

#endif