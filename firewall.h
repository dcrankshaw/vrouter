/*
firewall.h
Adam Gross
Revised 3/28/11 12:00 AM
*/

#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdint.h>

#include "sr_router.h"
#include "sr_if.h"

#define MAX_FT_SIZE	50
#define FW_EXTERNAL	"external"
#define FW_INTERNAL "internal"
#define CAT_NAME_LEN 32
#define TTL_INCREMENT	5  /* number of seconds */
#define MAX_ENTRY_TTL   100

/* node in the flow table */
struct ft
{
  struct in_addr srcIP;
  struct in_addr dstIP;
  uint8_t IPprotocol;
  int srcPort;
  int dstPort;
  time_t creation_time;
  time_t ttl;
  struct ft* next;
};

/* the struct containing the list of all internal/external interfaces */
struct if_cat_list
{
	char name[sr_IFACE_NAMELEN];
	struct if_cat_list *next; /* Should be either "external" or "internal" */
};

/* node (rule) in the rule table */
struct rule
{
  struct in_addr srcIP;
  struct in_addr dstIP;
  uint8_t IPprotocol;
  int srcPort;
  int dstPort;
  struct rule* next;
};

int init_rules_table(struct sr_instance*, const char*);
int init_if_config(struct sr_instance*, const char*);
int is_external(struct sr_instance*, char *);
int is_internal(struct sr_instance*, char *);
int add_rule(struct sr_instance*, struct in_addr, struct in_addr, uint8_t, int, int);
int add_ft_entry(struct sr_instance*, struct in_addr, struct in_addr, uint8_t, int, int);
int ft_contains(struct sr_instance*, struct in_addr, struct in_addr, uint8_t, int, int);
int rule_contains(struct sr_instance*, struct in_addr, struct in_addr, uint8_t, int, int);
void print_ft(struct sr_instance*);
void print_ft_entry(struct ft*);
void remove_old_ft_entries(struct sr_instance*);
int check_connection(struct sr_instance*, struct in_addr, struct in_addr, uint8_t, int, int);
void print_rules(struct sr_instance*);
void print_rule_entry(struct rule*);

#endif
