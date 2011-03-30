/*
firewall.c
Adam Gross
Revised 3/28/11 11:00 AM
http://yuba.stanford.edu/vns/assignments/firewall
*/

/*
eth0 is external
eth1 is internal
eth2 is internal

Pseudocode (goes in sr_router.c):

if (sr_handlepacket.if == eth0)
    if(dest == eth1 || dest == eth2)
     {
       drop packet, no response;
       return;
     }
    if(dest == app1 || dest == app2)
     {
       if(check_connection(sr, sourceIP, destIP, prtcl, sourcePort, destPort) == 0)
        {       
	  packet denied;
	  return;
        }
       if(check_connection(sr, sourceIP, destIP, prtcl, sourcePort, destPort) == 1)
        {
	 packed allowed;
	 return;
	}
     }
if (sr_handlepacket.if == eth1 || sr_handlepacket.if == eth2)
{
    if(sr_add_ft_entry(sr, sourceIP, destIP, prtcl, sourcePort, destPort) == 1)
       return;
    else
       flow table is full - send ICMP "connection refused" and generate log entry;
    if(sr_add_fr_entry(sr, destIP, sourceIP, prtcl, destPort, sourcePort) == 1)
       return;
    else
       flow table is full - send ICMP "connection refused" and generate log entry;
}
____________________________________________________________________________________________

Data members for router (goes in sr_router.h, in the sr_instance struct):

#include "firewall.h"

struct ft* flow_table; //flow table
struct rule* rule_table; //rules table
int ft_size; //number of entries in flow table

_____________________________________________________________________________________________

Notes:

_flow table_
<srcIP, dstIP, IPprotocol, src-port, dst-port>
 */

#include "firewall.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

/* returns 1 if success, 0 if error */
int init_rules_table(struct sr_instance* sr, const char* filename)
{
  FILE* fp = 0;
  char line[BUFSIZ];
  char sourceIPin[32];
  char destIPin[32];
  struct in_addr srcIP;
  struct in_addr dstIP;
  uint8_t IPprotocol;
  int srcPort;
  int dstPort;

  assert(filename);
  if(access(filename,R_OK) != 0)
    {
      perror("access");
      return 0;
    }

 fp = fopen(filename,"r");
	
 while(fgets(line,BUFSIZ,fp) != 0)
	{
	  sscanf(line,"%s %s %d %d %d",sourceIPin,destIPin,(int*)&IPprotocol,&srcPort,&dstPort);
	  if(inet_aton(sourceIPin,&srcIP) == 0)
	{
	  fprintf(stderr, "Error loading rules table, cannot convert %s to valid IP\n", sourceIPin);
	  return 0;
	}
	  if(inet_aton(destIPin,&dstIP) == 0)
	{
	  fprintf(stderr, "Error loading rules table, cannot convert %s to valid IP\n", destIPin);
	  return 0;
	}
	  add_rule(sr, srcIP, dstIP, IPprotocol, srcPort, dstPort);
	}
  return 1;
	
}

void print_rules(struct sr_instance* sr)
{
  struct rule* rule_walker = 0;
  
  if(sr->rule_table == 0)
    {
      printf("Rule Table is empty/n");
      return;
    }

  printf("Source IP\tDest IP\tProtocol\tSource Port\tDest Port");

  rule_walker = sr->rule_table;
  
  print_rule_entry(rule_walker);
  while(rule_walker->next)
    {
      rule_walker = rule_walker->next;
      print_rule_entry(rule_walker);
    }
}  /* end print_rules() */

void print_rule_entry(struct rule* entry)
{
  assert(entry);
  
  printf("%s\t\t",inet_ntoa(entry->srcIP));
  printf("%s\t",inet_ntoa(entry->dstIP));
  printf("%u\t",entry->IPprotocol);
  printf("%i\t",entry->srcPort);
  printf("%i\n",entry->dstPort);
} /* end print_rule_entry() */





/* returns 1 if the entry was successfully added, 0 if it was not added */
int add_rule(struct sr_instance* sr, struct in_addr srcIP, struct in_addr dstIP, uint8_t IPprotocol, int srcPort, int dstPort)
{
  struct rule* rule_walker = 0;
  
  /* see if the table is empty */
  if(sr->rule_table == 0)
    {
      sr->rule_table = (struct rule*)malloc(sizeof(struct rule));
      assert(sr->rule_table);
      sr->rule_table->next = 0;
      sr->rule_table->srcIP = srcIP;
      sr->rule_table->dstIP = dstIP;
      sr->rule_table->IPprotocol = IPprotocol;
      sr->rule_table->srcPort = srcPort;
      sr->rule_table->dstPort = dstPort;

      return 1;
    }

  /* find the end of the linked list */
  rule_walker = sr->rule_table;
  while(rule_walker->next)
	{
      rule_walker = rule_walker->next;
    }
  rule_walker->next = (struct rule*)malloc(sizeof(struct rule));
  assert(rule_walker->next);
  rule_walker = rule_walker->next;
  rule_walker->next = 0;
  rule_walker->srcIP = srcIP;
  rule_walker->dstIP = dstIP;
  rule_walker->IPprotocol = IPprotocol;
  rule_walker->srcPort = srcPort;
  rule_walker->dstPort = dstPort;

  return 1;
} /* end add_rule() */

/* returns 1 if the entry was successfully added, 0 if it was not added */
int add_ft_entry(struct sr_instance* sr, struct in_addr srcIP, struct in_addr dstIP, uint8_t IPprotocol, int srcPort, int dstPort)
{
  struct ft* ft_walker = 0;

  int maxSize = MAX_FT_SIZE;

  /* check to see if table is full */
  if(sr->ft_size == maxSize)
    {
      remove_old_ft_entries(sr);
    }
    /* if remove_old_ft_entries() didn't remove anything */
  if(sr->ft_size == maxSize)
    {
      return 0;  /* ICMP "connection refused" returned and log entry generated */
    }
  
  /* see if the table is empty */
  if(sr->flow_table == 0)
    {
      sr->flow_table = (struct ft*)malloc(sizeof(struct ft));
      assert(sr->flow_table);
      sr->flow_table->next = 0;
      sr->flow_table->srcIP = srcIP;
      sr->flow_table->dstIP = dstIP;
      sr->flow_table->IPprotocol = IPprotocol;
      sr->flow_table->srcPort = srcPort;
      sr->flow_table->dstPort = dstPort;
      sr->flow_table->creation_time = time(NULL);
      sr->flow_table->ttl += TTL_INCREMENT;
      sr->ft_size++;

      return 1;
    }
  /* find the end of the linked list */
  ft_walker = sr->flow_table;
  while(ft_walker->next)
    {
      ft_walker = ft_walker->next;
    }
  ft_walker->next = (struct ft*)malloc(sizeof(struct ft));
  assert(ft_walker->next);
  ft_walker = ft_walker->next;
  ft_walker->next = 0;
  ft_walker->srcIP = srcIP;
  ft_walker->dstIP = dstIP;
  ft_walker->IPprotocol = IPprotocol;
  ft_walker->srcPort = srcPort;
  ft_walker->dstPort = dstPort;
  ft_walker->creation_time = time(NULL);
  ft_walker->ttl += TTL_INCREMENT;
  sr->ft_size++;
  
  return 1;
} /* end add_ft_entry() */

/* returns 0 if not in table, 1 if in table */
int ft_contains(struct sr_instance* sr, struct in_addr srcIP, struct in_addr dstIP, uint8_t IPprotocol, int srcPort, int dstPort)
{
	struct ft* ft_walker = 0;
  
	ft_walker = sr->flow_table;
  	while(ft_walker)
    {
      
    	if((ft_walker->srcIP.s_addr == srcIP.s_addr) && (ft_walker->dstIP.s_addr == dstIP.s_addr) && (ft_walker->IPprotocol == IPprotocol) && (ft_walker->srcPort == srcPort) && (ft_walker->dstPort == dstPort))
		{
	  		ft_walker->ttl += TTL_INCREMENT;
	  		return 1;
		}
		ft_walker = ft_walker->next;
    }
  
  return 0;
} /* end ft_contains() */

/* returns 0 if not in table, 1 if in table */
int rule_contains(struct sr_instance* sr, struct in_addr srcIP, struct in_addr dstIP, uint8_t IPprotocol, int srcPort, int dstPort)
{
	struct rule* rule_walker = 0;
	
	
	rule_walker = sr->rule_table;
	while(rule_walker)
	{
		/* if the rule contains a wildcard, temporarily convert the parameter to a wildcard so it will match */
		if(rule_walker->srcIP.s_addr == 0)
		{
			srcIP.s_addr = 0;
		}
		if(rule_walker->dstIP.s_addr == 0)
		{
			dstIP.s_addr = 0;
		}
		if(rule_walker->IPprotocol == 0)
		{
			IPprotocol = 0;
		}
		if(rule_walker->srcPort == 0)
		{
			srcPort = 0;
		}
		if(rule_walker->dstPort == 0)
		{
			dstPort = 0;
		}
		if((rule_walker->srcIP.s_addr == srcIP.s_addr) && (rule_walker->dstIP.s_addr == dstIP.s_addr) && (rule_walker->IPprotocol == IPprotocol) && (rule_walker->srcPort == srcPort) && (rule_walker->dstPort == dstPort))
		{
			return 1;
		}
		rule_walker = rule_walker->next;
	}
	
	return 0;
}

void print_ft(struct sr_instance* sr)
{
  struct ft* ft_walker = 0;
  
  if(sr->flow_table == 0)
    {
      printf("Flow Table is empty/n");
      return;
    }

  printf("Source IP\tDest IP\tProtocol\tSource Port\tDest Port");

  ft_walker = sr->flow_table;
  
  print_ft_entry(ft_walker);
  while(ft_walker->next)
    {
      ft_walker = ft_walker->next;
      print_ft_entry(ft_walker);
    }
}  /* end print_ft() */

void print_ft_entry(struct ft* entry)
{
  assert(entry);
  
  printf("%s\t\t",inet_ntoa(entry->srcIP));
  printf("%s\t",inet_ntoa(entry->dstIP));
  printf("%u\t",entry->IPprotocol);
  printf("%i\t",entry->srcPort);
  printf("%i\n",entry->dstPort);
} /* end print_ft_entry() */

void remove_old_ft_entries(struct sr_instance* sr)
{
  struct ft* ft_walker = 0;
  time_t cur = time(NULL);
  int maxTTL = MAX_ENTRY_TTL;

  ft_walker = sr->flow_table;
  if((cur - ft_walker->creation_time - ft_walker->ttl) < maxTTL)
    {
      sr->flow_table = ft_walker->next;
      free(ft_walker);
      sr->ft_size--;
    }
  while(ft_walker->next)
    {
      // ft_walker = ft_walker->next;
      if((cur - ft_walker->next->creation_time - ft_walker->next->ttl) < maxTTL)
	{
	  struct ft* del = 0;
	  del = ft_walker->next;
	  ft_walker->next = ft_walker->next->next;
	  free(del);
	  sr->ft_size--;
	}
    }
} /* end remove_old_ft_entries() */

/* returns 1 if the connection is valid, returns 0 if the connection is invalid */
int check_connection(struct sr_instance* sr, struct in_addr srcIP, struct in_addr dstIP, uint8_t IPprotocol, int srcPort, int dstPort)
{
  if(ft_contains(sr, srcIP, dstIP, IPprotocol, srcPort, dstPort) == 1)
    {
      return 1;
    }
    if(ft_contains(sr, dstIP, srcIP, IPprotocol, dstPort, srcPort) == 1)
    {
      return 1;
    }
  if(rule_contains(sr, srcIP, dstIP, IPprotocol, srcPort, dstPort) == 1)
    {
      return 1;
    }
  return 0;
} /* end check_connection() */
