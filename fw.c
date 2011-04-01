
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "fw.h"
#include "sr_router.h"
#include "sr_if.h"

int init_rules_table(struct sr_instance* sr, const char* filename)

{

  FILE* fp = 0;
  char line[BUFSIZ];
  char sourceIPin[32];
  char destIPin[32];
  struct in_addr srcIP;
  struct in_addr dstIP;
  unsigned int IPprotocol;
  unsigned int srcPort;
  unsigned int dstPort;

  assert(filename);
  if(access(filename,R_OK) != 0)
    {
      perror("access");
      return 0;
    }

fp = fopen(filename,"r");

 while(fgets(line,BUFSIZ,fp) != 0)
	{
	  sscanf(line,"%s %s %u %u %u",sourceIPin,destIPin,&IPprotocol,&srcPort,&dstPort);
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
	  add_rule(sr, srcIP.s_addr, dstIP.s_addr, (uint8_t) IPprotocol, (uint16_t) srcPort, (uint16_t) dstPort);
	  printf("Adding to rule table:\n");
	  printf("%s\t%s\t%u\t%u\t%u\n",sourceIPin, destIPin, IPprotocol, srcPort, dstPort);
	}
  return 1;

}

void add_rule(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	if(sr->rules == 0)
	{

		sr->rules = (struct ft_entry*) malloc(sizeof(struct ft_entry));
		sr->rules->ip_s = ip_s;
		sr->rules->ip_d = ip_d;
		
		
		struct in_addr dip;
		dip.s_addr = sr->rules->ip_d;
		printf("Dest IP added to rule: %s\n", inet_ntoa(dip));
		
		sr->rules->protocol = protocol;
		sr->rules->port_s = port_s;
		sr->rules->port_d = port_d;
		sr->rules->exp_time = 0;
		sr->rules->ttl_updates = 0;
		sr->rules->next = 0;
	}
	else
	{
		struct ft_entry *walker = sr->rules;
		while(walker->next)
		{
			walker = walker->next;
		}
		walker->next = (struct ft_entry *)malloc(sizeof(struct ft_entry));
		walker=walker->next;
		walker->ip_s = ip_s;
		walker->ip_d = ip_d;
		
		struct in_addr dip;
		dip.s_addr = walker->ip_d;
		printf("Dest IP added to rule: %s\n", inet_ntoa(dip));
		
		walker->protocol = protocol;
		walker->port_s = port_s;
		walker->port_d = port_d;
		walker->exp_time = 0;
		walker->ttl_updates = 0;
		walker->next = 0;
	}
}



/* returns 1 if success, 0 if error */

int init_if_config(struct sr_instance* sr, const char* filename)
{

  FILE* fp = 0;
  char line[BUFSIZ];
  char if_name[sr_IFACE_NAMELEN];
  char category[CAT_NAME_LEN];
  char *exter = FW_EXTERNAL;
  char *inter = FW_INTERNAL;
  struct if_cat_list *int_walker = sr->inter;
  struct if_cat_list *ext_walker = sr->exter;
  assert(filename);
  if(access(filename,R_OK) != 0)
    {
      perror("access");
      return 0;
    }
fp = fopen(filename,"r");

 while(fgets(line,BUFSIZ,fp) != 0)
 {
	  sscanf(line,"%s %s",if_name,category);
	  if(strcmp(category, exter) == 0)
	  {
	  	if(sr->exter == 0)
	  	{
	  		sr->exter = (struct if_cat_list *)malloc(sizeof(struct if_cat_list));
	  		strncpy(sr->exter->name, if_name, sr_IFACE_NAMELEN);
	  		sr->exter->next = 0;
	  		ext_walker = sr->exter;
	  	}
	  	else
	  	{
	  		ext_walker->next = (struct if_cat_list *)malloc(sizeof(struct if_cat_list));
	  		ext_walker = ext_walker->next;
	  		strncpy(ext_walker->name, if_name, sr_IFACE_NAMELEN);
	  		ext_walker->next = 0;
	  	}
	  }
	  else if(strcmp(category, inter) == 0)
	  {
	  	if(sr->inter == 0)
	  	{
	  		sr->inter = (struct if_cat_list *)malloc(sizeof(struct if_cat_list));
	  		strncpy(sr->inter->name, if_name, sr_IFACE_NAMELEN);
	  		sr->inter->next = 0;
	  		int_walker = sr->inter;
	  	}
	  	else
	  	{
	  		int_walker->next = (struct if_cat_list *)malloc(sizeof(struct if_cat_list));
	  		int_walker = int_walker->next;
	  		strncpy(int_walker->name, if_name, sr_IFACE_NAMELEN);
	  		int_walker->next = 0;
	  	}
	  }
	  else
	  {
	  	printf("Error with the interface configuration file\n");
	  }
  }
  return 1;	
}

void print_if_config(struct sr_instance* sr)
{
	printf("Interface Config:\n");
	
	printf("External interfaces:\t");
	struct if_cat_list *walker = sr->exter;
	while(walker)
	{
		printf("%s\t", walker->name);
		walker = walker->next;
	}
	printf("\n");
	
	walker = sr->inter;
	printf("Internal interfaces:\t");
	while(walker)
	{
		printf("%s\t", walker->name);
		walker = walker->next;
	}
	printf("\n");
}


int is_external(struct sr_instance* sr, char *iface)
{
	struct if_cat_list *walker = sr->exter;
	while(walker)
	{
		if(strcmp(walker->name, iface) == 0)
		{
			return 1;
		}
		else
		{
			walker = walker->next;
		}
	}
	return 0;
}

int is_internal(struct sr_instance* sr, char *iface)
{
	struct if_cat_list *walker = sr->inter;
	while(walker)
	{
		if(strcmp(walker->name, iface) == 0)
		{
			return 1;
		}
		else
		{
			walker = walker->next;
		}
	}
	return 0;
}



int check_connection(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	printf("Currently checking connection\n");
	
	if(rule_contains(sr, ip_s, ip_d, protocol, port_s, port_d))
	{
		printf("This matches a rule\n");
		return 1;
	}
	struct ft_entry *ent = ft_contains(sr, ip_s, ip_d, protocol, port_s, port_d);
	if(ent)
	{
		ent->exp_time += TTL_INCREMENT;
		ent->ttl_updates++;
		printf("This matches a current flow table connection\n");
		return 1;
	}
	return 0;
}

int tell_valid(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	struct ft_entry *ent = ft_contains(sr, ip_s, ip_d, protocol, port_s, port_d);
	if(ent)
	{
		ent->exp_time += TTL_INCREMENT;
		ent->ttl_updates++;
	}
	else if(sr->ft_size < MAX_FT_SIZE)
	{
		add_connect(sr, ip_s, ip_d, protocol, port_s, port_d);
	}
	else
	{
		remove_stale_entries(sr);
		if(sr->ft_size < MAX_FT_SIZE)
		{
			add_connect(sr, ip_s, ip_d, protocol, port_s, port_d);
		}
		else
		{
			return 0;
		}
	}
	return 1;

}

void add_connect(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	if(sr->flow_table == 0)
	{
		sr->flow_table = (struct ft_entry*) malloc(sizeof(struct ft_entry));
		sr->flow_table->ip_s = ip_s;
		sr->flow_table->ip_d = ip_d;
		sr->flow_table->protocol = protocol;
		sr->flow_table->port_s = port_s;
		sr->flow_table->port_d = port_d;
		sr->flow_table->exp_time = time(NULL) + TTL_INCREMENT;
		sr->flow_table->ttl_updates = 0;
		sr->flow_table->next = 0;
		sr->ft_size++;
	}
	else
	{
		struct ft_entry *walker = sr->flow_table;
		while(walker->next)
		{
			walker = walker->next;
		}
		walker->next = (struct ft_entry *)malloc(sizeof(struct ft_entry));
		walker = walker->next;
		walker->ip_s = ip_s;
		walker->ip_d = ip_d;
		walker->protocol = protocol;
		walker->port_s = port_s;
		walker->port_d = port_d;
		walker->exp_time = time(NULL) + TTL_INCREMENT;
		walker->ttl_updates = 0;
		walker->next = 0;
		sr->ft_size++;	
	}
}

void remove_stale_entries(struct sr_instance *sr)
{
	struct ft_entry *prev = 0;
	struct ft_entry *walker = sr->flow_table;
	time_t current = time(NULL);
	while(walker)
	{
		if(walker->ttl_updates > MAX_TTL_UPDATES || walker->exp_time < current)
		{
			if(prev == 0)
			{
				sr->flow_table = sr->flow_table->next;
				free(walker);
				walker = sr->flow_table;
				sr->ft_size--;
			}
			else if(walker->next == 0)
			{
				free(walker);
				sr->ft_size--;
			}
			else
			{
				prev->next = walker->next;
				free(walker);
				sr->ft_size--;
			}
		}
		else
		{
			walker = walker->next;
		}
	}
}

struct ft_entry* ft_contains(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	struct ft_entry *walker = sr->flow_table;
	time_t current = 0;
	while(walker)
	{
		if((walker->ip_s == ip_s) && (walker->ip_d == ip_d) && (walker->protocol == protocol) && 
			(walker->port_s == port_s) && (walker->port_d == port_d))
		{
			current = time(NULL);
			if((walker->exp_time >= current) && (walker->ttl_updates <= MAX_TTL_UPDATES))
			{
				return walker;
			}
			else
			{
				walker = walker->next;
			}
		}
		else
		{
			walker = walker->next;
		}
	}
	return NULL;
}

void print_rule_table(struct sr_instance *sr)
{
	printf("Rule Table\nSource IP\tDest IP\tProt\tSource Port\tDest Port\n");
	
	struct ft_entry *walker = sr->rules;
	while(walker)
	{
		struct in_addr sip;
		sip.s_addr = walker->ip_s;
		struct in_addr dip;
		dip.s_addr = walker->ip_d;
		printf("Dest IP: %s\n", inet_ntoa(dip));
		printf("%s\t %s \t %u\t %u\t %u\n", inet_ntoa(sip), inet_ntoa(dip), walker->protocol, 
				walker->port_s, walker->port_d);
		walker = walker->next;
	}
}

int rule_contains(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	struct ft_entry *walker = sr->rules;
	while(walker)
	{
		if((walker->ip_s == ip_s) || (walker->ip_s == 0))
		{
			if((walker->ip_d == ip_d) || (walker->ip_d == 0))
			{
				if((walker->protocol == ip_d) || (walker->protocol == 0))
				{
					if((walker->port_s == port_s) || (walker->port_s == 0))
					{
						if((walker->port_d == port_d) || (walker->port_d == 0))
						{
							return 1;
						}
						else
							walker = walker->next;
					}
					else
						walker = walker->next;
				}
				else
					walker = walker->next;
			}
			else
				walker = walker->next;
		}
		else
			walker = walker->next;
	}
	return 0;
}












