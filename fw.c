
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

/*******************************************************************
*   Initializes Rules Table that lists external IP addresses that are allowed through server and 
*   which internal IP address they are allowed to access.
*******************************************************************/
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

/*Read in information from file.*/
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
	}
  return 1;

}

/*******************************************************************
*   Add a rule to rule table.
*******************************************************************/
void add_rule(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	if(sr->rules == 0)  /*Empty Rule Table*/
	{

		sr->rules = (struct ft_entry*) malloc(sizeof(struct ft_entry));
		sr->rules->ip_s = ip_s;
		sr->rules->ip_d = ip_d;
		
		struct in_addr dip;
		dip.s_addr = sr->rules->ip_d;
		
		sr->rules->protocol = protocol;
		sr->rules->port_s = port_s;
		sr->rules->port_d = port_d;
		sr->rules->exp_time = 0;
		sr->rules->ttl_updates = 0;
		sr->rules->next = 0;
	}
	else                /* Add new entry to end. */
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
		walker->protocol = protocol;
		walker->port_s = port_s;
		walker->port_d = port_d;
		walker->exp_time = 0;       /* Never will expire. */
		walker->ttl_updates = 0;    /* Will never be updated. */
		walker->next = 0;
	}
}

/*******************************************************************
*   Reads in list of internal and external interfaces. Adds to external interface list and internal
*   interface list. Will allow multiple external interfaces.
*******************************************************************/
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


/*******************************************************************
* prints the lists containing the internal and external interfaces
*******************************************************************/
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


/*******************************************************************
* determines whether a given interface is external based on the name
*******************************************************************/
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


/* determines whether a given interface is internal based on the name */
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


/***************************************************************************
 * Determines whether a given connection (based on source and dest IP addresses,
 * port numbers, and protocol) is valid (i.e. is in the rule table or flow table).
 * Also, if it is in the flow table, it updates the ttl of the connection.
 *
 ***************************************************************************/
int check_connection(struct sr_instance *sr, uint32_t ip_s, uint32_t ip_d,
					uint8_t protocol, uint16_t port_s, uint16_t port_d)
{
	
	if(rule_contains(sr, ip_s, ip_d, protocol, port_s, port_d))
	{
		return 1;
	}
	struct ft_entry *ent = ft_contains(sr, ip_s, ip_d, protocol, port_s, port_d);
	if(ent)
	{
		ent->exp_time += TTL_INCREMENT;
		ent->ttl_updates++;
		return 1;
	}
	return 0;
}

/*******************************************************************
*   Called when packet is received from internal IP and needs to be sent to external. Checks if 
*   entry is already in flow table and still valid. If not, adds to flow table. If flow table is 
*   greater than or equal to max size, the invalid entries are deleted. If flow table is still 
*   greater than or equal to max size, an ICMP Port Unreachable is sent.
*******************************************************************/
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
			return 0;   /* ICMP host unreachable will be sent. */
		}
	}
	return 1;

}

/*******************************************************************
*   After internal IP initiates a connection, the connection is added to the flow table. 
*******************************************************************/
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

/*******************************************************************
*   Removes entries that are no longer valid based on expiration time or number of times TTL was
*   updated.
*******************************************************************/
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

/*******************************************************************
*   Checks if the header information is contained in the flow table. If it is and still valid, 
*   return the entry.
*******************************************************************/
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

/*******************************************************************
*   Prints Rule Table.
*******************************************************************/
void print_rule_table(struct sr_instance *sr)
{
	printf("-----Rule Table-----\n");
	printf("Source IP\t\tDest IP\t\tProt\tSource Port\tDest Port\n");
    struct ft_entry* walker=sr->rules;
    while(walker)
    {
        print_ft_entry(walker);
        walker=walker->next;
    }
}

/*******************************************************************
*   Checks if external IP and internal dest IP are in rule table. Returns 1 if they are, returns 
*   NULL if they should not be.
*******************************************************************/
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

/*******************************************************************
*   Prints flow table entry.
*******************************************************************/
void print_ft_entry(const struct ft_entry* entry)
{
    struct in_addr sip;
    sip.s_addr = entry->ip_s;
    struct in_addr dip;
    dip.s_addr = entry->ip_d;
    printf("%s\t\t",inet_ntoa(sip));
    printf("%s\t",inet_ntoa(dip));
    printf("%u\t",entry->protocol);
    printf("%i\t\t",entry->port_s);
    printf("%i\n",entry->port_d);
}

/*******************************************************************
*   Prints flow table.
*******************************************************************/
void print_flow_table(struct sr_instance* sr)
{
    printf("-----Flow Table-----\n");
	printf("Source IP\t\tDest IP\t\tProt\tSource Port\tDest Port\n");
    struct ft_entry* walker=sr->flow_table;
    while(walker)
    {
        print_ft_entry(walker);
        walker=walker->next;
    }
}












