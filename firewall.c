


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>



#include "firewall.h"
#include "sr_if.h"


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

    printf("Entered add entry method.\n");
    printf("-------FLOW TABLE --------\n");
    print_ft(sr);
    
    struct ft* ft_walker = 0;
    int maxSize = MAX_FT_SIZE;

  /* check to see if table is full */
  if(sr->ft_size >= maxSize)
    {
        printf("Flow table is max size.\n");
        remove_old_ft_entries(sr);
    }

    /* if remove_old_ft_entries() didn't remove anything */
  if(sr->ft_size >= maxSize)
    {

	/***************************************
	SEND AN ICMP RESPONSE HOST UNREACHABLE
	****************************************/
	printf("Delete failed and Rule table is still max size.\n");

return 0;  /* ICMP "connection refused" returned and log entry generated */
    }

  /* -------------------------------------
   * Check if flow table already contains the connection
   * If it does, we need to update ttl, but not re-add
   * -------------------------------------*/

   if(ft_contains(sr, srcIP, dstIP, IPprotocol, srcPort, dstPort) == 1)
   {
        printf("Connection already contained in flow table.\n");
        return 1;
   }

  

  printf("Going to add now.\n");
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

      time(&sr->flow_table->creation_time);

      sr->flow_table->ttl += TTL_INCREMENT;

      sr->ft_size++;



      return 1;

      

    }

  /* find the end of the linked list */

  ft_walker = sr->flow_table;

  

  assert(ft_walker);

  

  

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

  	time_t maxTTL = MAX_ENTRY_TTL;
  	int cur = 0;
ft_walker = sr->flow_table;
  	
  	while(ft_walker)
    {
    	if((ft_walker->srcIP.s_addr == srcIP.s_addr) && (ft_walker->dstIP.s_addr == dstIP.s_addr) && (ft_walker->IPprotocol == IPprotocol) && (ft_walker->srcPort == srcPort) && (ft_walker->dstPort == dstPort))

		{

			
			cur = time(NULL);
			/*Check if packet is expired*/
	  		if((cur - ft_walker->creation_time )> ft_walker->ttl)
	  		{
	  		   printf("CURrent time hates us.\n");
	  		   return 0;
	  		  }
	  		    
	  		    if(ft_walker->ttl > maxTTL)
	        {
	  			printf("ttl sucks.\n");
	  			return 0;
	  		}

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



printf("Source IP\tDest IP\tProtocol\tSource Port\tDest Port\tTTL\n");

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

  printf("%s\t\t",inet_ntoa(entry->dstIP));

  printf("%u\t",entry->IPprotocol);

  printf("%i\t",entry->srcPort);

  printf("%i\t",entry->dstPort);
  int expired = time(NULL) - entry->creation_time - entry->ttl;
  printf("%u\n",expired);

} /* end print_ft_entry() */



void remove_old_ft_entries(struct sr_instance* sr)

{
  struct ft* ft_walker = 0;
  struct ft* prev = 0;
  struct ft* del = 0;
  time_t cur = time(NULL);
  int maxTTL = MAX_ENTRY_TTL;

  ft_walker = sr->flow_table;
  print_ft(sr);
  while(ft_walker)
  {
  	if((cur - ft_walker->creation_time > ft_walker->ttl) || (ft_walker->ttl > maxTTL))
  	{
  		if(prev == 0)
  		{
  			del = ft_walker;
  			sr->flow_table = sr->flow_table->next;
  			ft_walker = sr->flow_table;
  			sr->ft_size--;
  			if(del)
  				free(del);
  		}
  		else if(!ft_walker->next)
  		{
            free(prev->next);
            sr->ft_size--;
            ft_walker = 0;
		}
		else
		{
			prev->next=ft_walker->next;
			sr->ft_size--;
			if(ft_walker)
				free(ft_walker);
			ft_walker = prev->next;
		}
	}
	else
	{
		prev=ft_walker;
		ft_walker=ft_walker->next;
	}
  }
} /* end remove_old_ft_entries() */



/* returns 1 if the connection is valid, returns 0 if the connection is invalid */

int check_connection(struct sr_instance* sr, struct in_addr srcIP, struct in_addr dstIP, uint8_t IPprotocol, int srcPort, int dstPort)

{

	if(rule_contains(sr, srcIP, dstIP, IPprotocol, srcPort, dstPort) == 1)

    {

      return 1;

    }

  if(ft_contains(sr, srcIP, dstIP, IPprotocol, srcPort, dstPort) == 1)

    {

      return 1;

    }

    if(ft_contains(sr, dstIP, srcIP, IPprotocol, dstPort, srcPort) == 1)

    {

      return 1;

    }



  return 0;

} /* end check_connection() */

