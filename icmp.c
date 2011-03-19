
/*-------------------------------------------------------------
*
*Method:
*Handle recieved ICMP packets
ICMP Functionality:
-traceroutes through and to router
-Can respond to ICMP echo requests
-
*
*
*-------------------------------------------------------------*/

void handle_icmp(struct sr_instance *sr,
				uint8_t *packet,
				unsigned int len,
				char *interface,
				struct ip *ip_hdr)
{
	uint8_t icmp_type = *packet++;
	switch(icmp_type)
	{
		case ICMPT_ECHOREPLY:
			if(*packet++ == 0)
				/*ping response*/
			break;
			
		case ICMPT_ECHOREQUEST:
		
			break;
		
		case ICMPT_TIMEEX:
		
			break;
	
	
	}



}