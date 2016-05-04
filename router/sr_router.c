/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
 #include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


int sr_handleip(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* in_f, uint8_t** ethernet_data_addr);
int sr_handlearp(struct sr_instance** sr, uint8_t** ethernet_data_addr, struct sr_if* in_f, unsigned int len);
int check_ip_sum(sr_ip_hdr_t* ip_header);
int decrement_ttl(sr_ip_hdr_t* ip_header);

void send_icmp(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* in_f, uint8_t type, uint8_t code);
void send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* in_f, unsigned char *ether_dest_addr, uint8_t type, uint8_t code);
void send_icmp_error(struct sr_instance* sr, uint8_t* packet, struct sr_if* in_f, uint8_t type, uint8_t code);
int check_if_for_us(sr_ip_hdr_t* ip_header);
int forward_packet(sr_ip_hdr_t* ip_header);
struct sr_rt * check_routing_table(struct sr_instance* sr, uint32_t ip_dest);
int masklength(uint32_t mask);
void handle_arp_reply(struct sr_instance *sr, uint8_t* arp_header, struct sr_if* in_f);
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *cache_req_ptr);

void broadcast_arp_req(struct sr_instance* sr, uint32_t nexthopIP, sr_ethernet_hdr_t* packet_to_forward, unsigned int len, struct sr_rt * routing_node, struct sr_if* nexthopInterface);
void sr_create_arp_req_packet(uint8_t* arp_pkt_buf, struct sr_arpreq * cache_req_ptr, struct sr_if* nexthopInterface);

void mergesort(struct sr_rt **routing_table);
void splitlist(struct sr_rt *head, struct sr_rt **firstref, struct sr_rt **secondref);
struct sr_rt *sortandmerge(struct sr_rt* firsthalf, struct sr_rt* secondhalf);

void convert_ip_to_htons(sr_ip_hdr_t** ip_header);
void ntoh_eth_hdr(sr_ethernet_hdr_t** eth_header_buffer);
void hton_eth_hdr(sr_ethernet_hdr_t** eth_header_buffer);
void ntoh_ip_hdr(sr_ip_hdr_t** ip_header_buffer);
void hton_ip_hdr(sr_ip_hdr_t** ip_header_buffer);
void ntoh_arp_hdr(sr_arp_hdr_t** arp_header_buffer);
void hton_arp_hdr(sr_arp_hdr_t** arp_header_buffer);

struct sr_if* sr_get_interface_from_ip(struct sr_instance* sr, uint32_t ip);
int sr_create_arp_packet(uint8_t** buf, sr_arp_hdr_t* req_arp_hdr, struct sr_if* r_if);


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/


static const uint8_t destHostAddr[ETHER_ADDR_LEN] =
   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t* packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if *in_f;

  /*We are storing the header inside of packet, which is the address of a buffer*/
  sr_ethernet_hdr_t* eth_header_buffer = (sr_ethernet_hdr_t*)packet;
  ntoh_eth_hdr(&eth_header_buffer);

  /* Find the interface packet came from */
  in_f = sr_get_interface(sr, interface);

  /*Get the address of the data located after the ethernet header*/
  uint8_t* ethernet_data_addr = packet + sizeof(sr_ethernet_hdr_t);

  if (eth_header_buffer->ether_type == ethertype_ip) {
    sr_handleip(sr, packet, len, in_f, &ethernet_data_addr);
  }
  else if (eth_header_buffer->ether_type == ethertype_arp) { /* We have recieved a packet containing ARP data */
    sr_handlearp(&sr, &ethernet_data_addr, in_f, len); /* Process ARP data */
  }

  

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

}/* end sr_ForwardPacket */

/* Send an ICMP packet */
void send_icmp(struct sr_instance* sr, 
               uint8_t* packet,
               unsigned int len,
               struct sr_if* in_f, 
               uint8_t type, 
               uint8_t code) {

  if (type == dest_net_unreach_type && code == dest_net_unreach_code) {
    send_icmp_error(sr, packet, in_f, type, code);
  } else if (type == dest_host_unreach_type && code == dest_host_unreach_code) {
    send_icmp_error(sr, packet, in_f, type, code);
  } else if (type == port_unreach_type && code == port_unreach_code) {
    send_icmp_error(sr, packet, in_f, type, code);
  } else if (type == 11 && code == 0) {
    send_icmp_error(sr, packet, in_f, type, code);
  } else {
    /* Should never reach here, we've put in the wrong type or code */
    return;
  }
}

/* Send an ICMP echo reply packet. */
void send_icmp_echo_reply(struct sr_instance* sr, 
                          uint8_t* packet, 
                          unsigned int len,
                          struct sr_if* in_f,
                          unsigned char *ether_dest_addr, 
                          uint8_t type, 
                          uint8_t code) {
  /* Get headers from packet */
  /*
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;*/
  sr_ip_hdr_t* sending_ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

  /* Create ICMP echo reply frame */
  /*int size_of_icmp_req_pkt = len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)); *//* Get size of ICMP echo request packet 
                                                                                         to put into data of echo reply */
  /*unsigned int sending_pkt_len = size_of_icmp_req_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);*/
  /*uint8_t * sending_pkt_eth_buf = (uint8_t *) malloc(sending_pkt_len); *//* Allocate mem for sending eth packet buffer */
  sr_ethernet_hdr_t * sending_eth_hdr = (sr_ethernet_hdr_t *) packet;

  /* Get the IP Buffer*/
  /*uint8_t * sending_ip_pkt_buf = sending_pkt_eth_buf + sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t * sending_ip_hdr = (sr_ip_hdr_t *) sending_ip_pkt_buf;*/

  /* Get the ICMP Buffer*/
  
  uint8_t * sending_icmp_pkt_buf = (uint8_t *) sending_ip_hdr + sizeof(sr_ip_hdr_t);
  sr_icmp_hdr_t * sending_icmp_hdr = (sr_icmp_hdr_t *) sending_icmp_pkt_buf;

  /* Build Ethernet Header */
  /*HERE -- SOURCE HOST eth_hdr->ether_shost -- ASK FOR THIS*/
  memcpy(sending_eth_hdr->ether_dhost, ether_dest_addr, ETHER_ADDR_LEN);
  memcpy(sending_eth_hdr->ether_shost, in_f->addr, ETHER_ADDR_LEN);
  sending_eth_hdr->ether_type = ethertype_ip;
  /* Convert to network byte ordering */
  hton_eth_hdr(&sending_eth_hdr);

  /* Build the IP header */
  sending_ip_hdr->ip_tos = 0;
  sending_ip_hdr->ip_len = ntohs(sending_ip_hdr->ip_len);
  /*sending_ip_hdr->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + size_of_icmp_req_pkt);*/ /* Length of IP header + ICMP header + data */
                                               /* According to Sec 4.1 of RFC6864: Originating sources MAY set 
                                                the IPv4 ID field of atomic datagrams to any value */   
  sending_ip_hdr->ip_off = htons(IP_DF);      /* Make this an atomic datagram */
  sending_ip_hdr->ip_ttl = 100;      /* Set at 100 */
  sending_ip_hdr->ip_sum = 0;
  uint32_t temp_src = sending_ip_hdr->ip_src;
  sending_ip_hdr->ip_src =  sending_ip_hdr->ip_dst;
  sending_ip_hdr->ip_dst = temp_src;
  /* Convert IP header to network byte order */
  hton_ip_hdr(&sending_ip_hdr);
 

  /* Build the ICMP header */
  sending_icmp_hdr->icmp_type = type; /* type is 0 */
  sending_icmp_hdr->icmp_code = code; /* doesn't have code, just set to 0 */
  sending_icmp_hdr->icmp_sum = 0;
  /*uint8_t * sending_icmp_data_buf = sending_icmp_pkt_buf + sizeof(sr_icmp_hdr_t);*/
  /* Copy the ICMP request data into the ICMP reply data */
  /* Recompute Check Sum */
  sending_icmp_hdr->icmp_sum = cksum(sending_icmp_hdr, sending_ip_hdr->ip_len - sending_ip_hdr->ip_hl*4 );
  
  /* Recompute IP header Check Sum */
  sending_ip_hdr->ip_sum = cksum(sending_ip_hdr, sending_ip_hdr->ip_hl * 4);
  /* =================== NEED TO SEND PACKET ======================= */
  sr_send_packet(sr, (uint8_t *) sending_eth_hdr, len, in_f->name);

}

/* Send an ICMP error packet. This includes both type 3 and type 11. */
void send_icmp_error(struct sr_instance* sr, 
                      uint8_t* packet, 
                      struct sr_if* in_f, 
                      uint8_t type, 
                      uint8_t code) {
  /* Get headers from packet */
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
  uint8_t * ip_pkt_buf = packet + sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  unsigned int sending_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

  /* Create reply frame */
  uint8_t * sending_pkt_eth_buf = (uint8_t *) malloc(sending_pkt_len); /* Allocate mem for sending eth packet buffer */
  sr_ethernet_hdr_t * sending_eth_hdr = (sr_ethernet_hdr_t *) sending_pkt_eth_buf;

  /* Get the IP Buffer*/
  uint8_t * sending_ip_pkt_buf = sending_pkt_eth_buf + sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t * sending_ip_hdr = (sr_ip_hdr_t *) sending_ip_pkt_buf;

  /* Get the ICMP Buffer*/
  uint8_t * sending_icmp_pkt_buf = sending_ip_pkt_buf + sizeof(sr_ip_hdr_t);
  sr_icmp_t3_hdr_t * sending_icmp_hdr = (sr_icmp_t3_hdr_t *) sending_icmp_pkt_buf;

  /* Build Ethernet Header */
  memcpy(sending_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(sending_eth_hdr->ether_shost, in_f->addr, ETHER_ADDR_LEN);
  sending_eth_hdr->ether_type = ethertype_ip;
  /* Convert to network byte ordering */
  hton_eth_hdr(&sending_eth_hdr);

  /* Build the IP header */
  sending_ip_hdr->ip_v = 4; 
  sending_ip_hdr->ip_hl = 5;
  sending_ip_hdr->ip_tos = 0;
  sending_ip_hdr->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  sending_ip_hdr->ip_id = ip_hdr->ip_id;      /* According to Sec 4.1 of RFC6864: Originating sources MAY set 
                                                the IPv4 ID field of atomic datagrams to any value */   
  sending_ip_hdr->ip_off = htons(IP_DF);            /* Make this an atomic datagram */
  sending_ip_hdr->ip_ttl = TTL_DEFAULT;       /* Set at 64 */
  sending_ip_hdr->ip_p = ip_protocol_icmp;
  sending_ip_hdr->ip_sum = 0;
  sending_ip_hdr->ip_src = in_f->ip;
  sending_ip_hdr->ip_dst = ip_hdr->ip_src;
  /* Convert IP header to network byte order */
  hton_ip_hdr(&sending_ip_hdr);
  /* Recompute Check Sum */
  sending_ip_hdr->ip_sum = cksum(sending_ip_hdr, sending_ip_hdr->ip_hl * 4);

  /* Build the ICMP header */
  sending_icmp_hdr->icmp_type = type;
  sending_icmp_hdr->icmp_code = code;
  sending_icmp_hdr->icmp_sum = 0;
  /* sending_icmp_hdr->unused; */     /* Unused always cleared to 0 */
  /* sending_icmp_hdr->next_mtu; */   /* For use when code set to 4, this isn't a case we consider so no worries */
  memcpy(sending_icmp_hdr->data, ip_pkt_buf, ICMP_DATA_SIZE); /* IP header + first 8 bytes of original datagram data */
  /* Recompute Check Sum */
  sending_icmp_hdr->icmp_sum = cksum(sending_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /* =================== NEED TO SEND PACKET ======================= */
  sr_send_packet(sr, sending_pkt_eth_buf, sending_pkt_len, in_f->name);

  free(sending_pkt_eth_buf);


  /*sending_ip_hdr->ip_hl*4 */
}

/*Returns 0 on success and error code on fail*/
int sr_handleip(struct sr_instance* sr, 
                uint8_t* packet,
                unsigned int len, 
                struct sr_if* in_f, 
                uint8_t** ethernet_data_addr){
  sr_ip_hdr_t* ip_header_buffer = (sr_ip_hdr_t*) *ethernet_data_addr;

  /* Get headers from packet */
  /*sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
  uint8_t * ip_pkt_buf = packet + sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)); */
  uint8_t * icmp_pkt_buf = packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) icmp_pkt_buf;
  struct sr_if* ret_if; /* return interface */

  if (check_ip_sum(ip_header_buffer) == 0) { /*Pass Checksum*/
    printf("Checksum Pass\n");
  }
  else { /*Fail Checksum*/
    printf("Checksum Fail\n");
    return -1;
  }

  /*If the TTL went to 0*/
  if (decrement_ttl(ip_header_buffer) == -1) {
    /*Send ICMP with the proper TTL decrease type and icmp code*/
    printf("TTL reached 0\n"); 
    send_icmp(sr, packet, len, in_f, time_exceed_type, time_exceed_code);
    return -1;
  }

  /*Check if the IP packet is for us and not a echo request*/
  ret_if = sr_get_interface_from_ip(sr, ip_header_buffer->ip_dst);
  if(ret_if &&  !(ip_header_buffer->ip_p == ip_protocol_icmp && 
      icmp_hdr->icmp_type == echo_req_type && icmp_hdr->icmp_code == echo_req_code)) {
    /* The IP packet is FOR US */    
    printf("FOR US, NOT ECHO REQ");

    /* Check if it is an echo request */
    if (ip_header_buffer->ip_p == ip_protocol_tcp || 
               ip_header_buffer->ip_p == ip_protocol_udp) {
      /* It is TCP/UDP send ICMP port unreachable 
         SEND: an ICMP port unreachable to sending host*/
      send_icmp(sr, packet, len, in_f, port_unreach_type, port_unreach_code);
    } else {
      ;
      /* According to the Assignment: IGNORE THE PACKET*/
    }

  } else {
    
    /*If it's not in the routing table, send ICMP net unreachable*/
    struct sr_rt * routing_node;

    uint32_t ip_dest;

    /*If it's for us, we want to send back to the source, so check for the source in the routing table*/
    if (ret_if) {
      /* The IP packet is FOR US */
      printf("FOR US\n");
      ip_dest = ip_header_buffer->ip_src;
    }
    /*If not for us, we want to keep forwarding to the destination so check for that in the routing table*/
    else {
      /* The IP packet is NOT FOR US */
      printf("NOT FOR US\n");
      ip_dest = ip_header_buffer->ip_dst;
    }

    if ((routing_node = check_routing_table(sr, ip_dest)) == NULL) { 
      printf("NOT in routing table\n");
      send_icmp(sr, packet, len, in_f, dest_net_unreach_type, dest_net_unreach_code);
    }
    else {
      printf("In routing table\n");
      /*Got the routing table node in routing_node */

      /*Next hop IP address is in gateway
       *Look it up in arpcache_lookup to see if we know the MAC address
      */
      uint32_t nexthopIP = routing_node->gw.s_addr;
      struct sr_arpentry *arp_dest = sr_arpcache_lookup(&(sr->cache), nexthopIP);
      struct sr_if* nexthopInterface = sr_get_interface(sr, routing_node->interface);


      /*Create an ethernet header in front of the packet to forward regardless of
        whether or not we've found the next hop IP: need it in both cases*/

      /*Allocate space for ethernet header and packet, copy in contents of packet*/
      uint8_t* eth_header_packet = malloc(len);

      uint8_t* ip_header = eth_header_packet + sizeof(sr_ethernet_hdr_t);

      uint8_t* only_packet = eth_header_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

      memcpy(ip_header, ip_header_buffer, sizeof(sr_ip_hdr_t));

      memcpy(only_packet, (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)), len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));

      /*Save it in struct form*/
      sr_ethernet_hdr_t* packet_to_forward = (sr_ethernet_hdr_t*)eth_header_packet;

      /*Now set the actual ethernet header for the packet*/
      packet_to_forward->ether_type = htons(ethertype_ip);
      memcpy(packet_to_forward->ether_shost, nexthopInterface->addr, ETHER_ADDR_LEN);




      /*If NULL, send out the arp request*/
      if(arp_dest == NULL){
        printf("Not in arp cache: need to send an ARP request!\n");
        broadcast_arp_req(sr, nexthopIP, packet_to_forward, len, routing_node, nexthopInterface);

      }

      /*Otherwise just forward the packet to arp_dest's MAC address*/
      else {

        /*It's for us, it must be an echo request*/
        if (ret_if) {
          /*Doesn't have a code so just passing 0 as code*/
          struct sr_if *interface = sr_get_interface(sr, routing_node->interface);
          send_icmp_echo_reply(sr, packet, len, interface, arp_dest->mac, echo_reply_type, 0);
        }
        else {

          printf("In arp cache: just forwarding the packet\n");

          memcpy(packet_to_forward->ether_dhost, arp_dest->mac, ETHER_ADDR_LEN);
          sr_send_packet(sr, (uint8_t*)packet_to_forward, len, routing_node->interface);
          
          /*Free the arp_dest that sr_arpcache_lookup created*/
          free(arp_dest);
        }
      }


    }

  }

  return 0;
}

/* Decrement TTL and recompute checksum */
int decrement_ttl(sr_ip_hdr_t* ip_header) {
  ip_header->ip_ttl -= 1;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);
  
  if (ip_header->ip_ttl == 0) {
    return -1;
  }
  else {
    return 0;
  }
}

/*Return -1 for fail, 0 for pass*/
int check_ip_sum(sr_ip_hdr_t* ip_header){

  uint16_t header_sumval = ip_header->ip_sum;
  ip_header->ip_sum = 0;

  /*Checksum here, multiply ip header length by 4 because it is in 
  words right now, change to bits*/
  uint16_t cksum_val = cksum(ip_header, ip_header->ip_hl * 4);


  if((memcmp (&cksum_val, &header_sumval, 2)) == 0) {
    ip_header->ip_sum = cksum_val;
    return 0;
  }
  else {
    printf("checksum failed\n");
    return -1;
  }
}


/*Returns 0 on success and error code on fail*/
int sr_handlearp(struct sr_instance** sr, uint8_t** ethernet_data_addr, struct sr_if* in_f, unsigned int len){
  uint8_t *eth_pkt_buf;
  uint8_t *arp_pkt_buf; /* ARP packet buffer */
  struct sr_if* ret_if; /* return interface */
  printf("sr_handlearp");

  sr_arp_hdr_t* arp_header_buffer = (sr_arp_hdr_t*)*ethernet_data_addr;
  ntoh_arp_hdr(&arp_header_buffer); /* converts header members into host byte order where appropriate */

  /* Recieved ARP request! Reply to request. */
  if(arp_header_buffer->ar_op == arp_op_request) {
    if ((ret_if = sr_get_interface_from_ip(*sr, arp_header_buffer->ar_tip))) { /* Target IP is IP of a Router Interface*/ 
      
      /* Send an ARP reply (uint8_t*) */

      /* Create reply frame */
      eth_pkt_buf = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)); /* Allocate mem for reply packet buffer */
      sr_ethernet_hdr_t *req_reply_eth_header = (sr_ethernet_hdr_t *) eth_pkt_buf;

      /* Build Ethernet Header */
      memcpy(req_reply_eth_header->ether_dhost, arp_header_buffer->ar_sha, ETHER_ADDR_LEN);
      memcpy(req_reply_eth_header->ether_shost, in_f->addr, ETHER_ADDR_LEN);
      req_reply_eth_header->ether_type = ethertype_arp;
      /* Convert to network byte ordering */
      hton_eth_hdr(&req_reply_eth_header);

      /* Get the Arp Buffer and Build the Arp packet*/
      arp_pkt_buf = eth_pkt_buf + sizeof(sr_ethernet_hdr_t);
      sr_create_arp_packet(&arp_pkt_buf, arp_header_buffer, ret_if); /* Create arp packet to be sent as ARP reply, fill arp_pkt_buf with ARP reply header data */
      
      /* Send the ARP reply packet */
      sr_send_packet(*sr, eth_pkt_buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), in_f->name);
      free(eth_pkt_buf);


    } else { /* Target IP is *NOT* IP of a Router Interface */
      /* I'm not sure what to do here yet MAYBE NOTHING?!*/
    }
  }

  else if (arp_header_buffer->ar_op == arp_op_reply) {
    handle_arp_reply(*sr, *ethernet_data_addr, in_f);
  }
  


  return 0;
}

void convert_ip_to_htons(sr_ip_hdr_t** ip_header) {
  (*ip_header)->ip_len = ntohs((*ip_header)->ip_len);
  (*ip_header)->ip_id = ntohs((*ip_header)->ip_id);
  (*ip_header)->ip_off = ntohs((*ip_header)->ip_off);
  /*  (*ip_header)->ip_src = htons((*ip_header)->ip_src);
  (*ip_header)->ip_dst = htons((*ip_header)->ip_dst);*/
}


/* Convert necessary ethernet header members from network byte order to host byte order */
void ntoh_eth_hdr(sr_ethernet_hdr_t** eth_header_buffer) {
  /* uint8_t  ether_dhost[ETHER_ADDR_LEN];*/  /* destination ethernet address */
  /* uint8_t  ether_shost[ETHER_ADDR_LEN];*/  /* source ethernet address */
  /* uint16_t ether_type;*/                   /* packet type ID */

  (*eth_header_buffer)->ether_type = ntohs((*eth_header_buffer)->ether_type); 
}

/* Convert necessary ethernet header members from host byte order to network byte order */
void hton_eth_hdr(sr_ethernet_hdr_t** eth_header_buffer) {
  /* uint8_t  ether_dhost[ETHER_ADDR_LEN];*/  /* destination ethernet address */
  /* uint8_t  ether_shost[ETHER_ADDR_LEN];*/  /* source ethernet address */
  /* uint16_t ether_type;*/                   /* packet type ID */

  (*eth_header_buffer)->ether_type = htons((*eth_header_buffer)->ether_type);
}

/* Convert necessary IP header members from network byte order to host byte order */
void ntoh_ip_hdr(sr_ip_hdr_t** ip_header_buffer) {
  /* unsigned int ip_v:4;*/     /* version x*/
  /* unsigned int ip_hl:4;*/    /* header length in multiples of 4 bytes*/
  /* uint8_t ip_tos;*/          /* type of service */
  /* uint16_t ip_len;*/         /* total length*/
  /* uint16_t ip_id;*/          /* identification */
  /* uint16_t ip_off;*/         /* fragment offset field */
  /* uint8_t ip_ttl;*/          /* time to live */
  /* uint8_t ip_p;*/            /* protocol 1 == ICMP*/
  /* uint16_t ip_sum;*/         /* checksum */
  /* uint32_t ip_src, ip_dst;*/ /* source and dest address */

  (*ip_header_buffer)->ip_len = ntohs((*ip_header_buffer)->ip_len);
  (*ip_header_buffer)->ip_id = ntohs((*ip_header_buffer)->ip_id);


}

/* Convert necessary IP header members from host byte order to network byte order */
void hton_ip_hdr(sr_ip_hdr_t** ip_header_buffer) {
  /* unsigned int ip_v:4;*/     /* version */
  /* unsigned int ip_hl:4;*/    /* header length */
  /* uint8_t ip_tos;*/          /* type of service */
  /* uint16_t ip_len;*/         /* total length */
  /* uint16_t ip_id;*/          /* identification */
  /* uint16_t ip_off;*/         /* fragment offset field */
  /* uint8_t ip_ttl;*/          /* time to live */
  /* uint8_t ip_p;*/            /* protocol */
  /* uint16_t ip_sum;*/         /* checksum */
  /* uint32_t ip_src, ip_dst;*/ /* source and dest address */

  (*ip_header_buffer)->ip_len = htons((*ip_header_buffer)->ip_len);
  (*ip_header_buffer)->ip_id = htons((*ip_header_buffer)->ip_id);


}

/* Convert necessary ARP header members from network byte order to host byte order */
void ntoh_arp_hdr(sr_arp_hdr_t** arp_header_buffer) {
  /* unsigned short  ar_hrd;*/                  /* format of hardware address   */
  /* unsigned short  ar_pro;*/                  /* format of protocol address   */
  /* unsigned char   ar_hln;*/                  /* length of hardware address   */
  /* unsigned char   ar_pln;*/                  /* length of protocol address   */
  /* unsigned short  ar_op;*/                   /* ARP opcode (command)         */
  /* unsigned char   ar_sha[ETHER_ADDR_LEN];*/  /* sender hardware address      */
  /* uint32_t        ar_sip;*/                  /* sender IP address            */
  /* unsigned char   ar_tha[ETHER_ADDR_LEN];*/  /* target hardware address      */
  /* uint32_t        ar_tip;*/                  /* target IP address            */

  (*arp_header_buffer)->ar_hrd = ntohs((*arp_header_buffer)->ar_hrd);
  (*arp_header_buffer)->ar_op = ntohs((*arp_header_buffer)->ar_op);
}

/* Convert necessary ARP header members from host byte order to network byte order */
void hton_arp_hdr(sr_arp_hdr_t** arp_header_buffer) {
  /* unsigned short  ar_hrd;*/                  /* format of hardware address   */
  /* unsigned short  ar_pro;*/                  /* format of protocol address   */
  /* unsigned char   ar_hln;*/                  /* length of hardware address   */
  /* unsigned char   ar_pln;*/                  /* length of protocol address   */
  /* unsigned short  ar_op;*/                   /* ARP opcode (command)         */
  /* unsigned char   ar_sha[ETHER_ADDR_LEN];*/  /* sender hardware address      */
  /* uint32_t        ar_sip;*/                  /* sender IP address            */
  /* unsigned char   ar_tha[ETHER_ADDR_LEN];*/  /* target hardware address      */
  /* uint32_t        ar_tip;*/                  /* target IP address            */

  (*arp_header_buffer)->ar_hrd = htons((*arp_header_buffer)->ar_hrd);
  (*arp_header_buffer)->ar_op = htons((*arp_header_buffer)->ar_op);
  (*arp_header_buffer)->ar_pro = htons((*arp_header_buffer)->ar_pro);
}

/* Given an interface ip return the interface record or 0 if it doesn't
 * exist.*/
struct sr_if* sr_get_interface_from_ip(struct sr_instance* sr, uint32_t ip)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(ip);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
      if(if_walker->ip == ip)
        return if_walker;
      if_walker = if_walker->next;
    }

    return 0;
} /* -- sr_get_interface_from_ip -- */

/* Create ARP packet by filling buffer with ARP header entries. */
int sr_create_arp_packet(uint8_t** buf, sr_arp_hdr_t* req_arp_hdr, struct sr_if* r_if) {
  
  sr_arp_hdr_t reply_arp_hdr; /* ARP reply header*/

  reply_arp_hdr.ar_hrd = arp_hrd_ethernet;                  /* Set Ethernet Hardware Type   */
  reply_arp_hdr.ar_pro = ethertype_ip;                     /* Set same as req ethernet frame   */
  reply_arp_hdr.ar_hln = ETHER_ADDR_LEN;                    /* Set length of hardware address 6 bytes for ethernet addresses   */
  reply_arp_hdr.ar_pln = 0x04;                              /* Set length of protocol address 4 bytes for IP  */
  reply_arp_hdr.ar_op  = arp_op_reply;                      /* Set ARP opcode reply        */
  reply_arp_hdr.ar_sip = req_arp_hdr->ar_tip;               /* Set sender IP address to the requested target IP address */
  reply_arp_hdr.ar_tip = req_arp_hdr->ar_sip;               /* Set target IP address to senders IP address */

  sr_arp_hdr_t *reply_arp_hdr_ptr = &reply_arp_hdr;
  hton_arp_hdr(&reply_arp_hdr_ptr);


  memcpy(&(reply_arp_hdr.ar_sha), &(r_if->addr), ETHER_ADDR_LEN);          /* Set sender hardware address to targeted IP MAC addr */
  memcpy(&(reply_arp_hdr.ar_tha), &(req_arp_hdr->ar_sha), ETHER_ADDR_LEN); /* Set target hardware address to sender hardware address */
  memcpy(*buf, &reply_arp_hdr, sizeof(sr_arp_hdr_t));                 /* Copy reply_arp_hdr into buffer */
  
  return 0;
}

int check_if_for_us(sr_ip_hdr_t* ip_header){
  ;
  return -1;
}

/*Forward an IP Packet (ECHO) that's for us*/
int forward_packet(sr_ip_hdr_t* ip_header){
  return 0;
}

/*Check the routing table and see if the address is in there
* Return the corresponding routing table node if found, NULL if not
*/
struct sr_rt * check_routing_table(struct sr_instance* sr, uint32_t ip_dest) {
  /*uint32_t ip_src, ip_dst*/
  /*ip_leader->ip_dst*/
  struct sr_rt *sr_routing_table = &(*(sr->routing_table));

  /*MergeSort the routing table list*/
  mergesort(&sr_routing_table);

  struct sr_rt *current_route = sr_routing_table;
  /*Loop through all the routes in the routing table, break if we find a match
  to our destination*/   
  for (; current_route!=NULL; current_route=current_route->next) {     

    /*ip destination with the mask equals the routing table entry with the mask*/
    if ((ip_dest & (current_route->mask.s_addr)) == ((current_route->dest.s_addr) & (current_route->mask.s_addr))) {
      printf("FOUND IN ROUTING TABLE\n");
      break;
    }
  }
  
  /*We didn't find the address in the routing table*/
  if(current_route == NULL) {
    printf("Did NOT find address in routing table\n");
  }

  /*If we found the address in the routing table, current_route will be the correct table entry*/
  /*name of interface is current_route->interface
    *index into the interface table to get the MAC address
    *
  */
  /*sr_print_if_list(sr);*/

  return current_route;
}
/*
struct sr_rt
{
    struct in_addr dest;
    struct in_addr gw; #THIS IS A GATEWAY
    struct in_addr mask;
    char   interface[sr_IFACE_NAMELEN];
    struct sr_rt* next;
};*/



/*Broadcasts an arp request because the destination IP isn't in our cache*/
void broadcast_arp_req(struct sr_instance* sr, uint32_t nexthopIP, sr_ethernet_hdr_t* packet_to_forward, unsigned int len, struct sr_rt * routing_node, struct sr_if* nexthopInterface){
  
  /*Insert the request into the arpcache with pre-made sr_arpcache_queuereq: cache pointer is returned*/
  struct sr_arpreq *cache_req_ptr = sr_arpcache_queuereq(&(sr->cache), nexthopIP, (uint8_t*) packet_to_forward, len, routing_node->interface);
  
  handle_arpreq(sr, cache_req_ptr);
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *cache_req_ptr) {

  char *iface_name = cache_req_ptr->packets->iface;
  struct sr_if *interface = sr_get_interface(sr, iface_name);

  /*Only broadcast if this hasn't been sent out before: 
   *Otherwise, our packet has been added to the end of the 
  * request's linkedlist in the cache: do nothing*/
  if (difftime(time(0), cache_req_ptr->sent) > 1.0) {
    if (cache_req_ptr->times_sent >= 5) {
      struct sr_packet *req_pkt_ptr = cache_req_ptr->packets;
      for (; req_pkt_ptr; req_pkt_ptr = req_pkt_ptr->next) {
        send_icmp(sr, req_pkt_ptr->buf, req_pkt_ptr->len, interface, dest_host_unreach_type, dest_host_unreach_code);
      }
      sr_arpreq_destroy(&(sr->cache), cache_req_ptr);
    }
    else {
      /*Create space for the request*/
      uint8_t* eth_pkt_buf = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      uint8_t* arp_pkt_buf;
      /*Pointers to where different header structs start in the packet*/
      sr_ethernet_hdr_t* req_eth_header = (sr_ethernet_hdr_t*) eth_pkt_buf; /* Allocate mem for reply packet buffer */
      
      /* Copy addresses and type into the ethernet header */
      uint8_t broadcast_addr[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

      memcpy(req_eth_header->ether_dhost, broadcast_addr, ETHER_ADDR_LEN);
      memcpy(req_eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
      req_eth_header->ether_type = ethertype_arp;
      
      /* Convert to network byte ordering */
      hton_eth_hdr(&req_eth_header);


      /* Get the Arp Buffer and Build the Arp packet*/
      arp_pkt_buf = eth_pkt_buf + sizeof(sr_ethernet_hdr_t);
      sr_create_arp_req_packet(arp_pkt_buf, cache_req_ptr, interface);

      /* Send the ARP request packet */
      sr_send_packet(sr, eth_pkt_buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
        interface->name);
      cache_req_ptr->sent = time(0);
      cache_req_ptr->times_sent++;

      free(eth_pkt_buf);
    }
  }
}

/*
function handle_arpreq(sr, req):

  get interface name from (*((*cache_req_ptr)->packets))->iface and find ptr to it
  CALL: sr_get_interface(sr, routing_node->interface);

   if difftime(now, req->sent) > 1.0
       if req->times_sent >= 5:
           send icmp host unreachable to source addr of all pkts waiting
             on this request
           arpreq_destroy(req)
       else:
           send arp request
           req->sent = now
           req->times_sent++
*/


/*Create an ARP request packet: similar to the ARP reply packet but using cache_req_ptr for some info instead of an incoming request packet*/
void sr_create_arp_req_packet(uint8_t *arp_pkt_buf, struct sr_arpreq *cache_req_ptr, struct sr_if *nexthopInterface){
  /* ARP Header */
  sr_arp_hdr_t request_arp_hdr;

  request_arp_hdr.ar_hrd = arp_hrd_ethernet;                  /* Set Ethernet Hardware Type   */
  request_arp_hdr.ar_pro = ethertype_ip;                     /* Set same as req ethernet frame   */
  request_arp_hdr.ar_hln = ETHER_ADDR_LEN;                    /* Set length of hardware address 6 bytes for ethernet addresses   */
  request_arp_hdr.ar_pln = 0x04;                              /* Set length of protocol address 4 bytes for IP  */
  request_arp_hdr.ar_op  = arp_op_request;                    /* Set ARP opcode request        */
  request_arp_hdr.ar_sip = nexthopInterface->ip;              /* Set sender IP address to the interface's IP address */
  request_arp_hdr.ar_tip = cache_req_ptr->ip;                 /* Set target IP address to the IP in the cache request*/
  
  sr_arp_hdr_t *request_arp_hdr_ptr = &request_arp_hdr;
  hton_arp_hdr(&request_arp_hdr_ptr);

  memcpy(&(request_arp_hdr.ar_sha), &(nexthopInterface->addr), ETHER_ADDR_LEN);          /* Set sender hardware address to targeted IP MAC addr */
  memset(request_arp_hdr.ar_tha, 0, ETHER_ADDR_LEN);                            /* Set target hardware address to 0 */
  memcpy(arp_pkt_buf, &request_arp_hdr, sizeof(sr_arp_hdr_t));                 /* Copy reply_arp_hdr into buffer */
}



void handle_arp_reply(struct sr_instance *sr, uint8_t* ethernet_data_addr, struct sr_if* in_f){
  printf("in handle arp reply\n");

/*
  The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)
*/

  /*Loop through sr_cache requests and look for an IP match to the ARP header source IP*/

  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) ethernet_data_addr;

  struct sr_arpreq *req_ptr = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);

  /*If the IP in the reply matched something in our request queue*/
  if (req_ptr) {
    struct sr_packet *req_pkts = req_ptr->packets;
    struct sr_packet *req_pkt_ptr = req_pkts;

    for (; req_pkt_ptr; req_pkt_ptr = req_pkt_ptr->next) {

      sr_ethernet_hdr_t *packet_eth_hdr = (sr_ethernet_hdr_t *) req_pkts->buf;
      sr_ip_hdr_t *packet_ip_hdr = (sr_ip_hdr_t *) (req_pkts->buf + sizeof(sr_ethernet_hdr_t));

      /*ret_if will be populated if this was originally an echo request, else 0*/
      struct sr_if* ret_if = sr_get_interface_from_ip(sr, packet_ip_hdr->ip_dst);
      
      if (ret_if) {
        /*Doesn't have a code so just passing 0 as code*/
        send_icmp_echo_reply(sr, (uint8_t *) packet_eth_hdr, req_pkt_ptr->len, in_f, arp_header->ar_sha, echo_reply_type, 0);
      }
      
      else {
        memcpy(packet_eth_hdr->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
        sr_send_packet(sr, (uint8_t *) packet_eth_hdr, req_pkt_ptr->len, in_f->name);
      } 
    }
    sr_arpreq_destroy(&(sr->cache), req_ptr);
  }
  /*Otherwise do nothing, the reply wasn't about anything in our queue*/
}

/*Sorting Algorithm*/

/*Reverse Mergesort the routing table by mask, so that longer masks are at the head of the linkedlist*/
void mergesort(struct sr_rt **routing_table){
  struct sr_rt *head = *routing_table;
  struct sr_rt *firsthalf, *secondhalf;

  /*Base Case, length 0 or 1*/
  if ((head == NULL) || (head->next == NULL)){
    return;
  }

  splitlist(head, &firsthalf, &secondhalf);

  /*Now recursively call on both halves to split down until we get lists of 1 or 0*/
  mergesort(&firsthalf);
  mergesort(&secondhalf);

  /*Finally, sort the 2 halves and merge together*/
  *routing_table = sortandmerge(firsthalf, secondhalf);
}


/*Split the list at head in 2, firstref and secondref point to each list respectively*/
void splitlist(struct sr_rt *head, struct sr_rt **firstref, struct sr_rt **secondref) {

  /*If length <= 1*/
  if ((head == NULL) || (head->next == NULL)) {
    *firstref = head;
    *secondref = NULL;
  }
  else{

    struct sr_rt *slowptr = head;
    struct sr_rt *fastptr = head->next;

    /*Slow goes 1 at a time, fast goes 2 at a time: when fast reaches the end, slow is around the midpoint!*/
    while(fastptr != NULL) {
      fastptr = fastptr->next;
      if (fastptr != NULL) {
        fastptr = fastptr->next;
        slowptr = slowptr->next;
      }
    }

    *firstref = head;
    *secondref = slowptr->next;
    slowptr->next = NULL;
  }
}

struct sr_rt *sortandmerge(struct sr_rt *firsthalf, struct sr_rt *secondhalf) {
  struct sr_rt *result = NULL;

  /*Base cases: return the other list if one is null*/
  if (firsthalf == NULL) {
    return secondhalf;
  }
  else if(secondhalf == NULL) {
    return firsthalf;
  }

  /*Pick either first or second and recurse*/
  if (masklength(firsthalf->mask.s_addr) >= masklength(secondhalf->mask.s_addr)) {
    result = firsthalf;
    result->next = sortandmerge(firsthalf->next, secondhalf);
  }
  else {
    result = secondhalf;
    result->next = sortandmerge(firsthalf, secondhalf->next);
  }

  return result;
}

/*Returns the length of the mask passed in*/
int masklength(uint32_t mask){
  int len = 0;
  uint32_t bits = 0x80000000;

 while ((bits != 0) && ((bits & mask) != 0))
 {
    bits >>= 1;
    len++;
 }
 
 return len;
}
