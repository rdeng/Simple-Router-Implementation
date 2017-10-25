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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

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
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  uint16_t packet_type = ethertype(packet);
  struct sr_if* inter = sr_get_interface(sr, interface);
  switch(packet_type)
  {
    case ethertype_arp:
      fprintf(stderr, "arp packet\n");
      handle_arp_packet(sr, packet, len, inter);
      break;
    case ethertype_ip:
      fprintf(stderr, "ip packet\n");
      handle_ip_packet(sr, packet, len, inter);
      break;
    default:
      fprintf(stderr, "neither arp nor ip packet\n");
      return;
  }

}/* end sr_ForwardPacket */

void handle_arp_packet(struct sr_instance* sr, uint8_t* packet,
                       unsigned int len, struct sr_if* interface)
{
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  if(len < (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t)))
  {
    fprintf(stderr, "packet length check fail");
    return;
  }

  uint16_t arp_type = ntohs(arp_hdr->ar_op);
  switch(arp_type)
  {
    case arp_op_request:
      fprintf(stderr, "arp request\n");
      handle_request(sr, packet, interface);
      break;
    case arp_op_reply:
      fprintf(stderr, "arp reply\n");
      handle_reply(sr, packet, interface);
      break;
    default:
      fprintf(stderr, "neither a request nor a reply");
      return;
  }
}

void handle_request(struct sr_instance* sr, uint8_t* packet, struct sr_if* interface)
{
  uint8_t* new_packet = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
  
  sr_ethernet_hdr_t* new_ethernet_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_arp_hdr_t* new_arp_hdr = (sr_arp_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
  
  sr_ethernet_hdr_t* old_ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t* old_arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  memcpy(new_ethernet_hdr->ether_dhost, old_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
  new_ethernet_hdr->ether_type = old_ethernet_hdr->ether_type;
  
  new_arp_hdr->ar_hrd = old_arp_hdr->ar_hrd;
  new_arp_hdr->ar_pro = old_arp_hdr->ar_pro;
  new_arp_hdr->ar_hln = old_arp_hdr->ar_hln;
  new_arp_hdr->ar_pln = old_arp_hdr->ar_pln;
  new_arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(new_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
  new_arp_hdr->ar_sip = interface->ip;
  memcpy(new_arp_hdr->ar_tha, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  new_arp_hdr->ar_tip = old_arp_hdr->ar_sip;

  /*fprintf(stderr, "old arp header in request:\n");
  print_hdr_arp(old_arp_hdr);
  fprintf(stderr, "new arp header in request:\n");
  print_hdr_arp(new_arp_hdr);*/

  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  sr_send_packet(sr, new_packet, len, interface->name);
}

void handle_reply(struct sr_instance* sr, uint8_t* packet, struct sr_if* interface)
{
  sr_ethernet_hdr_t* old_ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t* old_arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if(old_arp_hdr->ar_tip != interface->ip)
  {
    fprintf(stderr, "ARP not for me");
    return;
  }

  struct sr_arpreq* request = sr_arpcache_insert(&sr->cache, old_arp_hdr->ar_sha,
                                                 old_arp_hdr->ar_sip);

  if(request)
  {
    struct sr_packet* packet_walker = request->packets;
    while(packet_walker)
    {
      uint8_t* buffer_packet = packet_walker->buf;
      sr_ethernet_hdr_t* buffer_ethernet_hdr = (sr_ethernet_hdr_t*)buffer_packet;
      sr_ip_hdr_t* buffer_ip_hdr = (sr_ip_hdr_t*)(buffer_packet+sizeof(sr_ethernet_hdr_t));
      memcpy(buffer_ethernet_hdr->ether_dhost, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(buffer_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
      buffer_ip_hdr->ip_sum = 0;
      buffer_ip_hdr->ip_sum = cksum(buffer_ip_hdr, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, buffer_packet, packet_walker->len, interface->name);
      packet_walker = packet_walker->next;
    }
    sr_arpreq_destroy(&sr->cache, request);
  }
}

void handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
                      unsigned int len, struct sr_if* interface)
{
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  /*print_hdr_ip(ip_hdr);*/
  if(len < (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)))
  {
    fprintf(stderr, "packet length check fail");
    return;
  }

  uint16_t temp_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != temp_sum) 
  {
    ip_hdr->ip_sum = temp_sum;
    fprintf(stderr, "ip check sum fail\n");
    return;
  }
  ip_hdr->ip_sum = temp_sum;

  struct sr_if* interface_walker = sr->if_list;
  while(interface_walker)
  {
    /* ip packet for me */
    if(interface_walker->ip == ip_hdr->ip_dst)
    {
      fprintf(stderr, "ip packet for me\n");
      uint8_t ip_protocol = ip_hdr->ip_p;
      if(ip_protocol == ip_protocol_icmp)
      {
        fprintf(stderr, "icmp packet\n");
        sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(packet + 
                                   sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* icmp packet */
        if(icmp_hdr->icmp_type == 0x08)
        {
          fprintf(stderr, "icmp packet\n");
          send_echo(sr, packet, len, interface_walker);
        }
      }
      /* TCP/UDP packet, ICMP port unreachable, type 3, code 3 */
      else
      {
        fprintf(stderr, "TCP/UDP packet\n");
        handle_icmp_unreach(sr, packet, 0x03, 0x03, interface_walker);
      } 
      return;
    }
    interface_walker = interface_walker->next;
  }
  
  /* not for me */
  fprintf(stderr, "ip packet not for me\n");

  /* time exceed */
  ip_hdr->ip_ttl--;
  if(ip_hdr->ip_ttl == 0)
  {
    fprintf(stderr, "ip packet time exceed\n");
    handle_icmp_unreach(sr, packet, 0x0b, 0x00, interface);
    return;
  }  

  /* not for me, ip forwarding */
  fprintf(stderr, "ip forwarding, ip packet not for me\n");
  ip_forwarding(sr, packet, len, interface);
}

void send_echo(struct sr_instance* sr, uint8_t* packet,
                      unsigned int len, struct sr_if* interface)
{
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(packet + 
                                   sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if* selected_interface;
  struct sr_rt* table_walker = sr->routing_table;
  while(table_walker)
  {
    uint32_t match_check = table_walker->mask.s_addr & ip_hdr->ip_src;
    if(match_check == table_walker->dest.s_addr)
      selected_interface = sr_get_interface(sr, table_walker->interface);
    table_walker = table_walker->next;
  }

  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, selected_interface->addr, ETHER_ADDR_LEN);
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = interface->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  icmp_hdr->icmp_type = 0x00;
  icmp_hdr->icmp_code = 0x00;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(len)-
			     sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
  fprintf(stderr, "icmp packet header:\n");
  print_hdr_icmp(icmp_hdr);

  sr_send_packet(sr, packet, len, selected_interface->name);
}

void ip_forwarding(struct sr_instance* sr, uint8_t* packet, 
                   unsigned int len, struct sr_if* interface)
{
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  int match = 0;
  struct sr_if* selected_interface;
  struct sr_rt* table_walker = sr->routing_table;

  /* check routing table, perform LPM */
  while(table_walker)
  {
    uint32_t match_check = table_walker->mask.s_addr & ip_hdr->ip_dst;
    if(match_check == table_walker->dest.s_addr)
    {
      selected_interface = sr_get_interface(sr, table_walker->interface);
      match = 1;
    }
    table_walker = table_walker->next;
  }

  /* not match, ICMP net unreachable */
  if(match == 0)
  {
    fprintf(stderr, "not match, ICMP net unreachable\n");
    handle_icmp_unreach(sr, packet, 0x03, 0x00, interface);
  }
  /* match */
  else
  {
    fprintf(stderr, "match, check ARP cache\n");

    /* check ARP cache */
    struct sr_arpentry* hit_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

    /* hit, send frame to next hope */
    if(hit_entry != NULL)
    {
      fprintf(stderr, "hit, send frame to next hope\n");
      memcpy(ethernet_hdr->ether_dhost, hit_entry->mac, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_shost, selected_interface->addr, ETHER_ADDR_LEN);
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, packet, len, selected_interface->name);
      free(hit_entry);
    }
    /* miss, send ARP request */
    else
    {
      fprintf(stderr, "miss, send ARP request\n");
      struct sr_arpreq* request = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst,
                                           packet, len, selected_interface->name);
      handle_arpreq(sr, request);
    }
  }
}

void handle_icmp_unreach(struct sr_instance* sr, uint8_t* packet, 
                         uint8_t icmp_type, uint8_t icmp_code,
                         struct sr_if* interface)
{
  uint8_t* new_packet = malloc(sizeof(sr_icmp_t11_hdr_t) + 
                          sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ethernet_hdr_t* new_ethernet_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* new_icmp_hdr = (sr_icmp_t11_hdr_t*)(new_packet + 
				    sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ethernet_hdr_t* old_ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* old_ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if* selected_interface;
  struct sr_rt* table_walker = sr->routing_table;
  while(table_walker)
  {
    uint32_t match_check = table_walker->mask.s_addr & old_ip_hdr->ip_src;
    if(match_check == table_walker->dest.s_addr)
      selected_interface = sr_get_interface(sr, table_walker->interface);
    table_walker = table_walker->next;
  }
      
  memcpy(new_ethernet_hdr->ether_dhost, old_ethernet_hdr->ether_shost,ETHER_ADDR_LEN);
  memcpy(new_ethernet_hdr->ether_shost, selected_interface->addr, ETHER_ADDR_LEN);
  new_ethernet_hdr->ether_type = old_ethernet_hdr->ether_type;

  new_ip_hdr->ip_hl = old_ip_hdr->ip_hl;
  new_ip_hdr->ip_v = old_ip_hdr->ip_v;
  new_ip_hdr->ip_tos = old_ip_hdr->ip_tos;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t));
  new_ip_hdr->ip_id = old_ip_hdr->ip_id;
  new_ip_hdr->ip_off = old_ip_hdr->ip_off;
  new_ip_hdr->ip_ttl = INIT_TTL;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = interface->ip;
  new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  new_icmp_hdr->icmp_type = icmp_type;
  new_icmp_hdr->icmp_code = icmp_code;
  memcpy(new_icmp_hdr->data, old_ip_hdr, ICMP_DATA_SIZE-8);
  memcpy(new_icmp_hdr->data+20, packet + sizeof(sr_ethernet_hdr_t) + 
         sizeof(sr_ip_hdr_t), 8);
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

  fprintf(stderr, "unreach icmp header:\n");
  print_hdr_icmp(new_icmp_hdr);
  unsigned int icmp_pac_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) +
               	              sizeof(sr_icmp_t11_hdr_t);
  sr_send_packet(sr, new_packet, icmp_pac_len, selected_interface->name);

}
