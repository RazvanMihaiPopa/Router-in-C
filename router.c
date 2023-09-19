#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

/* Routing table */
struct route_table_entry *route_table;
int route_table_len;

/* Mac table */
struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *candidate = NULL;
	for (int i = 0; i < route_table_len; i++) {
		if (route_table[i].prefix == (ip_dest & route_table[i].mask)) {
			if (candidate == NULL || (ntohl(route_table[i].mask) > ntohl(candidate->mask))) {
				candidate = &route_table[i];
			}
		}
	}
	return candidate;
}

struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

void send_icmp(char *buf, size_t len, int interface, uint8_t type) {
	// create new packet to send
	char packet[MAX_PACKET_LEN];

	// get eth and icmp headers of the original packet
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct icmphdr *old_icmp = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	// create new eth header
	struct ether_header *new_eth = malloc(sizeof(struct ether_header));
	memcpy(new_eth->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	memcpy(new_eth->ether_shost, eth_hdr->ether_dhost, 6 * sizeof(uint8_t));
	new_eth->ether_type = htons(0x0800);

	// copy the new eth header to the new packet
	memcpy(packet, new_eth, sizeof(struct ether_header));

	// create new ip header
	struct iphdr *new_ip = malloc(sizeof(struct iphdr));
	new_ip->tos = 0;
	new_ip->frag_off = 0;
	new_ip->version = 4;
	new_ip->ihl = 5;
	new_ip->id = 1;
	new_ip->daddr = ip_hdr->saddr;
	new_ip->saddr = ip_hdr->daddr;
	new_ip->ttl = 64;
	new_ip->protocol = 1;
	new_ip->check = 0;
	new_ip->check = htons(checksum((uint16_t *)new_ip, sizeof(struct iphdr)));
	new_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	// copy the new ip header to the new packet
	memcpy(packet + sizeof(struct ether_header), new_ip, sizeof(struct iphdr));

	// create new icmp header with given type
	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	if (type == 0) {
		icmp_hdr->un.echo.id = old_icmp->un.echo.id;
		icmp_hdr->un.echo.sequence = old_icmp->un.echo.sequence;
	}
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// copy the new icmp header to the packet and the dropped IPV4 header and the first 64 bits of the  original payload
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), buf + sizeof(struct ether_header), sizeof(struct iphdr) + 8);

	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(route_table == NULL, "memory");

	arp_table = malloc(sizeof(struct arp_entry) * 100000);
	DIE(arp_table == NULL, "memory");

	route_table_len = read_rtable(argv[1], route_table);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;
		uint8_t mac[6];

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// get the headers of the packet
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
		
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// verify if the packet is IPv4
	    if (ntohs(eth_hdr->ether_type) == 0x0800) {
			// verify if the router is the destination
			get_interface_mac(interface, mac);
			for (int i = 0; i < 6; i++) {
				if (eth_hdr->ether_dhost[i] != mac[i]) {
					continue;
				}
			}

			// // if the packet is ICMP, check if it is an echo request
			if(ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if (icmp_hdr->type == 8) {
					// send ICMP message with type "Echo reply"
					send_icmp(buf, len, interface, 0);
				}
				continue;
			}
			
			// verify checksum
			if ((ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) != 0) {
				continue;
			}

			// verify TTL
			if (ip_hdr->ttl <= 1) {
				// send ICMP message with type "Time exceeded"
				send_icmp(buf, len, interface, 11);
				continue;
			}
			ip_hdr->ttl--;
			
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				// send ICMP message with type "Destination unreachable"
				send_icmp(buf, len, interface, 3);
				continue;
			}

			// update checksum
			ip_hdr->check = 0;
			ip_hdr->check = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// destination address is the mac address of the next hop
			struct arp_entry *arp_entry = get_arp_entry(best_route->next_hop);
			if (arp_entry == NULL) {
				continue;
			}
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6 * sizeof(uint8_t));
			// source address is the mac address of the interface
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			send_to_link(best_route->interface, buf, len);
	   }
	}
	
}

