#ifndef SENDARP_HEADER_H
#define SENDARP_HEADER_H

#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <vector>
#include <arpa/inet.h>
#include <thread>
#include <unistd.h>

using namespace std;

extern const uint8_t broad_mac_addr[];
extern const uint8_t zero_mac_addr[];
extern const uint8_t ethernet_type_arp[];
extern const uint8_t arp_dummy[];
extern const uint8_t arp_opcode_request[];
extern const uint8_t arp_opcode_reply[];
extern uint8_t packet1[2000];
extern uint8_t packet2[2000];
extern uint8_t my_ip_addr[4];
extern uint8_t my_mac_addr[6];
extern char* interface;

typedef struct{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
}Session;

typedef struct{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint16_t type;
}Ethernet;

typedef struct{
    uint8_t dummy[6];
    uint8_t opcode[2];
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
}ARP;

typedef struct{
    uint8_t IHL;
    uint8_t service;
    uint16_t total_length;
    uint8_t dummy2[5];
    uint8_t protocol;
    uint8_t dummy3[2];
    uint8_t source_address[4];
    uint8_t destination_address[4];
}IP;

typedef struct{
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t dummy[8];
    uint8_t Hlen;
    uint8_t dummy2[7];
}TCP;

void usage();
void get_my_mac_ip();
int send_packet(Session* a, int opcode);
int get_mac(Session* a, int opcode);
[[noreturn]] void arp_poisoning(vector<Session*> Sessions);
void arp_relaying(vector<Session*> Sessions);

#endif // SENDARP_HEADER_H
