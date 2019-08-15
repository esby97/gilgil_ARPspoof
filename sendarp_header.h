#ifndef SENDARP_HEADER_H
#define SENDARP_HEADER_H

#include <stdint.h>
#include <sys/types.h>
#include <string.h>

typedef struct{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
}Session;

typedef struct{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint8_t type[2];
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


#endif // SENDARP_HEADER_H
