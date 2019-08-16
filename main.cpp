#include "sendarp_header.h"

using namespace std;

uint8_t broad_mac_addr[] = "\xff\xff\xff\xff\xff\xff";
uint8_t zero_mac_addr[] = "\x00\x00\x00\x00\x00\x00";
uint8_t arp_dummy[] = "\x00\x01\x08\x00\x06\x04";
uint8_t arp_opcode_request[] = "\x00\x01";
uint8_t arp_opcode_reply[] = "\x00\x02";
uint8_t packet1[2000];
uint8_t packet2[2000];
uint8_t my_ip_addr[4];
uint8_t my_mac_addr[6];
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
    get_my_mac_ip();

    /* get sender_mac, target_mac for each sessions */
    for(auto a : Sessions){
        get_mac(a, 1);
        get_mac(a, 2);
    }

    std::thread thread1(&arp_poisoning, Sessions);
    std::thread thread2(&arp_relaying, Sessions);

    thread1.join();
    thread2.join();
}


