#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SIZE 65536

void print(struct ethhdr* eth, struct iphdr* ip){
    
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->h_source[0], eth->h_source[1], eth->h_source[2],
    eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    
}

void process_packet(unsigned char* buffer, int size){
    struct ethhdr* eth= (struct ethhdr*)buffer;

    if(ntohs(eth->h_proto) == ETH_P_IP){
        struct iphdr* ip= (struct iphdr*)(buffer+ sizeof(struct ethhdr));
        
        if (ip->protocol==IPPROTO_TCP){
            struct tcphdr* tcp= (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("-----TCP packet-----\n\n");
            print(eth,ip);

        }

        if (ip->protocol==IPPROTO_UDP){
            struct udphdr* udp= (struct udphdr*)(buffer+ sizeof(struct ethhdr)+sizeof(struct iphdr));
            printf("-----UDP packet-----\n\n");
            print(eth,ip);

        }

        if (ip->protocol==IPPROTO_ICMP){
            struct icmphdr* icmp= (struct icmphdr*)(buffer+ sizeof(struct ethhdr)+sizeof(struct iphdr));
            printf("-----ICMP packet-----\n\n");
            print(eth,ip);
        }
    }
}

void protocol_filter(char* protocol,int* used_domain, int* used_protocol){
    
    if(strcmp(protocol,"tcp")==0){
        printf("TCP protocol\n\n");
        *used_domain=AF_PACKET;
        *used_protocol=6;
    }
    
    if(strcmp(protocol,"udp")==0){
        printf("UDP protocol\n\n");
        *used_domain=AF_INET;
        *used_protocol=17;
    }
    
    if(strcmp(protocol,"icmp")==0){
        printf("ICMP protocol\n\n");
        *used_domain=AF_INET;
        *used_protocol=1;
    }
    
    if(strcmp(protocol,"arp")==0){
        printf("ARP protocol\n\n");
        *used_domain=AF_PACKET;
        *used_protocol= htons(ETH_P_ARP);
    }
    
    if(strcmp(protocol,"ip")==0){
        printf("IP protocol\n\n");
        *used_domain=AF_PACKET;
        *used_protocol=htons(ETH_P_IP);
    }
}

int main(int argc, char* argv[]){
    int DOMAIN= AF_PACKET;
    int PROTOCOL= htons(ETH_P_ALL);

    for(int k=0; k<argc; ++k){
        if(strcmp(argv[k],"-p")==0){
            if(k+1<argc){
                protocol_filter(argv[k+1],&DOMAIN,&PROTOCOL);
            }
        }
    }

    int fd= socket(DOMAIN,SOCK_RAW,PROTOCOL);
    if(fd == -1){
        perror("error\n");
    }
    
    int recv_length;
    unsigned char* recv_buffer= (unsigned char*)malloc(SIZE);
    memset(recv_buffer,0,SIZE);

    struct sockaddr saddr;
    int saddr_len=sizeof(saddr);

    while(1){
        recv_length= recvfrom(fd,recv_buffer,SIZE,0,&saddr,(socklen_t*)&saddr_len);
        
        if(recv_length>0){
            process_packet(recv_buffer,recv_length);
        } 
    }
    return 0;
}