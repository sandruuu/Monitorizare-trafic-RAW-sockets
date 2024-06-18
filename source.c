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

void process_packet(unsigned char* buffer, int size){
    struct ethhdr* eth= (struct ethhdr*)buffer;

    if(ntohs(eth->h_proto) == ETH_P_IP){
        struct iphdr* ip= (struct iphdr*)(buffer+ sizeof(struct ethhdr));
        
        if (ip->protocol==IPPROTO_TCP){
            struct tcphdr* tcp= (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("-----TCP packet-----\n\n");
        }

        if (ip->protocol==IPPROTO_UDP){
            struct udphdr* udp= (struct udphdr*)(buffer+ sizeof(struct ethhdr)+sizeof(struct iphdr));
            printf("-----UDP packet-----\n\n");
        }

        if (ip->protocol==IPPROTO_ICMP){
            struct icmphdr* icmp= (struct icmphdr*)(buffer+ sizeof(struct ethhdr)+sizeof(struct iphdr));
            printf("-----ICMP packet-----\n\n");
        }
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    }
}

int main(int argc, char* argv[]){

    int protocol= htons(ETH_P_ALL);

    int fd= socket(AF_PACKET,SOCK_RAW,protocol);
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