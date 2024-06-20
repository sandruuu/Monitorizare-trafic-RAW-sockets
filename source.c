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
#include <linux/icmp.h>
#include <linux/if_arp.h>

#define SIZE 65536

void print_eth(struct ethhdr* eth){
    
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->h_source[0], eth->h_source[1], eth->h_source[2],
    eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

}

void print_ip(struct iphdr* ip){
    
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    
}

void print_arp(struct arphdr* arp, unsigned char* buff){
    unsigned char* sender_mac = buff + sizeof(struct ethhdr) + sizeof(struct arphdr);
        unsigned char* sender_ip = sender_mac + 6;
        unsigned char* target_mac = sender_ip + 4;
        unsigned char* target_ip = target_mac + 6;
        
        printf("Hardware type: %u\n", ntohs(arp->ar_hrd));
        printf("Protocol type: %u\n", ntohs(arp->ar_pro));
        printf("Hardware size: %u\n", arp->ar_hln);
        printf("Protocol size: %u\n", arp->ar_pln);
        printf("Opcode: %u\n", ntohs(arp->ar_op));

        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                sender_mac[0], sender_mac[1], sender_mac[2],
                sender_mac[3], sender_mac[4], sender_mac[5]);
        printf("Sender IP: %u.%u.%u.%u\n",
                sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);

        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                target_mac[0], target_mac[1], target_mac[2],
                target_mac[3], target_mac[4], target_mac[5]);
        printf("Target IP: %u.%u.%u.%u\n",
                target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
}

void print_data(const unsigned char *data, int size){
    printf("Data:\t");
    for (int i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

void process_packet_layer2(unsigned char* buffer, int size){
    struct ethhdr* eth= (struct ethhdr*)buffer;

    if(ntohs(eth->h_proto) == ETH_P_IP){
        struct iphdr* ip= (struct iphdr*)(buffer+ sizeof(struct ethhdr));
        
        if (ip->protocol==IPPROTO_TCP){
            struct tcphdr* tcp= (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("-----TCP packet-----\n\n");
            print_eth(eth);
            print_ip(ip);
            printf("Source Port: %u\n", ntohs(tcp->source));
            printf("Destination Port: %u\n", ntohs(tcp->dest));
            print_data(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr),
             size - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr));
        }

        if (ip->protocol==IPPROTO_UDP){
            struct udphdr* udp= (struct udphdr*)(buffer+ sizeof(struct ethhdr)+sizeof(struct iphdr));
            printf("-----UDP packet-----\n\n");
            print_eth(eth);
            print_ip(ip);
            printf("Source Port: %u\n", ntohs(udp->source));
            printf("Destination Port: %u\n", ntohs(udp->dest));
            print_data(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
             size - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr));
        }

        if (ip->protocol==IPPROTO_ICMP){
            struct icmphdr* icmp = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("-----ICMP packet-----\n\n");
            print_eth(eth);
            print_ip(ip);
            printf("Type: %u\n", (unsigned int)(icmp->type));
            printf("Code: %u\n", (unsigned int)(icmp->code));
            print_data(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr),
             size - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr));
        }
    }

    if(ntohs(eth->h_proto) == ETH_P_ARP){
        struct arphdr* arp = (struct arphdr*)(buffer + sizeof(struct ethhdr));
        printf("-----ARP packet-----\n\n");
        print_arp(arp, buffer);
        print_data(buffer + sizeof(struct ethhdr) + sizeof(struct arphdr) + 20,
             size - sizeof(struct ethhdr) - sizeof(struct arphdr) - 20);
    }
    printf("\n\n");
}

void process_packet_layer3(unsigned char* buffer, int size){
    struct iphdr* ip = (struct iphdr*)buffer;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(buffer + sizeof(struct iphdr));
        printf("-----TCP packet-----\n\n");
        print_ip(ip);
        printf("Source Port: %u\n", ntohs(tcp->source));
        printf("Destination Port: %u\n", ntohs(tcp->dest));
        print_data(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr),
             size - sizeof(struct iphdr) - sizeof(struct tcphdr));
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct iphdr));
        printf("-----UDP packet-----\n\n");
        print_ip(ip);
        printf("Source Port: %u\n", ntohs(udp->source));
        printf("Destination Port: %u\n", ntohs(udp->dest));
        print_data(buffer + sizeof(struct iphdr) + sizeof(struct udphdr),
             size - sizeof(struct iphdr) - sizeof(struct udphdr));
    }

    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr* icmp = (struct icmphdr*)(buffer + sizeof(struct iphdr));
        printf("-----ICMP packet-----\n\n");
        print_ip(ip);
        printf("Type: %u\n", (unsigned int)(icmp->type));
        printf("Code: %u\n", (unsigned int)(icmp->code));
        print_data(buffer + sizeof(struct iphdr) + sizeof(struct icmphdr),
             size - sizeof(struct iphdr) - sizeof(struct icmphdr));
    }

    printf("\n\n");
}

void protocol_filter(char* protocol,int* used_domain, int* used_protocol){
    
    if(strcmp(protocol,"tcp")==0){
        printf("TCP protocol\n\n");
        *used_domain=AF_INET;
        *used_protocol=IPPROTO_TCP;
    }
    
    if(strcmp(protocol,"udp")==0){
        printf("UDP protocol\n\n");
        *used_domain=AF_INET;
        *used_protocol=IPPROTO_UDP;
    }
    
    if(strcmp(protocol,"icmp")==0){
        printf("ICMP protocol\n\n");
        *used_domain=AF_INET;
        *used_protocol=IPPROTO_ICMP;
    }
    
    if(strcmp(protocol,"arp")==0){
        printf("ARP protocol\n\n");
        *used_domain=AF_PACKET;
        *used_protocol= htons(ETH_P_ARP);
    }
    
    if(strcmp(protocol,"ip")==0){
        printf("IP protocol\n\n");
        *used_domain=AF_PACKET;
        *used_protocol= htons(ETH_P_IP);
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
            if(DOMAIN==AF_PACKET){
                process_packet_layer2(recv_buffer,recv_length);
            } else{
                if(DOMAIN==AF_INET){
                    process_packet_layer3(recv_buffer,recv_length);
                }
            }
        } 
    }
    return 0;
}