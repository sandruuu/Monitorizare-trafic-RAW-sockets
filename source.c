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

void print_data(const unsigned char *data, int size){
    printf("Data:\t");
    for (int i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

void print_tcp_info(struct tcphdr* tcp){
    printf("Source Port: %u\n", ntohs(tcp->source));
    printf("Destination Port: %u\n", ntohs(tcp->dest));
}

void print_udp_info(struct udphdr* udp){
    printf("Source Port: %u\n", ntohs(udp->source));
    printf("Destination Port: %u\n", ntohs(udp->dest));
}

void print_icmp_info(struct icmphdr* icmp){
    printf("Type: %u\n", (unsigned int)(icmp->type));
    printf("Code: %u\n", (unsigned int)(icmp->code));
}

void print_arp_info(struct arphdr* arp, unsigned char* buff){
    unsigned char* sender_mac = buff + sizeof(struct ethhdr) + sizeof(struct arphdr);
    unsigned char* sender_ip = sender_mac + 6;
    unsigned char* target_mac = sender_ip + 4;
    unsigned char* target_ip = target_mac + 6;

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

    printf("Hardware type: %u\n", ntohs(arp->ar_hrd));
    printf("Protocol type: %u\n", ntohs(arp->ar_pro));
    printf("Hardware size: %u\n", arp->ar_hln);
    printf("Protocol size: %u\n", arp->ar_pln);
    printf("Opcode: %u\n", ntohs(arp->ar_op));
}

 void print_in_file_tcp_info(struct ethhdr* eth, struct iphdr* ip, struct tcphdr* tcp, FILE* outfile){
    fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",//source mac
    eth->h_source[0], eth->h_source[1], eth->h_source[2],
    eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(outfile,"%s ", inet_ntoa(*(struct in_addr *)&ip->saddr));//source ip
    fprintf(outfile,"%u ", ntohs(tcp->source));//source port

    fprintf(outfile,"> ");

    fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",//dest mac
    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(outfile,"%s ", inet_ntoa(*(struct in_addr *)&ip->daddr));//dest ip
    fprintf(outfile,"%u: ", ntohs(tcp->dest));//dest port

    
    fprintf(outfile, "Seq=%u ", ntohl(tcp->seq)); // seq number
    fprintf(outfile, "Ack=%u ", ntohl(tcp->ack_seq)); // acknowledgment number
    fprintf(outfile, "Flags=[");
    if (tcp->fin)
        fprintf(outfile, "F.");
    if (tcp->syn)
        fprintf(outfile, "S.");
    if (tcp->rst)
        fprintf(outfile, "R.");
    if (tcp->psh)
        fprintf(outfile, "P.");
    if (tcp->ack)
        fprintf(outfile, "A.");
    if (tcp->urg)
        fprintf(outfile, "U.");
    if(!tcp->fin && !tcp->syn && !tcp->rst && !tcp->psh && !tcp->ack && !tcp->urg)
        fprintf(outfile,".");
    fprintf(outfile, "] ");
    fprintf(outfile, "Win=%u ", ntohs(tcp->window)); // window size
    fprintf(outfile, "Length=%u\n", ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4));
 }
 void print_in_file_udp_info(struct ethhdr* eth, struct iphdr* ip, struct udphdr* udp, FILE* outfile){
    fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",//source mac
    eth->h_source[0], eth->h_source[1], eth->h_source[2],
    eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(outfile,"%s ", inet_ntoa(*(struct in_addr *)&ip->saddr));//source ip
    fprintf(outfile,"%u ", ntohs(udp->source));//source port

    fprintf(outfile,"> ");

    fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",//dest mac
    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(outfile,"%s ", inet_ntoa(*(struct in_addr *)&ip->daddr));//dest ip
    fprintf(outfile,"%u: ", ntohs(udp->dest));//dest port

    fprintf(outfile, "Checksum=%04x ", ntohs(udp->check));
    fprintf(outfile, "Length=%u\n", ntohs(udp->len));
 }
 void print_in_file_icmp_info(struct ethhdr* eth, struct iphdr* ip, struct icmphdr* icmp, FILE* outfile){
    fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",//source mac
    eth->h_source[0], eth->h_source[1], eth->h_source[2],
    eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(outfile,"%s ", inet_ntoa(*(struct in_addr *)&ip->saddr));//source ip

    fprintf(outfile,"> ");

    fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",//dest mac
    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(outfile,"%s ", inet_ntoa(*(struct in_addr *)&ip->daddr));//dest ip

    fprintf(outfile, "Type=%u ", icmp->type); //type
    fprintf(outfile, "Code=%u\n", icmp->code);//code

 }
void print_in_file_arp_info(struct ethhdr* eth, struct arphdr* arp, unsigned char* buff,FILE* outfile){
    unsigned char* sender_mac = buff + sizeof(struct ethhdr) + sizeof(struct arphdr);
        unsigned char* sender_ip = sender_mac + 6;
        unsigned char* target_mac = sender_ip + 4;
        unsigned char* target_ip = target_mac + 6;

        fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",
                sender_mac[0], sender_mac[1], sender_mac[2],
                sender_mac[3], sender_mac[4], sender_mac[5]);//source mac
        fprintf(outfile,"%u.%u.%u.%u ",
                sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);//source ip

        fprintf(outfile,"> ");

        fprintf(outfile,"%02x:%02x:%02x:%02x:%02x:%02x ",
                target_mac[0], target_mac[1], target_mac[2],
                target_mac[3], target_mac[4], target_mac[5]);//dest mac 
        fprintf(outfile,"%u.%u.%u.%u:",
                target_ip[0], target_ip[1], target_ip[2], target_ip[3]);//dest ip
        fprintf(outfile,"%u ", ntohs(arp->ar_op));//opcode
        fprintf(outfile,"%u ", ntohs(arp->ar_hrd));//hardware type
        fprintf(outfile,"%u ", ntohs(arp->ar_pro));//protocol type
        fprintf(outfile,"\n");
 }

void process_transport_layer(struct ethhdr* eth, struct iphdr* ip,unsigned char* buffer,int size, FILE* outfile){
    int headers_size=0;
    if (ip->protocol==IPPROTO_TCP){
        struct tcphdr* tcp= NULL;
        printf("-----TCP packet-----\n\n");
        if(eth!=NULL){
            tcp= (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            headers_size+=sizeof(struct ethhdr);
            print_eth(eth);
            fprintf(outfile,"TCP ");
            print_in_file_tcp_info(eth,ip,tcp,outfile);
        } else{
            tcp= (struct tcphdr*)(buffer+ sizeof(struct iphdr));
        }
        headers_size+=sizeof(struct iphdr)+sizeof(struct tcphdr);
        print_ip(ip);
        print_tcp_info(tcp);
        print_data(buffer+headers_size,size-headers_size);
    }

    if (ip->protocol==IPPROTO_UDP){
        struct udphdr* udp=NULL;
        printf("-----UDP packet-----\n\n");
        if(eth!=NULL){
            udp=(struct udphdr*)(buffer+ sizeof(struct ethhdr)+sizeof(struct iphdr));
            print_eth(eth);
            fprintf(outfile,"UDP ");
            print_in_file_udp_info(eth,ip,udp,outfile);
        } else{
            udp=(struct udphdr*)(buffer+ sizeof(struct iphdr));
        }
        headers_size+=sizeof(struct iphdr)+sizeof(struct udphdr);
        print_ip(ip);
        print_udp_info(udp);
        print_data(buffer+headers_size,size-headers_size);
    }

    if (ip->protocol==IPPROTO_ICMP){
        struct icmphdr* icmp = NULL;
        printf("-----ICMP packet-----\n\n");
        if(eth!=NULL){
            icmp=(struct icmphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            headers_size+=sizeof(struct ethhdr);
            print_eth(eth);
            fprintf(outfile,"ICMP ");
            print_in_file_icmp_info(eth,ip,icmp,outfile);
        } else{
            icmp=(struct icmphdr*)(buffer+sizeof(struct iphdr));
        }
        headers_size+=sizeof(struct iphdr)+sizeof(struct icmphdr);
        print_ip(ip);
        print_icmp_info(icmp);
        print_data(buffer+headers_size,size-headers_size);
    }
}

void process_packet(int domain, unsigned char* buffer, int size, FILE* outfile){
    
    if(domain==AF_PACKET){
        struct ethhdr* eth= (struct ethhdr*)buffer;
        
        if(ntohs(eth->h_proto) == ETH_P_IP){
            struct iphdr* ip= (struct iphdr*)(buffer+ sizeof(struct ethhdr));
            
            process_transport_layer(eth,ip,buffer,size,outfile);
        }
        if(ntohs(eth->h_proto) == ETH_P_ARP){
            struct arphdr* arp = (struct arphdr*)(buffer + sizeof(struct ethhdr));
            printf("-----ARP packet-----\n\n");
            print_arp_info(arp, buffer);
            fprintf(outfile,"ARP ");
            print_in_file_arp_info(eth,arp,buffer,outfile);
        }
    }
    if(domain==AF_INET){
        struct iphdr* ip= (struct iphdr*)buffer;
        process_transport_layer(NULL,ip,buffer,size,outfile);
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
        perror("socket error\n");
    }
    
    FILE* file=fopen("out.txt","w");
    if (file == NULL) {
        perror("file error\n");
        return -1;
    }

    int recv_length;
    unsigned char* recv_buffer= (unsigned char*)malloc(SIZE);
    memset(recv_buffer,0,SIZE);

    struct sockaddr saddr;
    int saddr_len=sizeof(saddr);

    while(1){
        recv_length= recvfrom(fd,recv_buffer,SIZE,0,&saddr,(socklen_t*)&saddr_len);
        
        if(recv_length>0){
            time_t rawtime;
            struct tm * timeinfo;
            time ( &rawtime );
            timeinfo = localtime ( &rawtime );
            char time_string[9];
            strftime(time_string, sizeof(time_string), "%H:%M:%S", timeinfo);
	        if(DOMAIN==AF_PACKET)
                fprintf(file,"%s ",time_string);
            printf("%s",asctime(timeinfo));
            process_packet(DOMAIN,recv_buffer,recv_length,file);
        }
    } 
    free(recv_buffer);
    fclose(file);
    return 0;
}