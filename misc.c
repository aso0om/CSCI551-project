////////////////////////////////////////////////////////////////////////////////////
///////// misc.c has the supporting functions such as tunnel allocation and checksum
///////// calculation.
/////////////////////////////////////////////////////////////////////////////////////
#include <strings.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <netdb.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
// unsigned short in_cksum(unsigned short *addr, int len)  ///// FROM (4)	/////
// {
    // register int sum = 0;
    // u_short answer = 0;
    // register u_short *w = addr;
    // register int nleft = len;
	
    // while (nleft > 1)
    // {
		// sum += *w++;
		// nleft -= 2;
	// }
    // /* mop up an odd byte, if necessary */
    // if (nleft == 1)
    // {
		// *(u_char *) (&answer) = *(u_char *) w;
		// sum += answer;
	// }
    // /* add back carry outs from top 16 bits to low 16 bits */
    // sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    // sum += (sum >> 16);             /* add carry */
    // answer = ~sum;              /* truncate to 16 bits */
    // return (answer);
// }											
/*int icmp_reply(){
	// struct iphdr *ip, *ip_reply;
    // struct icmphdr* icmp;
    // struct sockaddr_in connection;
    // char *dst_addr="127.0.0.1";
    // char *src_addr="127.0.0.1";
    // char *packet, *buffer;
    // int sockfd, optval, addrlen;
	// struct ifreq if_idx, if_mac, if_ip;
	
    // packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
    // ip = (struct iphdr*) packet;
    // icmp = (struct icmphdr*) (packet + sizeof(struct iphdr));
	
    // ip->ihl         = 5;
    // ip->version     = 4;
    // ip->tot_len     = sizeof(struct iphdr) + sizeof(struct icmphdr);
    // ip->protocol    = IPPROTO_ICMP;
    // ip->saddr       = inet_addr(src_addr);
    // ip->daddr       = inet_addr(dst_addr);
    // ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr)); 
	
    // icmp->type      = ICMP_ECHOREPLY;
    // icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));
	///////////////////////
	//////// FROM (3)	/////
	// if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		// perror("socket");
	// }
	// memset(&if_idx, 0, sizeof(struct ifreq));
	// strncpy(if_idx.ifr_name, "lo", IFNAMSIZ-1);
	// if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    // perror("SIOCGIFINDEX");
	// memset(&if_mac, 0, sizeof(struct ifreq));
	// strncpy(if_mac.ifr_name, "lo", IFNAMSIZ-1);
	// if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    // perror("SIOCGIFHWADDR");
	// memset(&if_ip, 0, sizeof(struct ifreq));
	// strncpy(if_ip.ifr_name, "lo", IFNAMSIZ-1);
	// if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
    // perror("SIOCGIFADDR");

	// struct sockaddr_ll socket_address;

	// socket_address.sll_ifindex = if_idx.ifr_ifindex;

	// socket_address.sll_halen = ETH_ALEN;

	// socket_address.sll_addr[0] = 0x00;
	// socket_address.sll_addr[1] = 0x00;
	// socket_address.sll_addr[2] = 0x00;
	// socket_address.sll_addr[3] = 0x00;
	// socket_address.sll_addr[4] = 0x00;
	// socket_address.sll_addr[5] = 0x00;
	//////////////////////////

	// if (sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    // printf("Send failed\n");
    // sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
	// int x = write(fd, packet, ip->tot_len);
	
// } */
int tun_alloc(char *dev, int flags) //// From sample tunnel.c
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = (char*)"/dev/net/tun";
	
    if( (fd = open(clonedev , O_RDWR)) < 0 ) 
    {
		perror("Opening /dev/net/tun");
		return fd;
	}
	
    memset(&ifr, 0, sizeof(ifr));
	
    ifr.ifr_flags = flags;
	
    if (*dev) 
    {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}
	
    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
    {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}
	
    strcpy(dev, ifr.ifr_name);
    return fd;
}

