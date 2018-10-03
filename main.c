////////////////////////////////////////////////////////////////////////////////////
///////// main.c is the main code of this project it handels all the communication
///////// between the OP and the ORs as well as processing the data.
/////////////////////////////////////////////////////////////////////////////////////
#include "main.h"
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
#include <time.h>
#include <signal.h>




int port=0;
struct sockaddr_in proxy_addr;
// char* stageNo, routerNo;
int stageNo, routerNo, hopsNo=0, dieAfter=0;
char *hops_list;
char removed_list[40];
int removed_ctr = 0;
typedef unsigned short u16;
typedef unsigned long u32;
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
int crashed = 0;
void crashTimer(int sig) {
    crashed = 1;
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
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

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;
	
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
	}
	
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
	}
	
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
	
    return (answer);
}
int init_soc(char *argv[]){     ////// from (1)
	int fd;	/* our socket */
	unsigned int alen;	/* length of address (for getsockname) */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket");
		return 0;
	}
	memset((void *)&proxy_addr, 0, sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	proxy_addr.sin_port = htons(0);
	
	if (bind(fd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
		perror("bind failed");
		return 0;
	}
	
	alen = sizeof(proxy_addr);
	if (getsockname(fd, (struct sockaddr *)&proxy_addr, &alen) < 0) {
		perror("getsockname failed");
		return 0;
	}
	port = ntohs(proxy_addr.sin_port);
	return fd;
} ////////////////////////

int init_circuit(int srv_fd, FILE *fp, unsigned int *rport, unsigned char *key, int circuitNo){
	//////////////////////////////////////////////////////////////////////// just for stage 8
	int fd;	/* our socket */
	unsigned int alen;	/* length of address (for getsockname) */
	struct sockaddr_in proxy_addr_setup;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket");
		return 0;
	}
	memset((void *)&proxy_addr_setup, 0, sizeof(proxy_addr_setup));
	proxy_addr_setup.sin_family = AF_INET;
	proxy_addr_setup.sin_addr.s_addr = htonl(INADDR_ANY);
	proxy_addr_setup.sin_port = htons(0);
	
	if (bind(fd, (struct sockaddr *)&proxy_addr_setup, sizeof(proxy_addr_setup)) < 0) {
		perror("bind failed");
		return 0;
	}
	
	alen = sizeof(proxy_addr_setup);
	if (getsockname(fd, (struct sockaddr *)&proxy_addr_setup, &alen) < 0) {
		perror("getsockname failed");
		return 0;
	}
	///////////////////////////////////////////////////////////////////////////
	struct sockaddr_in remaddr;
	socklen_t addrlen = sizeof(remaddr);
	char buffer[100];
	memset((char *) &remaddr, 0, sizeof(remaddr));
	memset((char *) &buffer, 0, sizeof(buffer));
	struct iphdr *iph = (struct iphdr*)buffer;
	unsigned short iphdrlen = 20;
	remaddr.sin_family = AF_INET;
	remaddr.sin_port = htons(rport[(int)hops_list[0]]);
	char *server = "127.0.0.1";
	iph->saddr = inet_addr(server);
	iph->daddr = inet_addr(server);
	iph->protocol = 253;
	if (stageNo == 5){
		buffer[iphdrlen] = 0x52;
		buffer[iphdrlen+1] = 0x00;
		buffer[iphdrlen+2] = 0x01;
		char res[2]; /* two bytes of hex = 4 characters, plus NULL terminator */
		if (inet_aton(server, &remaddr.sin_addr)==0) {
			fprintf(stderr, "inet_aton() failed\n");
			exit(1);
		}
		for(int i =0; i<hopsNo;i++){
			memset((char *) &buffer, 0, sizeof(buffer));
			iph->saddr = inet_addr(server);
			iph->daddr = inet_addr(server);
			iph->protocol = 253;
			buffer[iphdrlen] = 0x52;
			buffer[iphdrlen+1] = 0x00;
			buffer[iphdrlen+2] = 0x01;
			if(i<hopsNo-1){
				printf("I should add %d whic has hex %02x \n", rport[(int)hops_list[(i+1)]], rport[(int)hops_list[(i+1)]]);
				memcpy(res, &rport[(int)hops_list[i+1]], 2);
				buffer[iphdrlen+3] = res[1];
				buffer[iphdrlen+4] = res[0];
			}
			else{
				buffer[iphdrlen+3] = 0xff;
				buffer[iphdrlen+4] = 0xff;
			}
			
			sendto(srv_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
			memset((char *) &buffer, 0, sizeof(buffer));
			recvfrom(srv_fd, buffer, 2048, 0, (struct sockaddr *)&remaddr, &addrlen);
			printf("parent recived\n");
			printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
			for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buffer[20+i]);} printf("\n"); 
			fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
			for(int i = 0; i<3;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n");
			fprintf(fp,"incoming extend-done circuit, incoming: 0x%d from port: %d\n",1,ntohs(remaddr.sin_port));
			fflush(fp);
			// for(int i =0;i<50;i++){printf("%02x ", buffer[i]);}
		}
	}
	else if (stageNo == 6 || stageNo == 7 || stageNo == 8 || stageNo == 9){
		unsigned char newkey[16],newkey_temp[16], tempkey[16];
		AES_KEY enc_key;
		unsigned char *crypt_key,*crypt_text;
		int crypt_text_len, crypt_key_len;
		buffer[iphdrlen] = 0x65;
		buffer[iphdrlen+1] = 0x00;
		buffer[iphdrlen+2] = (char)circuitNo;
		unsigned char res[6]; /* two bytes of hex = 4 characters, plus NULL terminator */
		if (inet_aton(server, &remaddr.sin_addr)==0) {
			fprintf(stderr, "inet_aton() failed\n");
			exit(1);
		}
		for(int i =0; i<hopsNo;i++){
			char router_indx_temp1 = (1+hops_list[i]);
			for (int j =0; j<16; j++){newkey_temp[j] = key[j] ^ router_indx_temp1;}
			fprintf(fp,"new-fake-diffe-hellman, router index: %d, circuit outgoing: 0x00%02x, key: 0x",router_indx_temp1, buffer[iphdrlen+2] );
			for (int j =0; j<16; j++){fprintf(fp,"%02x",newkey_temp[j]);} fprintf(fp,"\n"); fflush(fp);
			
		}
		for(int i =0; i<hopsNo;i++){
			char router_indx_temp = (1+hops_list[i]);
			fprintf(fp,"hop: %d, router: %d\n",(i+1),router_indx_temp);
			fflush(fp);
		}
		
		for(int i =0; i<hopsNo;i++){
			memset((char *) &buffer, 0, sizeof(buffer));
			iph->saddr = inet_addr(server);
			iph->daddr = inet_addr(server);
			iph->protocol = 253;
			buffer[iphdrlen] = 0x65;
			buffer[iphdrlen+1] = 0x00;
			buffer[iphdrlen+2] = (char)circuitNo;
			char router_indx = (1+hops_list[i]);
			// for (int j =0; j<16; j++){printf("%02x",router_indx);} printf("\n");
			for (int j =0; j<16; j++){newkey[j] = key[j] ^ router_indx; buffer[iphdrlen+3+j] = newkey[j];}
			for (int j =i; j>0; j--){
				for (int k =0; k<16; k++){
					tempkey[k]=(1+hops_list[j-1]) ^ key[k];
				}
				class_AES_set_encrypt_key(tempkey, &enc_key);
				if (j == i){
					class_AES_encrypt_with_padding(newkey, 16, &crypt_key, &crypt_key_len, &enc_key);
					// printf("here\n");
				}
				else{
					class_AES_encrypt_with_padding(crypt_key, crypt_key_len, &crypt_key, &crypt_key_len, &enc_key);
					// printf("there\n");
				}
				//printf("newkey: ");
				for (int k =0; k<crypt_key_len; k++){//printf("%02x",crypt_key[k]);
				buffer[iphdrlen+3+k] = crypt_key[k];} 
				//printf("\n");
			} 
			
			// fprintf(fp,"new-fake-diffe-hellman, router index: %d, circuit outgoing: 0x01, key: 0x",router_indx );
			// for (int j =0; j<16; j++){fprintf(fp,"%02x",newkey[j]);} fprintf(fp,"\n"); fflush(fp);
			
			if (stageNo == 6 || stageNo == 7) sendto(srv_fd, buffer, 23+(16*(i+1)), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
			else sendto(fd, buffer, 23+(16*(i+1)), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
			class_AES_set_encrypt_key(newkey, &enc_key);
			if(i<hopsNo-1){
				sprintf((char*)res, "%d", rport[(int)hops_list[i+1]]);
			}
			else{
				sprintf((char*)res, "%d", 65535);
			}
			// printf("port : %s \n", res);
			// for (int j=0; j<5; j++){printf("%02x", res[j]);} printf("\n");
			class_AES_encrypt_with_padding(res, 5, &crypt_text, &crypt_text_len, &enc_key);
			for (int j =i; j>0; j--){
				for (int k =0; k<16; k++){
					tempkey[k]=(1+hops_list[j-1]) ^ key[k];
				}
				class_AES_set_encrypt_key(tempkey, &enc_key);
				class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
				printf("data: ");
				for (int k =0; k<crypt_key_len; k++){//printf("%02x",crypt_text[k]); 
				buffer[iphdrlen+3+k] = crypt_key[k];} 
				// printf("\n");
			} 
			buffer[iphdrlen] = 0x62;
			for (int j=0; j<crypt_text_len; j++) {buffer[iphdrlen+3+j]= crypt_text[j]; printf("%02x", crypt_text[j]);} printf("\n");
			if (stageNo == 6 || stageNo == 7) sendto(srv_fd, buffer,(crypt_text_len+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
			else sendto(fd, buffer,(crypt_text_len+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
			memset((char *) &buffer, 0, sizeof(buffer));
			if (stageNo == 6 || stageNo == 7) recvfrom(srv_fd, buffer, 2048, 0, (struct sockaddr *)&remaddr, &addrlen);
			else recvfrom(fd, buffer, 2048, 0, (struct sockaddr *)&remaddr, &addrlen);
			printf("parent recived\n");
			printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
			for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buffer[20+i]);} printf("\n"); 
			fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
			for(int i = 0; i<3;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n");
			fprintf(fp,"incoming extend-done circuit, incoming: 0x%02x%02x from port: %d\n",buffer[21],buffer[22],ntohs(remaddr.sin_port));
			fflush(fp);		
			
		}
	}
	printf("circuit creation complete\n");
	// while(1);
	return 1;
}

int tunnel_reader(int srv_fd, FILE *fp, unsigned int *rport, unsigned char *key)
{
	char tun_name[IFNAMSIZ];
	char buffer[8192], packet[300];
	struct sockaddr_in remaddr;
	socklen_t addrlen = sizeof(remaddr);
	fd_set master_set;
	int max_sd;
	int recvlen;
	strcpy(tun_name, "tun1");
	int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI); 
	struct sockaddr_in source,dest, orgin_src,orgin_dst;
	char *server = "127.0.0.1";
	
	unsigned char *crypt_text;
	int crypt_text_len;
	unsigned char *clear_crypt_text;
	int clear_crypt_text_len;
	
	AES_KEY enc_key;
	
	if(tun_fd < 0)
	{
		perror("Open tunnel interface");
		exit(1);
	}
	FD_ZERO(&master_set);
	fcntl(tun_fd, F_SETFL, O_NONBLOCK);
	fcntl(srv_fd, F_SETFL, O_NONBLOCK);
	if (tun_fd > srv_fd)
	max_sd = (tun_fd + 1);
	else if(srv_fd > tun_fd)   
	max_sd = (srv_fd + 1);
	FD_SET(tun_fd, &master_set);
	FD_SET(srv_fd, &master_set);
	int nb;
	int e_reply=0;
	// int init_first = 0;
	hashtable_t *hashtable = ht_create( 65536 );
	ht_set( hashtable, "key1", "inky" );
	// char circuit_key;
	int circuit_counter= 1;
	int packet_counter=0;
	char circuit_counter_str[10];
	unsigned long ip_decimal2;
	for(int i = 0; i < sizeof(removed_list); i++){removed_list[i]=0xff;}
	while(1) ////////////////////
	{
		memset(&buffer, 0, sizeof(buffer));
		FD_ZERO(&master_set);
		FD_SET(tun_fd, &master_set);
		FD_SET(srv_fd, &master_set);
		nb = select(max_sd,&master_set,NULL,NULL,NULL);
		if (nb < 0)
		{
			perror("select");
			close(tun_fd);
			close(srv_fd);
			exit(1);
		}
		
		if (nb)
		{
			
			if (FD_ISSET(srv_fd,&master_set))
			{
				/* Packet received on a Broadcast Socket */
				if ((recvlen = recvfrom(srv_fd, buffer, 8192, 0, (struct sockaddr *)&remaddr, &addrlen) ) < 0)
				{
					perror("recvfrom:sockrb");
					continue;
					} else {
					if(stageNo < 5){
						struct iphdr *iph = (struct iphdr*)buffer;
						unsigned short iphdrlen = iph->ihl*4;
						struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);
						struct sockaddr_in source,dest;
						memset(&source, 0, sizeof(source));
						source.sin_addr.s_addr = iph->saddr;
						memset(&dest, 0, sizeof(dest));
						dest.sin_addr.s_addr = iph->daddr;
						//printf("Parent: in loop received message: \"%s\" (%d bytes) from port %d\n", buffer, recvlen, ntohs(remaddr.sin_port));
						fprintf(fp,"ICMP from port: %d, src: %s, ",ntohs(remaddr.sin_port), inet_ntoa(source.sin_addr));
						fprintf(fp,"dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),e_reply);
						printf("Parent recived from child src: %s, ",inet_ntoa(source.sin_addr));
						printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(icmph->type));
						fflush(fp);
						// printf("ACTUAL:  ");
						// printf("\n");
						// printf("IP Header\n");
						// printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
						// printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
						// printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
						// printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
						// printf("   |-Identification    : %d\n",ntohs(iph->id));
						// printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
						// printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
						// printf("   |-Checksum : %d\n",ntohs(iph->check));
						// printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
						// printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
						// for(int i =0; i< 90; i++){printf("%02x ", (unsigned int)buffer[i]);}
						write(tun_fd,buffer,sizeof(buffer));
					}
					else if (stageNo ==5 ) {
						char *packet_content = buffer+23;
						struct iphdr *packet_iph = (struct iphdr*)packet_content;
						// unsigned short iphdrlen = packet_iph->ihl*4;
						// struct icmphdr *packet_icmph = (struct icmphdr *)(buffer + iphdrlen);
						memset(&source, 0, sizeof(source));
						source.sin_addr.s_addr = packet_iph->saddr;
						fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n"); fflush(fp);
						fprintf(fp,"incoming packet, circuit incoming: 0x%02x, src: %s, ",0x01,inet_ntoa(source.sin_addr));
						fprintf(fp,"dst: %s\n",inet_ntoa(orgin_src.sin_addr));
						fflush(fp);
						printf("incoming packet, circuit incoming: 0x%02x, src: %s, ",0x01,inet_ntoa(source.sin_addr));
						printf("dst: %s\n",inet_ntoa(orgin_src.sin_addr));
						packet_iph->saddr = source.sin_addr.s_addr;
						packet_iph->daddr = orgin_src.sin_addr.s_addr;
						packet_iph->check = 0;
						packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
						// for(int i=0; i<recvlen-23; i++){printf("%02x ",packet_content[i]);} printf("\n");
						write(tun_fd,packet_content,recvlen-23);
						
					}
					else if (stageNo ==6 ) {
						unsigned char tempkey[16];
						char* pkt=buffer+23;
						printf("parent recived the final packert of size %d and data: \n",recvlen);
						printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buffer[20+i]);} printf("\n"); 
						fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n"); 
						for (int j =0; j<hopsNo; j++){
							
							for (int k =0; k<16; k++){
								tempkey[k]=(1+hops_list[j]) ^ key[k];
								printf("%02x",tempkey[k]);
							}
							
							class_AES_set_decrypt_key(tempkey, &enc_key);
							if (j == 0){
								//class_AES_encrypt_with_padding(buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding((unsigned char*)pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("here\n");
							}
							else{
								//class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding(clear_crypt_text, clear_crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("there\n");
							}
							printf("new data: ");
							for (int k =0; k<clear_crypt_text_len; k++){printf("%02x",clear_crypt_text[k]);} printf("\n");
						}
						printf("incoming packet, circuit incoming: 0x%02x, src: %s, ",0x01,inet_ntoa(dest.sin_addr));
						printf("dst: %s\n",inet_ntoa(orgin_src.sin_addr));
						fprintf(fp,"incoming packet, circuit incoming: 0x%02x, src: %s, ",0x01,inet_ntoa(dest.sin_addr));
						fprintf(fp,"dst: %s\n",inet_ntoa(orgin_src.sin_addr)); fflush(fp);
						struct iphdr *packet_iph = (struct iphdr*)clear_crypt_text;
						packet_iph->saddr = dest.sin_addr.s_addr;
						packet_iph->daddr = orgin_src.sin_addr.s_addr;
						packet_iph->check = 0;
						packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
						write(tun_fd,clear_crypt_text,clear_crypt_text_len);
					}
					else if (stageNo == 7 ) {
						unsigned char tempkey[16];
						char* pkt=buffer+23;
						printf("parent recived the final packert of size %d and data: \n",recvlen);
						printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buffer[20+i]);} printf("\n"); 
						fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n"); 
						for (int j =0; j<hopsNo; j++){
							
							for (int k =0; k<16; k++){
								tempkey[k]=(1+hops_list[j]) ^ key[k];
								printf("%02x",tempkey[k]);
							}
							
							class_AES_set_decrypt_key(tempkey, &enc_key);
							if (j == 0){
								//class_AES_encrypt_with_padding(buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding((unsigned char*)pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("here\n");
							}
							else{
								//class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding(clear_crypt_text, clear_crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("there\n");
							}
							printf("new data: ");
							for (int k =0; k<clear_crypt_text_len; k++){printf("%02x",clear_crypt_text[k]);} printf("\n");
						}
						printf("incoming packet, circuit incoming: 0x%02x, src: %s, ",0x01,inet_ntoa(dest.sin_addr));
						printf("dst: %s\n",inet_ntoa(orgin_src.sin_addr));
						fprintf(fp,"incoming packet, circuit incoming: 0x%02x, src: %s, ",0x01,inet_ntoa(dest.sin_addr));
						fprintf(fp,"dst: %s\n",inet_ntoa(orgin_src.sin_addr)); fflush(fp);
						struct iphdr *packet_iph = (struct iphdr*)clear_crypt_text;
						struct tcphdr *tcph = (struct tcphdr *) (clear_crypt_text + sizeof (struct ip));
						struct pseudo_header psh;
						printf("parent recieved check= %x\n",tcph->check);
						tcph->check = 0;
						packet_iph->saddr = dest.sin_addr.s_addr;
						packet_iph->daddr = orgin_src.sin_addr.s_addr;
						packet_iph->check = 0;
						packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
						
						//Now the TCP checksum
						psh.source_address = dest.sin_addr.s_addr;
						psh.dest_address = orgin_src.sin_addr.s_addr;
						psh.placeholder = 0;
						psh.protocol = IPPROTO_TCP;
						psh.tcp_length = htons(clear_crypt_text_len-20);
						
						int psize = sizeof(struct pseudo_header) + clear_crypt_text_len-20;
						char *pseudogram = malloc(psize);
						memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
						memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , clear_crypt_text_len-20);
						printf("parent method1: %x method2: %x \n",in_cksum ((u16 *) pseudogram, psize),csum( (unsigned short*) pseudogram , psize));
						//tcph->check = csum( (unsigned short*) pseudogram , psize);
						tcph->check = in_cksum ((u16 *) pseudogram, psize);
						write(tun_fd,clear_crypt_text,clear_crypt_text_len);
					}
					else if (stageNo == 8 && buffer[20]!=0x63) {
						unsigned char tempkey[16];
						char* pkt=buffer+23;
						printf("parent recived the final packert of size %d and data: \n",recvlen);
						printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buffer[20+i]);} printf("\n"); 
						fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n"); 
						for (int j =0; j<hopsNo; j++){
							
							for (int k =0; k<16; k++){
								tempkey[k]=(1+hops_list[j]) ^ key[k];
								printf("%02x",tempkey[k]);
							}
							
							class_AES_set_decrypt_key(tempkey, &enc_key);
							if (j == 0){
								//class_AES_encrypt_with_padding(buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding((unsigned char*)pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("here\n");
							}
							else{
								//class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding(clear_crypt_text, clear_crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("there\n");
							}
							printf("new data: ");
							for (int k =0; k<clear_crypt_text_len; k++){printf("%02x",clear_crypt_text[k]);} printf("\n");
						}
						printf("incoming packet, circuit incoming: 0x%02x%02x, src: %s, ",buffer[21],buffer[22],inet_ntoa(dest.sin_addr));
						printf("dst: %s\n",inet_ntoa(orgin_src.sin_addr));
						fprintf(fp,"incoming packet, circuit incoming: 0x%02x%02x, src: %s, ",buffer[21],buffer[22],inet_ntoa(dest.sin_addr));
						fprintf(fp,"dst: %s\n",inet_ntoa(orgin_src.sin_addr)); fflush(fp);
						struct iphdr *packet_iph = (struct iphdr*)clear_crypt_text;
						struct tcphdr *tcph = (struct tcphdr *) (clear_crypt_text + sizeof (struct ip));
						struct pseudo_header psh;
						printf("parent recieved check= %x\n",tcph->check);
						tcph->check = 0;
						packet_iph->saddr = dest.sin_addr.s_addr;
						packet_iph->daddr = orgin_src.sin_addr.s_addr;
						packet_iph->check = 0;
						packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
						
						//Now the TCP checksum
						psh.source_address = dest.sin_addr.s_addr;
						psh.dest_address = orgin_src.sin_addr.s_addr;
						psh.placeholder = 0;
						psh.protocol = IPPROTO_TCP;
						psh.tcp_length = htons(clear_crypt_text_len-20);
						
						int psize = sizeof(struct pseudo_header) + clear_crypt_text_len-20;
						char *pseudogram = malloc(psize);
						memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
						memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , clear_crypt_text_len-20);
						printf("parent method1: %x method2: %x \n",in_cksum ((u16 *) pseudogram, psize),csum( (unsigned short*) pseudogram , psize));
						//tcph->check = csum( (unsigned short*) pseudogram , psize);
						tcph->check = in_cksum ((u16 *) pseudogram, psize);
						write(tun_fd,clear_crypt_text,clear_crypt_text_len);
					}
					else if (stageNo == 9 && (unsigned char)buffer[20]==0x92) {
							char circuit_key1[20];
							sprintf(circuit_key1, "%ld", ip_decimal2);
							ht_set( hashtable, circuit_key1, "x" );
							int existt = 0;
							fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
							for(int i = 0; i<recvlen-20;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n"); 
							for (int i =0; i<sizeof(removed_list); i++){if(removed_list[i] == hops_list[1]){existt = 1;}}
							if (existt == 0){
									removed_list[removed_ctr] = hops_list[1];
									removed_ctr++;
							}
							
						}
					else if (stageNo == 9 && buffer[20]!=0x63) {
						unsigned char tempkey[16];
						char* pkt=buffer+23;
						printf("parent recived the final packert of size %d and data: \n",recvlen);
						printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buffer[20+i]);} printf("\n"); 
						fprintf(fp,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
						for(int i = 0; i<recvlen-20;i++){fprintf(fp,"%02x",(unsigned char)buffer[20+i]);} fprintf(fp,"\n"); 
						for (int j =0; j<hopsNo; j++){
							
							for (int k =0; k<16; k++){
								tempkey[k]=(1+hops_list[j]) ^ key[k];
								printf("%02x",tempkey[k]);
							}
							
							class_AES_set_decrypt_key(tempkey, &enc_key);
							if (j == 0){
								//class_AES_encrypt_with_padding(buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding((unsigned char*)pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("here\n");
							}
							else{
								//class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
								class_AES_decrypt_with_padding(clear_crypt_text, clear_crypt_text_len, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
								printf("there\n");
							}
							printf("new data: ");
							for (int k =0; k<clear_crypt_text_len; k++){printf("%02x",clear_crypt_text[k]);} printf("\n");
						}
						printf("incoming packet, circuit incoming: 0x%02x%02x, src: %s, ",buffer[21],buffer[22],inet_ntoa(dest.sin_addr));
						printf("dst: %s\n",inet_ntoa(orgin_src.sin_addr));
						fprintf(fp,"incoming packet, circuit incoming: 0x%02x%02x, src: %s, ",buffer[21],buffer[22],inet_ntoa(dest.sin_addr));
						fprintf(fp,"dst: %s\n",inet_ntoa(orgin_src.sin_addr)); fflush(fp);
						struct iphdr *packet_iph = (struct iphdr*)clear_crypt_text;
						struct tcphdr *tcph = (struct tcphdr *) (clear_crypt_text + sizeof (struct ip));
						struct pseudo_header psh;
						printf("parent recieved check= %x\n",tcph->check);
						tcph->check = 0;
						packet_iph->saddr = dest.sin_addr.s_addr;
						packet_iph->daddr = orgin_src.sin_addr.s_addr;
						packet_iph->check = 0;
						packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
						
						//Now the TCP checksum
						psh.source_address = dest.sin_addr.s_addr;
						psh.dest_address = orgin_src.sin_addr.s_addr;
						psh.placeholder = 0;
						psh.protocol = IPPROTO_TCP;
						psh.tcp_length = htons(clear_crypt_text_len-20);
						
						int psize = sizeof(struct pseudo_header) + clear_crypt_text_len-20;
						char *pseudogram = malloc(psize);
						memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
						memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , clear_crypt_text_len-20);
						printf("parent method1: %x method2: %x \n",in_cksum ((u16 *) pseudogram, psize),csum( (unsigned short*) pseudogram , psize));
						//tcph->check = csum( (unsigned short*) pseudogram , psize);
						tcph->check = in_cksum ((u16 *) pseudogram, psize);
						write(tun_fd,clear_crypt_text,clear_crypt_text_len);
					}
					/* Packet Processing code with sendto() in the end*/
					
				}
			}
			else if (FD_ISSET(tun_fd,&master_set))
			{
				/* Packet received on a Unicast/Broadcast Socket */
				if ((recvlen = read(tun_fd,buffer,sizeof(buffer))) < 0)
				{
					perror("recvfrom:socksrusb");
					continue;
				}
				else {
					// printf("Read a packet from tunnel, packet length:%d %s\n", recvlen,buffer);
					struct iphdr *iph = (struct iphdr*)buffer;
					unsigned short iphdrlen = iph->ihl*4;
					struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);
					unsigned int icmptype= (unsigned int)(icmph->type);
					memset(&source, 0, sizeof(source));
					source.sin_addr.s_addr = iph->saddr;
					memset(&orgin_src, 0, sizeof(orgin_src));
					orgin_src.sin_addr.s_addr = iph->saddr;
					memset(&dest, 0, sizeof(dest));
					dest.sin_addr.s_addr = iph->daddr;
					memset(&orgin_dst, 0, sizeof(orgin_dst));
					orgin_dst.sin_addr.s_addr = iph->daddr;
					//write(tun_fd,buffer,sizeof(buffer));
					//printf("Parent: packt ver= %d\n",iph->protocol);
					if(iph->protocol == 1 || iph->protocol == 253 || iph->protocol == 6){
						printf("Parent: packt ver= %d SourcIP=%s ",iph->protocol, inet_ntoa(source.sin_addr));
						printf("DestIP=%s type= %d\n",inet_ntoa(dest.sin_addr),icmptype);
						unsigned long ip_decimal1;
						if(iph->protocol == 1 || iph->protocol == 253){
							fprintf(fp,"ICMP from tunnel, src: %s, ", inet_ntoa(source.sin_addr));
							fprintf(fp,"dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),icmptype);
							fflush(fp);	
							ip_decimal1 = ntohl(dest.sin_addr.s_addr)+(unsigned long)ntohs(iph->protocol);
						}
						else if(iph->protocol == 6){
							struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
							fprintf(fp,"TCP from tunnel, src IP/port: %s:%u, ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
							fprintf(fp,"dst IP/port: %s:%u, seqno: %u, ackno: %u\n",inet_ntoa(dest.sin_addr),ntohs(tcph->dest), ntohl(tcph->seq),ntohl(tcph->ack_seq));
							fflush(fp);
							ip_decimal1 = ntohl(dest.sin_addr.s_addr)+(unsigned long)ntohs(tcph->dest)+(unsigned long)ntohs(iph->protocol)+(unsigned long)ntohs(tcph->source);
						}
						// uint32_t ip_decimal = ntohl(dest.sin_addr.s_addr);
						unsigned long ip_decimal = ntohl(dest.sin_addr.s_addr);
						
						char circuit_key[20];
						sprintf(circuit_key, "%ld", ip_decimal1);
						ip_decimal2 = ip_decimal1;
						sprintf(circuit_counter_str, "%d", circuit_counter);
						int chosen_router = ip_decimal%routerNo;
						for(int i=0; i<routerNo;i++){printf("port of router [%d] = %d, ", i, rport[i]);}
						printf("ip address in decimal is %ld and should be routed to router %d which has port %d\n", ip_decimal,chosen_router,rport[chosen_router]);
						memset((char *) &remaddr, 0, sizeof(remaddr));
						remaddr.sin_family = AF_INET;
						if (inet_aton(server, &remaddr.sin_addr)==0) {
							fprintf(stderr, "inet_aton() failed\n");
							exit(1);
						}
						if(stageNo == 4){
							remaddr.sin_port = htons(rport[chosen_router]);
							sendto(srv_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
						}
						else if(stageNo == 5){
							memset((char *) &packet, 0, sizeof(packet));
							struct iphdr *iph = (struct iphdr*)packet;
							unsigned short iphdrlen = 20;
							remaddr.sin_port = htons(rport[(int)hops_list[0]]);
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							packet[iphdrlen] = 0x51;
							packet[iphdrlen+1] = 0x00;
							packet[iphdrlen+2] = 0x01;
							for(int i=0; i<recvlen;i++){packet[iphdrlen+3+i]=buffer[i];}
							sendto(srv_fd, packet, (recvlen+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
						}
						else if(stageNo == 6){
							unsigned char tempkey[16];
							memset((char *) &packet, 0, sizeof(packet));
							struct iphdr *iph = (struct iphdr*)packet;
							struct iphdr *iph_original = (struct iphdr*)buffer;
							unsigned short iphdrlen = 20;
							remaddr.sin_port = htons(rport[(int)hops_list[0]]);
							iph_original->saddr = inet_addr("0.0.0.0");
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							packet[iphdrlen] = 0x61;
							packet[iphdrlen+1] = 0x00;
							packet[iphdrlen+2] = 0x01;
							// char *content = buffer + 23;
							printf("buffer content: ");
							for (int k =0; k<recvlen; k++){printf("%02x",(unsigned char)buffer[k]);}
							printf("\n");
							for (int j =hopsNo; j>0; j--){
								
								for (int k =0; k<16; k++){
									tempkey[k]=(1+hops_list[j-1]) ^ key[k];
									printf("%02x",tempkey[k]);
								}
								
								class_AES_set_encrypt_key(tempkey, &enc_key);
								if (j == hopsNo){
									class_AES_encrypt_with_padding((unsigned char*)buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
									printf("here\n");
								}
								else{
									class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
									printf("there\n");
								}
								printf("new data: ");
								for (int k =0; k<crypt_text_len; k++){printf("%02x",crypt_text[k]);} printf("\n");
							}
							
							for(int i=0; i<crypt_text_len;i++){packet[iphdrlen+3+i]=crypt_text[i];}
							sendto(srv_fd, packet, (crypt_text_len+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
						}
						else if(stageNo == 7){
							unsigned char tempkey[16];
							memset((char *) &packet, 0, sizeof(packet));
							struct iphdr *iph = (struct iphdr*)packet;
							struct iphdr *iph_original = (struct iphdr*)buffer;
							unsigned short iphdrlen = 20;
							remaddr.sin_port = htons(rport[(int)hops_list[0]]);
							iph_original->saddr = inet_addr("0.0.0.0");
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							packet[iphdrlen] = 0x61;
							packet[iphdrlen+1] = 0x00;
							packet[iphdrlen+2] = 0x01;
							// char *content = buffer + 23;
							printf("buffer content: ");
							for (int k =0; k<recvlen; k++){printf("%02x",(unsigned char)buffer[k]);}
							printf("\n");
							for (int j =hopsNo; j>0; j--){
								
								for (int k =0; k<16; k++){
									tempkey[k]=(1+hops_list[j-1]) ^ key[k];
									printf("%02x",tempkey[k]);
								}
								
								class_AES_set_encrypt_key(tempkey, &enc_key);
								if (j == hopsNo){
									class_AES_encrypt_with_padding((unsigned char*)buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
									printf("here\n");
								}
								else{
									class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
									printf("there\n");
								}
								printf("new data: ");
								for (int k =0; k<crypt_text_len; k++){printf("%02x",crypt_text[k]);} printf("\n");
							}
							
							for(int i=0; i<crypt_text_len;i++){packet[iphdrlen+3+i]=crypt_text[i];}
							sendto(srv_fd, packet, (crypt_text_len+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
						}
						else if(stageNo == 8){
							//fcntl(srv_fd, F_SETFL, ~O_NONBLOCK);
							printf( "%s  ", circuit_key );
							if (ht_get( hashtable, circuit_key ) != NULL) {printf( "circuit no: %s\n\n\n\n", ht_get( hashtable, circuit_key ) );}
							else {
								printf( "%s\n\n\n\n", "key doesnt exist" );
								ht_set( hashtable, circuit_key, circuit_counter_str );
								//srand (time(NULL));
								int Duplicate;
								//memset((char *) &hops_list, 0, sizeof(hops_list));
								for (int I = 0; I < hopsNo; I++)
								{
									do
									{
										Duplicate = 0;
										hops_list[I] = (rand()%routerNo); 
										for (int J = I - 1; J > -1; J--) // works backwards from the recently generated element to element 0
										if (hops_list[I] == hops_list[J]) //checks if number is already used
										Duplicate = 1; //sets Duplicate to true to indicate there is a repeat
									} while (Duplicate); //loops until a new, distinct number is generated
								}
								init_circuit(srv_fd,fp,rport,key,circuit_counter);
								circuit_counter++;
							}
							// if (init_first == 0){init_circuit(srv_fd,fp,rport,key,1); init_first =1;}
							//fcntl(srv_fd, F_SETFL, O_NONBLOCK);
							// usleep(1000000);
							int cir_num = atoi(ht_get( hashtable, circuit_key ));
							// printf("0x%02x\n\n",(char)cir_num);
							unsigned char tempkey[16];
							memset((char *) &packet, 0, sizeof(packet));
							struct iphdr *iph = (struct iphdr*)packet;
							struct iphdr *iph_original = (struct iphdr*)buffer;
							unsigned short iphdrlen = 20;
							remaddr.sin_port = htons(rport[(int)hops_list[0]]);
							iph_original->saddr = inet_addr("0.0.0.0");
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							packet[iphdrlen] = 0x61;
							packet[iphdrlen+1] = 0x00;
							packet[iphdrlen+2] = (char)cir_num;
							printf("buffer content: ");
							for (int k =0; k<recvlen; k++){printf("%02x",(unsigned char)buffer[k]);}
							printf("\n");
							for (int j =hopsNo; j>0; j--){
								
								for (int k =0; k<16; k++){
									tempkey[k]=(1+hops_list[j-1]) ^ key[k];
									printf("%02x",tempkey[k]);
								}
								
								class_AES_set_encrypt_key(tempkey, &enc_key);
								if (j == hopsNo){
									class_AES_encrypt_with_padding((unsigned char*)buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
									printf("here\n");
								}
								else{
									class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
									printf("there\n");
								}
								printf("new data: ");
								for (int k =0; k<crypt_text_len; k++){printf("%02x",crypt_text[k]);} printf("\n");
							}
							
							for(int i=0; i<crypt_text_len;i++){packet[iphdrlen+3+i]=crypt_text[i];}
							sendto(srv_fd, packet, (crypt_text_len+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr)); 
						}
						else if(stageNo == 9){
							//fcntl(srv_fd, F_SETFL, ~O_NONBLOCK);
							printf( "%s  ", circuit_key );
							if (ht_get( hashtable, circuit_key ) != NULL && strcmp(ht_get( hashtable, circuit_key ), "x")) {printf( "circuit no: %s\n\n\n\n", ht_get( hashtable, circuit_key ) ); packet_counter++;}
							else {
								printf( "%s\n\n\n\n", "key doesnt exist" );
								packet_counter = 0;
								ht_set( hashtable, circuit_key, circuit_counter_str );
								//srand (time(NULL));
								int Duplicate;
								//memset((char *) &hops_list, 0, sizeof(hops_list));
								for (int I = 0; I < hopsNo; I++)
								{
									do
									{
										Duplicate = 0;
										hops_list[I] = (rand()%routerNo); 
										for (int k = 0; k < sizeof(removed_list); k++){
											if (hops_list[I] == removed_list[k]){Duplicate = 1;}
										}
										for (int J = I - 1; J > -1; J--) // works backwards from the recently generated element to element 0
										if (hops_list[I] == hops_list[J]) //checks if number is already used
										Duplicate = 1; //sets Duplicate to true to indicate there is a repeat
										printf("hla\n");
									} while (Duplicate); //loops until a new, distinct number is generated
								}
								init_circuit(srv_fd,fp,rport,key,circuit_counter);
								circuit_counter++;
							}
							//fcntl(srv_fd, F_SETFL, O_NONBLOCK);
							// usleep(1000000);
							int cir_num = atoi(ht_get( hashtable, circuit_key ));
							// printf("0x%02x\n\n",(char)cir_num);
							unsigned char tempkey[16];
							memset((char *) &packet, 0, sizeof(packet));
							struct iphdr *iph = (struct iphdr*)packet;
							struct iphdr *iph_original = (struct iphdr*)buffer;
							unsigned short iphdrlen = 20;
							remaddr.sin_port = htons(rport[(int)hops_list[0]]);
							iph_original->saddr = inet_addr("0.0.0.0");
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							packet[iphdrlen] = 0x61;
							packet[iphdrlen+1] = 0x00;
							packet[iphdrlen+2] = (char)cir_num;
							printf("buffer content: ");
							for (int k =0; k<recvlen; k++){printf("%02x",(unsigned char)buffer[k]);}
							printf("\n");
							for (int j =hopsNo; j>0; j--){
								
								for (int k =0; k<16; k++){
									tempkey[k]=(1+hops_list[j-1]) ^ key[k];
									printf("%02x",tempkey[k]);
								}
								
								class_AES_set_encrypt_key(tempkey, &enc_key);
								if (j == hopsNo){
									class_AES_encrypt_with_padding((unsigned char*)buffer, recvlen, &crypt_text, &crypt_text_len, &enc_key);
									printf("here\n");
								}
								else{
									class_AES_encrypt_with_padding(crypt_text, crypt_text_len, &crypt_text, &crypt_text_len, &enc_key);
									printf("there\n");
								}
								printf("new data: ");
								for (int k =0; k<crypt_text_len; k++){printf("%02x",crypt_text[k]);} printf("\n");
							}
							
							for(int i=0; i<crypt_text_len;i++){packet[iphdrlen+3+i]=crypt_text[i];}
							sendto(srv_fd, packet, (crypt_text_len+23), 0, (struct sockaddr *)&remaddr, sizeof(remaddr)); 
							//fprintf(fp,"packet No: %d \n", packet_counter); fflush(fp);
							if (packet_counter == dieAfter && removed_ctr < hopsNo){
								packet[20] = 0x91;
								remaddr.sin_port = htons(rport[(int)hops_list[1]]);
								sendto(srv_fd, packet, 23, 0, (struct sockaddr *)&remaddr, sizeof(remaddr)); 
								//fprintf(fp,"router %d will be killed at port %d \n", hops_list[1]+1, rport[(int)hops_list[1]]); fflush(fp);
								
							}
						}
						else {
							remaddr.sin_port = htons(rport[0]);
							sendto(srv_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remaddr, sizeof(remaddr));
						}
					}
					
					// iph->saddr = dest.sin_addr.s_addr;
					// iph->daddr = source.sin_addr.s_addr;
					// icmph -> type = ICMP_ECHOREPLY;
					// icmph -> code = 0;
					// icmph -> checksum = 0;
					// iph->frag_off = 0x40;
					// iph->ttl = 128;
					// unsigned short check = ntohs(iph->check);
					// iph->check = 0;
					// iph->check = csum ((unsigned short *) buffer, ntohs(iph->tot_len));
					// iph->check = in_cksum ((u16 *) iph, sizeof (struct iphdr));
					// printf("\n");
					// printf("IP Header\n");
					// printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
					// printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
					// printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
					// printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
					// printf("   |-Identification    : %d\n",ntohs(iph->id));
					// printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
					// printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
					// printf("   |-Checksum : %d\n",ntohs(iph->check));
					// printf("   |-Expected Checksum : %d\n",check);
					// printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
					// printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
					// printf("EXPECTED:  ");
					// iph->check = htons(check);
					// printf("   |-Checksum : %d\n",ntohs(iph->check));
					// for(int i =0; i< sizeof(buffer); i++){printf("%02x ", (unsigned int)buffer[i]);}
					// write(tun_fd,buffer,sizeof(buffer));
					
					
				}
			} 
		}
		
	}
}

int init_router(int router_number, char* router_ip)
{
	
	struct sockaddr_in myaddr, remaddr,webaddr;
	struct sockaddr_in servaddr;
	struct sockaddr_in source,source_orgin,dest,save_src,save_dst;
	int fd,webfd, webfd1, slen=sizeof(remaddr);
	int sent_size;
	char buf[8192];	/* message buffer */
	char buf1[8192];
	unsigned char key[16];
	int recvlen;		/* # bytes in acknowledgement message */
	char *server = "127.0.0.1";	/* change this to use a different server */
	// char *eth1 = "192.168.203.2";
	// char *target = "23.185.0.3";
	fd_set master_set;
	int max_sd;
	///////////////// STAGE 5 variables /////////////////
	unsigned char in_ID[2]={0xff,0xff};
	unsigned char in_ID8[20][2];
	for (int i =0; i<20; i++){for (int j =0; j<2; j++){in_ID8[i][j]=0xff;}}
	// printf("annaaaaaaaa %02x", in_ID8[7][1]);
	unsigned char out_ID[2]={0xff,0xff};
	unsigned char out_portarr[2];
	int in_port;
	unsigned int out_port;
	int in_port8[20];
	unsigned int out_port8[20];
	int key_set=0;
	int key_set8[20];
	for (int i =0; i<20; i++){key_set8[i]=0;}
	unsigned char *crypt_text;
	int crypt_text_len;
	unsigned char *clear_crypt_text;
	int clear_crypt_text_len;
	AES_KEY enc_key;
	int cir_num_web;
	////////////////////////////////////////////////////////
	socklen_t addrlen = sizeof(remaddr);	
	/* create a socket */
	
	if ((fd=socket(AF_INET, SOCK_DGRAM, 0))==-1)
	printf("socket created\n");
	webfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	webfd1 = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if (webfd < 0) {
        perror("socket");
	}
	if (webfd1 < 0) {
        perror("socket");
	}
	/* bind it to all local addresses and pick any port number */
	
	memset((char *)&myaddr, 0, sizeof(myaddr)); ///////////////////////// SET MY ADDRESS
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(0);
	
	if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		perror("bind failed");
		return 0;
	}       
	
	memset((char *)&webaddr, 0, sizeof(webaddr)); ////////////////////// SET WEB SOCKET remote
	webaddr.sin_family = AF_INET;
	if (inet_aton(router_ip, &webaddr.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}
	if (bind(webfd, (struct sockaddr *)&webaddr, sizeof(webaddr)) < 0) {
		perror("bind failed aaaaaaa");
		return 0;
	}  
	if (bind(webfd1, (struct sockaddr *)&webaddr, sizeof(webaddr)) < 0) {
		perror("bind failed aaaaaaa");
		return 0;
	}  
    int on = 1;
    // We shall provide IP headers
    if (setsockopt (webfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
    {
        perror("setsockopt");
        return (0);
	}
	if (setsockopt (webfd1, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
    {
        perror("setsockopt");
        return (0);
	}
    //allow socket to send datagrams to broadcast addresses
    if (setsockopt (webfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
    {
        perror("setsockopt");
        return (0);
	} 
	if (setsockopt (webfd1, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
    {
        perror("setsockopt");
        return (0);
	} 
	// struct ifreq ifr;
	
	// memset(&ifr, 0, sizeof(ifr));
	printf("I'm node %d and my IP is %s and binding to socket eth%d\n",router_number,router_ip,router_number);
	// snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth%d",router_number);
	// if (setsockopt(webfd_recv, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
	// perror("bind to interface error");
	// return (0);
	// }
	//////////////////////////////////////////////////////////////////////////////////////////////
	memset((char *) &remaddr, 0, sizeof(remaddr)); /////////////////// SET REMOTE ADDRESS
	remaddr.sin_family = AF_INET;
	remaddr.sin_port = htons(port);
	if (inet_aton(server, &remaddr.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}
	unsigned int alen = sizeof(myaddr);
	if (getsockname(fd, (struct sockaddr *)&myaddr, &alen) < 0) {
		perror("getsockname failed");
		return 0;
	} 
	printf("Child: Sending packet to %s port %d and my port is %d\n", server, port,ntohs(myaddr.sin_port));
	sprintf(buf, "%d",getpid());
	char filename[20];
	snprintf(filename, sizeof(filename), "stage%d.router%d.out", stageNo, router_number);
	FILE *fr_log = fopen(filename, "wb+");
	if(stageNo > 4){fprintf(fr_log,"router: %d, pid: %d, port: %d, IP: %s\n",router_number,getpid(),ntohs(myaddr.sin_port), router_ip);}
	else{fprintf(fr_log,"router: %d, pid: %d, port: %d\n",router_number,getpid(),ntohs(myaddr.sin_port));}
	fflush(fr_log);
	
	if (sendto(fd, buf, strlen(buf), 0, (struct sockaddr *)&remaddr, slen)==-1) {
		perror("sendto");
		exit(1);
	}
	memset(&buf, 0, sizeof(buf));
	memset((char *) &remaddr, 0, sizeof(remaddr));
	FD_ZERO(&master_set);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	fcntl(webfd, F_SETFL, O_NONBLOCK);
	fcntl(webfd1, F_SETFL, O_NONBLOCK);
	if (fd > webfd && fd > webfd1)
    max_sd = (fd + 1);
	else if(webfd > fd && webfd > webfd1)   
    max_sd = (webfd + 1);
	else if(webfd1 > fd && webfd1 > webfd)   
    max_sd = (webfd1 + 1);
	FD_SET(fd, &master_set);
	FD_SET(webfd, &master_set);
	FD_SET(webfd1, &master_set);
	int nb;
	int forked = 0;
	int pktCount[20];
	for(int i=0; i<20; i++){pktCount[i]=0;}
	int cr_cir_num;
	if((int)stageNo>1){ printf("waiting..");
		while(1){ 
			while (forked){
				if (crashed){
					printf("router %d worried about %d on circuit %d\n",ntohs(myaddr.sin_port), out_port8[cr_cir_num],cr_cir_num);
					fprintf(fr_log,"router %d worried about %d on circuit %d\n",ntohs(myaddr.sin_port), out_port8[cr_cir_num],cr_cir_num); fflush(fr_log);
					char recovery_pkt[16];
					recovery_pkt[0]= out_port8[cr_cir_num];
					for(int i = 1; i<16;i++){recovery_pkt[i]= 0x00;}
					char *fwd_pkt = recovery_pkt;
					class_AES_set_encrypt_key(key, &enc_key);
					class_AES_encrypt_with_padding((unsigned char*)fwd_pkt, 16, &crypt_text, &crypt_text_len, &enc_key);
					buf[20] = 0x92;
					buf[21] = in_ID8[cr_cir_num][0];
					buf[22] = in_ID8[cr_cir_num][1];
					for(int i=0; i<crypt_text_len;i++){buf[23+i]=crypt_text[i];}
					remaddr.sin_port = htons(in_port8[cr_cir_num]);
					recvlen = sendto(fd, buf, (23+16), 0, (struct sockaddr *)&remaddr, slen);
					//printf("sent %d bytes as recovery \n",recvlen );
					crashed = 0; alarm(0); kill(getpid(), SIGKILL);
				}
			}
			memset(&buf, 0, sizeof(buf));
			FD_ZERO(&master_set);
			FD_SET(fd, &master_set);
			FD_SET(webfd, &master_set);
			FD_SET(webfd1, &master_set);
			nb = select(max_sd,&master_set,NULL,NULL,NULL);
			if (nb < 0)
			{
				// perror("select");
				// close(fd);
				// close(webfd);
				// exit(1);
				continue;
			}
			if (nb){
				if (FD_ISSET(fd,&master_set)) {
					if ((recvlen = recvfrom(fd, buf, 8192, 0, (struct sockaddr *)&remaddr, &addrlen)) < 0)
					{
						perror("recvfrom:socksrusb");
						continue;
					}
					else {
						buf[recvlen] = 0;
						struct iphdr *iph = (struct iphdr*)buf;
						unsigned short iphdrlen = iph->ihl*4;
						struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen);
						memset(&source, 0, sizeof(source));
						source.sin_addr.s_addr = iph->saddr;
						memset(&source_orgin, 0, sizeof(source_orgin));
						source_orgin.sin_addr.s_addr = iph->saddr;
						memset(&dest, 0, sizeof(dest));
						dest.sin_addr.s_addr = iph->daddr;
						if (stageNo <=4){
							printf("child: received message: %s (%d byte) from port %d protocol: %d\n",buf, recvlen, ntohs(remaddr.sin_port),(iph->protocol));
							fprintf(fr_log,"ICMP from port: %d, src: %s, ",ntohs(remaddr.sin_port),inet_ntoa(source.sin_addr));
							fprintf(fr_log,"dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(icmph->type));
							fflush(fr_log);
						}
						if (stageNo == 2){
							iph->saddr = dest.sin_addr.s_addr;
							iph->daddr = source.sin_addr.s_addr;
							icmph -> type = ICMP_ECHOREPLY;
							icmph -> code = 0;
							icmph -> checksum = 0;
							fflush(fr_log);
							sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&remaddr, slen);
						}
						else if (stageNo == 3 || stageNo == 4) {								///////////////////////// SATAGE 3 ////////////////////////// in router ///////////////////
							iph->saddr = inet_addr(router_ip);
							memset(&source, 0, sizeof(source));
							source.sin_addr.s_addr = iph->saddr;
							memset(&dest, 0, sizeof(dest));
							dest.sin_addr.s_addr = iph->daddr;
							iph->check = 0;
							iph->check = in_cksum ((u16 *) iph, sizeof (struct iphdr));
							printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
							printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(icmph->type));
							servaddr.sin_family = AF_INET;
							char* addresss = inet_ntoa(dest.sin_addr);
							if (inet_aton(addresss, &servaddr.sin_addr)==0) {
								fprintf(stderr, "inet_aton() failed\n");
								exit(1);
							}
							//servaddr.sin_addr.s_addr = &(addresss);
							memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
							if ((sent_size = sendto(webfd, buf, 84, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
							{
								perror("send failed\n");
								break;
							}
						}
						else if (stageNo== 5 ||stageNo== 6 ){
							// out_portarr[0]=buf[23]; out_portarr[1]=buf[24];
							// outid = (router_number*256)+1;
							// memcpy(out_ID, &outid, 2);
							// in_port = ntohs(remaddr.sin_port);
							// out_port = (out_portarr[0] <<8) | out_portarr[1] ;
							// unsigned char *crypt_text;
							// int crypt_text_len;
							// unsigned char *clear_crypt_text;
							// int clear_crypt_text_len;
							// AES_KEY enc_key;
							// AES_KEY dec_key;
							out_ID[0]= (unsigned char)router_number;
							out_ID[1]= 0x01;
							if(buf[20]==0x52){
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),5);
								for(int i = 0; i<5;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),5);
								for(int i = 0; i<5;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								if (in_ID[0]==0xff && in_ID[1]==0xff){
									out_portarr[0]=buf[23]; out_portarr[1]=buf[24];
									in_port = ntohs(remaddr.sin_port);
									out_port = (out_portarr[0] <<8) | out_portarr[1] ;
									in_ID[0]= buf[21];
									in_ID[1]= buf[22];
									printf("new extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									fprintf(fr_log,"new extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									fflush(fr_log);
									buf[20]=0x53;
									sendto(fd, buf, 23, 0, (struct sockaddr *)&remaddr, slen);
								}
								else{
									printf("Node %d: forwarding extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									fprintf(fr_log,"forwarding extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									remaddr.sin_port = htons(out_port);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									sendto(fd, buf, 25, 0, (struct sockaddr *)&remaddr, slen);
								}
							}
							else if(buf[20]==0x53){
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); 
								fprintf(fr_log,"forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1],in_port);
								fflush(fr_log);
								remaddr.sin_port = htons(in_port);
								buf[21]= in_ID[0]; 
								buf[22]= in_ID[1];
								sendto(fd, buf, 25, 0, (struct sockaddr *)&remaddr, slen);
							}
							else if(buf[20]==0x51){
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								char *packet_content = buf+23;
								// printf("%02x\n",packet_content[0]);
								struct iphdr *packet_iph = (struct iphdr*)packet_content;
								memset(&source, 0, sizeof(source));
								source.sin_addr.s_addr = packet_iph->saddr;
								memset(&source_orgin, 0, sizeof(source_orgin));
								source_orgin.sin_addr.s_addr = packet_iph->saddr;
								memset(&dest, 0, sizeof(dest));
								dest.sin_addr.s_addr = packet_iph->daddr;
								fflush(fr_log);
								
								if(out_port == 65535){
									packet_iph->saddr = inet_addr(router_ip);
									printf("outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr));
									printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fprintf(fr_log,"outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
									// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
									// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
									servaddr.sin_family = AF_INET;
									char* addresss = inet_ntoa(dest.sin_addr);
									if (inet_aton(addresss, &servaddr.sin_addr)==0) {
										fprintf(stderr, "inet_aton() failed\n");
										exit(1);
									}
									//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
									memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
									if ((sent_size = sendto(webfd, packet_content, 84, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
									{
										perror("send failed\n");
										break;
									}
								}
								else {
									memset(&save_src, 0, sizeof(save_src));
									save_src.sin_addr.s_addr = packet_iph->saddr;
									memset(&save_dst, 0, sizeof(save_dst));
									save_dst.sin_addr.s_addr = packet_iph->daddr;
									packet_iph->saddr = inet_addr(router_ip);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									fprintf(fr_log,"relay packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],out_ID[0],out_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fflush(fr_log);
									remaddr.sin_port = htons(out_port);
									sendto(fd, buf, recvlen, 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x54){
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								fprintf(fr_log,"relay reply packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x, src:%s, ",out_ID[0],out_ID[1],in_ID[0],in_ID[1],inet_ntoa(save_dst.sin_addr));
								fprintf(fr_log,"incoming dst: %s, outgoing dest: %s\n",router_ip,inet_ntoa(save_src.sin_addr));
								fflush(fr_log);
								printf("\n");
								buf[21] = in_ID[0];
								buf[22] = in_ID[1];
								remaddr.sin_port = htons(in_port);
								sendto(fd, buf, recvlen, 0, (struct sockaddr *)&remaddr, slen);
							} 
							else if(buf[20]==0x65){
								char tmp_ID[2];
								tmp_ID[0]= buf[21];
								tmp_ID[1]= buf[22];
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								if(key_set ==0){
									in_port = ntohs(remaddr.sin_port);
									for(int i = 0; i<recvlen-23;i++){key[i]=buf[23+i];}
									fprintf(fr_log,"fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									key_set=1;
								}
								else{
									char *fwd_key = buf+23;
									buf[21]= out_ID[0];
									buf[22]= out_ID[1];
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_key, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",router_number,tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									remaddr.sin_port = htons(out_port);
									printf("sending to %d the following: ", out_port);
									for(int i = 0; i<(3+(clear_crypt_text_len));i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
							}
							else if(buf[20]==0x62){
								//printf("hello form %d\n",router_number);
								if (in_ID[0]==0xff && in_ID[1]==0xff){
									in_ID[0]= buf[21];
									in_ID[1]= buf[22];
									char *in_port_ptr = buf + 23;
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)in_port_ptr, 16, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									out_port = atoi((char*)clear_crypt_text);
									//printf("port after dec: %s\n",clear_crypt_text );
									fprintf(fr_log,"new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port); fflush(fr_log);
									printf("Node %d: new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									buf[20]=0x63;
									sendto(fd, buf, 23, 0, (struct sockaddr *)&remaddr, slen);
								}
								else{
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									printf("Node %d: forwarding extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									fprintf(fr_log,"forwarding extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									remaddr.sin_port = htons(out_port);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x63){
								buf[21]= in_ID[0];
								buf[22]= in_ID[1];
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n"); 
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								fprintf(fr_log,"forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1],in_port);
								fflush(fr_log);
								printf("forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1],in_port);
								remaddr.sin_port = htons(in_port);
								sendto(fd, buf, 25, 0, (struct sockaddr *)&remaddr, slen);
							}
							else if(buf[20]==0x61){
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								char *packet_content = buf+23;
								// printf("%02x\n",packet_content[0]);
								struct iphdr *packet_iph = (struct iphdr*)packet_content;
								memset(&source, 0, sizeof(source));
								source.sin_addr.s_addr = packet_iph->saddr;
								memset(&source_orgin, 0, sizeof(source_orgin));
								source_orgin.sin_addr.s_addr = packet_iph->saddr;
								memset(&dest, 0, sizeof(dest));
								dest.sin_addr.s_addr = packet_iph->daddr;
								fflush(fr_log);
								
								if(out_port == 65535){
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									memset(&source, 0, sizeof(source));
									source.sin_addr.s_addr = clear_packet_iph->saddr;
									memset(&source_orgin, 0, sizeof(source_orgin));
									source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
									memset(&dest, 0, sizeof(dest));
									dest.sin_addr.s_addr = clear_packet_iph->daddr;
									clear_packet_iph->saddr = inet_addr(router_ip);
									for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
									printf("outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr));
									printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fprintf(fr_log,"outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
									// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
									// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
									servaddr.sin_family = AF_INET;
									char* addresss = inet_ntoa(dest.sin_addr);
									if (inet_aton(addresss, &servaddr.sin_addr)==0) {
										fprintf(stderr, "inet_aton() failed\n");
										exit(1);
									}
									//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
									memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
									if ((sent_size = sendto(webfd, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
									{
										perror("send failed\n");
										break;
									}
								}
								else {
									// memset(&save_src, 0, sizeof(save_src));
									// save_src.sin_addr.s_addr = packet_iph->saddr;
									// memset(&save_dst, 0, sizeof(save_dst));
									// save_dst.sin_addr.s_addr = packet_iph->daddr;
									//packet_iph->saddr = inet_addr(router_ip);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									// struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									// clear_packet_iph->saddr = inet_addr(router_ip);
									fprintf(fr_log,"relay packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],out_ID[0],out_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fflush(fr_log);
									remaddr.sin_port = htons(out_port);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x64){
								char *fwd_pkt = buf+23;
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); 
								fprintf(fr_log,"relay reply packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1]);
								fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								printf("relay reply packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1]);
								buf[21] = in_ID[0];
								buf[22] = in_ID[1];
								//for(int i=0; i<recvlen-20;i++){printf("%02x", (unsigned char)buf[20+i]);}
								remaddr.sin_port = htons(in_port);
								printf("i'm node %d sending back to port %d\n", router_number, in_port);
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)fwd_pkt, recvlen-23, &crypt_text, &crypt_text_len, &enc_key);
								for(int i=0; i<crypt_text_len;i++){buf[23+i]=crypt_text[i];}
								//or(int i=0; i<crypt_text_len;i++){printf("%02x", (unsigned char)buf[20+i]);}
								recvlen = sendto(fd, buf, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
								printf("im' node %d  and %d bytes sent\n",router_number, recvlen);
							} 
						}
						else if (stageNo== 7 ){
							// out_portarr[0]=buf[23]; out_portarr[1]=buf[24];
							// outid = (router_number*256)+1;
							// memcpy(out_ID, &outid, 2);
							// in_port = ntohs(remaddr.sin_port);
							// out_port = (out_portarr[0] <<8) | out_portarr[1] ;
							// unsigned char *crypt_text;
							// int crypt_text_len;
							// unsigned char *clear_crypt_text;
							// int clear_crypt_text_len;
							// AES_KEY enc_key;
							// AES_KEY dec_key;
							out_ID[0]= (unsigned char)router_number;
							out_ID[1]= 0x01;
							if(buf[20]==0x65){
								char tmp_ID[2];
								tmp_ID[0]= buf[21];
								tmp_ID[1]= buf[22];
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								if(key_set ==0){
									in_port = ntohs(remaddr.sin_port);
									for(int i = 0; i<recvlen-23;i++){key[i]=buf[23+i];}
									fprintf(fr_log,"fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									key_set=1;
								}
								else{
									char *fwd_key = buf+23;
									buf[21]= out_ID[0];
									buf[22]= out_ID[1];
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_key, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",router_number,tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									remaddr.sin_port = htons(out_port);
									printf("sending to %d the following: ", out_port);
									for(int i = 0; i<(3+(clear_crypt_text_len));i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
							}
							else if(buf[20]==0x62){
								//printf("hello form %d\n",router_number);
								if (in_ID[0]==0xff && in_ID[1]==0xff){
									in_ID[0]= buf[21];
									in_ID[1]= buf[22];
									char *in_port_ptr = buf + 23;
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)in_port_ptr, 16, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									out_port = atoi((char*)clear_crypt_text);
									//printf("port after dec: %s\n",clear_crypt_text );
									fprintf(fr_log,"new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port); fflush(fr_log);
									printf("Node %d: new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									buf[20]=0x63;
									sendto(fd, buf, 23, 0, (struct sockaddr *)&remaddr, slen);
								}
								else{
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									printf("Node %d: forwarding extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									fprintf(fr_log,"forwarding extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID[0],in_ID[1],out_ID[0],out_ID[1],out_port);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									remaddr.sin_port = htons(out_port);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x63){
								buf[21]= in_ID[0];
								buf[22]= in_ID[1];
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n"); 
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								fprintf(fr_log,"forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1],in_port);
								fflush(fr_log);
								printf("forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1],in_port);
								remaddr.sin_port = htons(in_port);
								sendto(fd, buf, 25, 0, (struct sockaddr *)&remaddr, slen);
							}
							else if(buf[20]==0x61){
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								char *packet_content = buf+23;
								// printf("%02x\n",packet_content[0]);
								struct iphdr *packet_iph = (struct iphdr*)packet_content;
								memset(&source, 0, sizeof(source));
								source.sin_addr.s_addr = packet_iph->saddr;
								memset(&source_orgin, 0, sizeof(source_orgin));
								source_orgin.sin_addr.s_addr = packet_iph->saddr;
								memset(&dest, 0, sizeof(dest));
								dest.sin_addr.s_addr = packet_iph->daddr;
								fflush(fr_log);
								
								if(out_port == 65535){
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									if(clear_packet_iph->protocol == 6){
										//printf("HIIIIIIIIIIIIIIIIII\n");
										struct tcphdr *tcph = (struct tcphdr *) (clear_crypt_text + sizeof (struct ip));
										struct pseudo_header psh;
										//printf("check sum= %x\n", ntohs(tcph->check));
										tcph->check = 0;
										memset(&source, 0, sizeof(source));
										source.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&source_orgin, 0, sizeof(source_orgin));
										source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&dest, 0, sizeof(dest));
										dest.sin_addr.s_addr = clear_packet_iph->daddr;
										clear_packet_iph->saddr = inet_addr(router_ip);
										
										//Now the TCP checksum
										psh.source_address = inet_addr( router_ip );
										psh.dest_address = dest.sin_addr.s_addr;
										psh.placeholder = 0;
										psh.protocol = IPPROTO_TCP;
										psh.tcp_length = htons(clear_crypt_text_len-20);
										
										int psize = sizeof(struct pseudo_header) + clear_crypt_text_len-20;
										char *pseudogram = malloc(psize);
										memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
										memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , clear_crypt_text_len-20);
										printf("method1: %x method2: %x \n",in_cksum ((u16 *) pseudogram, psize),csum( (unsigned short*) pseudogram , psize));
										//tcph->check = csum( (unsigned short*) pseudogram , psize);
										tcph->check = in_cksum ((u16 *) pseudogram, psize);
										//printf("check sum= %x TCPlength=%d\n", ntohs(tcph->check), clear_crypt_text_len-20);
										for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
										//printf("outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
										//printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
										fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
										// fprintf(fp,"TCP from tunnel, src IP/port: %s:%u, ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
										// fprintf(fp,"dst IP/port: %s:%u, seqno: %u, ackno: %u\n",inet_ntoa(dest.sin_addr),ntohs(tcph->dest), ntohl(tcph->seq),ntohl(tcph->ack_seq));
										packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
										// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
										// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
										servaddr.sin_family = AF_INET;
										servaddr.sin_port = htons(80);
										char* addresss = inet_ntoa(dest.sin_addr);
										if (inet_aton(addresss, &servaddr.sin_addr)==0) {
											fprintf(stderr, "inet_aton() failed\n");
											exit(1);
										}
										//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
										memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
										if ((sent_size = sendto(webfd1, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
										{
											perror("send failed\n");
											break;
										}
									}
									else if(clear_packet_iph->protocol == 1){
										//printf("HIIIIIIIIIIIIIIIIII\n");
										memset(&source, 0, sizeof(source));
										source.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&source_orgin, 0, sizeof(source_orgin));
										source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&dest, 0, sizeof(dest));
										dest.sin_addr.s_addr = clear_packet_iph->daddr;
										clear_packet_iph->saddr = inet_addr(router_ip);
										for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
										printf("outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr));
										printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										fprintf(fr_log,"outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr));
										fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
										// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
										// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
										servaddr.sin_family = AF_INET;
										char* addresss = inet_ntoa(dest.sin_addr);
										if (inet_aton(addresss, &servaddr.sin_addr)==0) {
											fprintf(stderr, "inet_aton() failed\n");
											exit(1);
										}
										//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
										memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
										if ((sent_size = sendto(webfd, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
										{
											perror("send failed\n");
											break;
										}
									}
								}
								else {
									// memset(&save_src, 0, sizeof(save_src));
									// save_src.sin_addr.s_addr = packet_iph->saddr;
									// memset(&save_dst, 0, sizeof(save_dst));
									// save_dst.sin_addr.s_addr = packet_iph->daddr;
									//packet_iph->saddr = inet_addr(router_ip);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									// struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									// clear_packet_iph->saddr = inet_addr(router_ip);
									fprintf(fr_log,"relay encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x, incoming src:%s, ",in_ID[0],in_ID[1],out_ID[0],out_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fflush(fr_log);
									remaddr.sin_port = htons(out_port);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x64){
								char *fwd_pkt = buf+23;
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); 
								fprintf(fr_log,"relay reply encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1]);
								fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								printf("relay reply encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID[0],in_ID[1]);
								buf[21] = in_ID[0];
								buf[22] = in_ID[1];
								//for(int i=0; i<recvlen-20;i++){printf("%02x", (unsigned char)buf[20+i]);}
								remaddr.sin_port = htons(in_port);
								printf("i'm node %d sending back to port %d\n", router_number, in_port);
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)fwd_pkt, recvlen-23, &crypt_text, &crypt_text_len, &enc_key);
								for(int i=0; i<crypt_text_len;i++){buf[23+i]=crypt_text[i];}
								//or(int i=0; i<crypt_text_len;i++){printf("%02x", (unsigned char)buf[20+i]);}
								recvlen = sendto(fd, buf, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
								printf("im' node %d  and %d bytes sent\n",router_number, recvlen);
							} 
						}
						else if (stageNo== 8 ){
							// out_portarr[0]=buf[23]; out_portarr[1]=buf[24];
							// outid = (router_number*256)+1;
							// memcpy(out_ID, &outid, 2);
							// in_port = ntohs(remaddr.sin_port);
							// out_port = (out_portarr[0] <<8) | out_portarr[1] ;
							// unsigned char *crypt_text;
							// int crypt_text_len;
							// unsigned char *clear_crypt_text;
							// int clear_crypt_text_len;
							// AES_KEY enc_key;
							// AES_KEY dec_key;
							int setup_port;
							out_ID[0]= (unsigned char)router_number;
							out_ID[1]=  buf[22];
							int cir_num = (int)buf[22];
							if(buf[20]==0x65){
								char tmp_ID[2];
								tmp_ID[0]= buf[21];
								tmp_ID[1]= buf[22];
								//out_ID[1]= buf[22];
								if (tmp_ID[0]==0x00) fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",port,(recvlen-20));
								else fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								if(key_set8[cir_num] ==0){
									if (tmp_ID[0]==0x00){in_port8[cir_num] = port; setup_port = ntohs(remaddr.sin_port); }
									else in_port8[cir_num] = ntohs(remaddr.sin_port);
									for(int i = 0; i<recvlen-23;i++){key[i]=buf[23+i];}
									fprintf(fr_log,"fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									key_set8[cir_num]=1;
								}
								else{
									char *fwd_key = buf+23;
									buf[21]= out_ID[0];
									buf[22]= out_ID[1];
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_key, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",router_number,tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									remaddr.sin_port = htons(out_port8[cir_num]);
									printf("sending to %d the following: ", out_port8[cir_num]);
									for(int i = 0; i<(3+(clear_crypt_text_len));i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
							}
							else if(buf[20]==0x62){
								//printf("hello form %d\n",router_number);
								if (in_ID8[cir_num][0]==0xff && in_ID8[cir_num][1]==0xff){
									in_ID8[cir_num][0]= buf[21];
									in_ID8[cir_num][1]= buf[22];
									char *in_port_ptr = buf + 23;
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)in_port_ptr, 16, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									out_port8[cir_num] = atoi((char*)clear_crypt_text);
									//printf("port after dec: %s\n",clear_crypt_text );
									fprintf(fr_log,"new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]); fflush(fr_log);
									printf("Node %d: new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]);
									buf[20]=0x63;
									sendto(fd, buf, 23, 0, (struct sockaddr *)&remaddr, slen);
								}
								else{
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									printf("Node %d: forwarding extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]);
									fprintf(fr_log,"forwarding extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									remaddr.sin_port = htons(out_port8[cir_num]);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x63){
								buf[21]= in_ID8[cir_num][0];
								buf[22]= in_ID8[cir_num][1];
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n"); 
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								fprintf(fr_log,"forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1],in_port8[cir_num]);
								fflush(fr_log);
								printf("forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1],in_port8[cir_num]);
								if (in_ID8[cir_num][0]==0x00) remaddr.sin_port = htons(setup_port);
								else remaddr.sin_port = htons(in_port8[cir_num]);
								sendto(fd, buf, 25, 0, (struct sockaddr *)&remaddr, slen);
							}
							else if(buf[20]==0x61){
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								char *packet_content = buf+23;
								// printf("%02x\n",packet_content[0]);
								struct iphdr *packet_iph = (struct iphdr*)packet_content;
								memset(&source, 0, sizeof(source));
								source.sin_addr.s_addr = packet_iph->saddr;
								memset(&source_orgin, 0, sizeof(source_orgin));
								source_orgin.sin_addr.s_addr = packet_iph->saddr;
								memset(&dest, 0, sizeof(dest));
								dest.sin_addr.s_addr = packet_iph->daddr;
								fflush(fr_log);
								
								if(out_port8[cir_num] == 65535){
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									if(clear_packet_iph->protocol == 6){
										//printf("HIIIIIIIIIIIIIIIIII\n");
										struct tcphdr *tcph = (struct tcphdr *) (clear_crypt_text + sizeof (struct ip));
										struct pseudo_header psh;
										//printf("check sum= %x\n", ntohs(tcph->check));
										tcph->check = 0;
										memset(&source, 0, sizeof(source));
										source.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&source_orgin, 0, sizeof(source_orgin));
										source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&dest, 0, sizeof(dest));
										dest.sin_addr.s_addr = clear_packet_iph->daddr;
										clear_packet_iph->saddr = inet_addr(router_ip);
										
										//Now the TCP checksum
										psh.source_address = inet_addr( router_ip );
										psh.dest_address = dest.sin_addr.s_addr;
										psh.placeholder = 0;
										psh.protocol = IPPROTO_TCP;
										psh.tcp_length = htons(clear_crypt_text_len-20);
										
										int psize = sizeof(struct pseudo_header) + clear_crypt_text_len-20;
										char *pseudogram = malloc(psize);
										memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
										memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , clear_crypt_text_len-20);
										printf("method1: %x method2: %x \n",in_cksum ((u16 *) pseudogram, psize),csum( (unsigned short*) pseudogram , psize));
										//tcph->check = csum( (unsigned short*) pseudogram , psize);
										tcph->check = in_cksum ((u16 *) pseudogram, psize);
										//printf("check sum= %x TCPlength=%d\n", ntohs(tcph->check), clear_crypt_text_len-20);
										for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
										//printf("outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
										//printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
										fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
										// fprintf(fp,"TCP from tunnel, src IP/port: %s:%u, ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
										// fprintf(fp,"dst IP/port: %s:%u, seqno: %u, ackno: %u\n",inet_ntoa(dest.sin_addr),ntohs(tcph->dest), ntohl(tcph->seq),ntohl(tcph->ack_seq));
										packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
										// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
										// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
										servaddr.sin_family = AF_INET;
										servaddr.sin_port = htons(80);
										char* addresss = inet_ntoa(dest.sin_addr);
										if (inet_aton(addresss, &servaddr.sin_addr)==0) {
											fprintf(stderr, "inet_aton() failed\n");
											exit(1);
										}
										//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
										memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
										cir_num_web = cir_num;
										if ((sent_size = sendto(webfd1, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
										{
											perror("send failed\n");
											break;
										}
									}
									else if(clear_packet_iph->protocol == 1){
										//printf("HIIIIIIIIIIIIIIIIII\n");
										memset(&source, 0, sizeof(source));
										source.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&source_orgin, 0, sizeof(source_orgin));
										source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&dest, 0, sizeof(dest));
										dest.sin_addr.s_addr = clear_packet_iph->daddr;
										clear_packet_iph->saddr = inet_addr(router_ip);
										for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
										printf("outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr));
										printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										fprintf(fr_log,"outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr));
										fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
										// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
										// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
										servaddr.sin_family = AF_INET;
										char* addresss = inet_ntoa(dest.sin_addr);
										if (inet_aton(addresss, &servaddr.sin_addr)==0) {
											fprintf(stderr, "inet_aton() failed\n");
											exit(1);
										}
										//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
										memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
										cir_num_web = cir_num;
										if ((sent_size = sendto(webfd, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
										{
											perror("send failed\n");
											break;
										}
									}
								}
								else {
									// memset(&save_src, 0, sizeof(save_src));
									// save_src.sin_addr.s_addr = packet_iph->saddr;
									// memset(&save_dst, 0, sizeof(save_dst));
									// save_dst.sin_addr.s_addr = packet_iph->daddr;
									//packet_iph->saddr = inet_addr(router_ip);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									// struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									// clear_packet_iph->saddr = inet_addr(router_ip);
									fprintf(fr_log,"relay encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fflush(fr_log);
									remaddr.sin_port = htons(out_port8[cir_num]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x64){
								char *fwd_pkt = buf+23;
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); 
								fprintf(fr_log,"relay reply encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1]);
								fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								printf("relay reply encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1]);
								buf[21] = in_ID8[cir_num][0];
								buf[22] = in_ID8[cir_num][1];
								//for(int i=0; i<recvlen-20;i++){printf("%02x", (unsigned char)buf[20+i]);}
								remaddr.sin_port = htons(in_port8[cir_num]);
								printf("i'm node %d sending back to port %d\n", router_number, in_port8[cir_num]);
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)fwd_pkt, recvlen-23, &crypt_text, &crypt_text_len, &enc_key);
								for(int i=0; i<crypt_text_len;i++){buf[23+i]=crypt_text[i];}
								//or(int i=0; i<crypt_text_len;i++){printf("%02x", (unsigned char)buf[20+i]);}
								recvlen = sendto(fd, buf, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
								printf("im' node %d  and %d bytes sent\n",router_number, recvlen);
							} 
						}
						else if (stageNo== 9 ){
							// out_portarr[0]=buf[23]; out_portarr[1]=buf[24];
							// outid = (router_number*256)+1;
							// memcpy(out_ID, &outid, 2);
							// in_port = ntohs(remaddr.sin_port);
							// out_port = (out_portarr[0] <<8) | out_portarr[1] ;
							// unsigned char *crypt_text;
							// int crypt_text_len;
							// unsigned char *clear_crypt_text;
							// int clear_crypt_text_len;
							// AES_KEY enc_key;
							// AES_KEY dec_key;
							int setup_port;
							out_ID[0]= (unsigned char)router_number;
							out_ID[1]=  buf[22];
							int cir_num = (int)buf[22];
							//fprintf(fr_log,"\n %02x \n", (unsigned char)buf[20]);
							if(buf[20]==0x65){
								char tmp_ID[2];
								tmp_ID[0]= buf[21];
								tmp_ID[1]= buf[22];
								//out_ID[1]= buf[22];
								if (tmp_ID[0]==0x00) fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",port,(recvlen-20));
								else fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								if(key_set8[cir_num] ==0){
									if (tmp_ID[0]==0x00){in_port8[cir_num] = port; setup_port = ntohs(remaddr.sin_port); }
									else in_port8[cir_num] = ntohs(remaddr.sin_port);
									for(int i = 0; i<recvlen-23;i++){key[i]=buf[23+i];}
									fprintf(fr_log,"fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("fake-diffie-hellman, new circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									key_set8[cir_num]=1;
								}
								else{
									char *fwd_key = buf+23;
									buf[21]= out_ID[0];
									buf[22]= out_ID[1];
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_key, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									for(int i = 0; i<recvlen-23;i++){fprintf(fr_log,"%02x",(unsigned char)buf[23+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: fake-diffie-hellman, forwarding,  circuit incoming: 0x%02x%02x, key: 0x",router_number,tmp_ID[0],tmp_ID[1]);
									for(int i = 0; i<recvlen-23;i++){printf("%02x",(unsigned char)buf[23+i]);} printf("\n");
									remaddr.sin_port = htons(out_port8[cir_num]);
									printf("sending to %d the following: ", out_port8[cir_num]);
									for(int i = 0; i<(3+(clear_crypt_text_len));i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
							}
							else if(buf[20]==0x62){
								//printf("hello form %d\n",router_number);
								if (in_ID8[cir_num][0]==0xff && in_ID8[cir_num][1]==0xff){
									in_ID8[cir_num][0]= buf[21];
									in_ID8[cir_num][1]= buf[22];
									char *in_port_ptr = buf + 23;
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)in_port_ptr, 16, &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									out_port8[cir_num] = atoi((char*)clear_crypt_text);
									//printf("port after dec: %s\n",clear_crypt_text );
									fprintf(fr_log,"new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]); fflush(fr_log);
									printf("Node %d: new extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]);
									buf[20]=0x63;
									sendto(fd, buf, 23, 0, (struct sockaddr *)&remaddr, slen);
								}
								else{
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
									printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
									for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
									printf("Node %d: forwarding extend circuit: incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",router_number,in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]);
									fprintf(fr_log,"forwarding extend circuit: incoming: 0x%x%x, outgoing: 0x%x%02x at %d\n",in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],out_port8[cir_num]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									remaddr.sin_port = htons(out_port8[cir_num]);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								
							}
							else if(buf[20]==0x63){
								buf[21]= in_ID8[cir_num][0];
								buf[22]= in_ID8[cir_num][1];
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n"); 
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),3);
								for(int i = 0; i<3;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								fprintf(fr_log,"forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1],in_port8[cir_num]);
								fflush(fr_log);
								printf("forwarding extend-done circuit, incoming: 0x%02x%02x, outgoing: 0x%02x%02x at %d\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1],in_port8[cir_num]);
								if (in_ID8[cir_num][0]==0x00) remaddr.sin_port = htons(setup_port);
								else remaddr.sin_port = htons(in_port8[cir_num]);
								sendto(fd, buf, 25, 0, (struct sockaddr *)&remaddr, slen);
							}
							else if(buf[20]==0x61){
								pktCount[cir_num]++;
								printf("Node %d: pkt from port: %d, length: %d, contents: 0x",router_number,ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								char *packet_content = buf+23;
								// printf("%02x\n",packet_content[0]);
								struct iphdr *packet_iph = (struct iphdr*)packet_content;
								memset(&source, 0, sizeof(source));
								source.sin_addr.s_addr = packet_iph->saddr;
								memset(&source_orgin, 0, sizeof(source_orgin));
								source_orgin.sin_addr.s_addr = packet_iph->saddr;
								memset(&dest, 0, sizeof(dest));
								dest.sin_addr.s_addr = packet_iph->daddr;
								fflush(fr_log);
								
								if(out_port8[cir_num] == 65535){
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									if(clear_packet_iph->protocol == 6){
										//printf("HIIIIIIIIIIIIIIIIII\n");
										struct tcphdr *tcph = (struct tcphdr *) (clear_crypt_text + sizeof (struct ip));
										struct pseudo_header psh;
										//printf("check sum= %x\n", ntohs(tcph->check));
										tcph->check = 0;
										memset(&source, 0, sizeof(source));
										source.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&source_orgin, 0, sizeof(source_orgin));
										source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&dest, 0, sizeof(dest));
										dest.sin_addr.s_addr = clear_packet_iph->daddr;
										clear_packet_iph->saddr = inet_addr(router_ip);
										
										//Now the TCP checksum
										psh.source_address = inet_addr( router_ip );
										psh.dest_address = dest.sin_addr.s_addr;
										psh.placeholder = 0;
										psh.protocol = IPPROTO_TCP;
										psh.tcp_length = htons(clear_crypt_text_len-20);
										
										int psize = sizeof(struct pseudo_header) + clear_crypt_text_len-20;
										char *pseudogram = malloc(psize);
										memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
										memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , clear_crypt_text_len-20);
										printf("method1: %x method2: %x \n",in_cksum ((u16 *) pseudogram, psize),csum( (unsigned short*) pseudogram , psize));
										//tcph->check = csum( (unsigned short*) pseudogram , psize);
										tcph->check = in_cksum ((u16 *) pseudogram, psize);
										//printf("check sum= %x TCPlength=%d\n", ntohs(tcph->check), clear_crypt_text_len-20);
										for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
										//printf("outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
										//printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
										fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
										// fprintf(fp,"TCP from tunnel, src IP/port: %s:%u, ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
										// fprintf(fp,"dst IP/port: %s:%u, seqno: %u, ackno: %u\n",inet_ntoa(dest.sin_addr),ntohs(tcph->dest), ntohl(tcph->seq),ntohl(tcph->ack_seq));
										packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
										// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
										// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
										servaddr.sin_family = AF_INET;
										servaddr.sin_port = htons(80);
										char* addresss = inet_ntoa(dest.sin_addr);
										if (inet_aton(addresss, &servaddr.sin_addr)==0) {
											fprintf(stderr, "inet_aton() failed\n");
											exit(1);
										}
										//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
										memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
										cir_num_web = cir_num;
										if ((sent_size = sendto(webfd1, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
										{
											perror("send failed\n");
											break;
										}
									}
									else if(clear_packet_iph->protocol == 1){
										//printf("HIIIIIIIIIIIIIIIIII\n");
										memset(&source, 0, sizeof(source));
										source.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&source_orgin, 0, sizeof(source_orgin));
										source_orgin.sin_addr.s_addr = clear_packet_iph->saddr;
										memset(&dest, 0, sizeof(dest));
										dest.sin_addr.s_addr = clear_packet_iph->daddr;
										clear_packet_iph->saddr = inet_addr(router_ip);
										for(int i = 0; i<clear_crypt_text_len;i++) {printf("%02x",clear_crypt_text[i]);} printf("\n");
										printf("outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr));
										printf("outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										fprintf(fr_log,"outgoing packet, circuit incoming: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],inet_ntoa(source.sin_addr));
										fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
										packet_iph->check = in_cksum ((u16 *) packet_iph, sizeof (struct iphdr));
										// printf("child preparing to send to server: src: %s, ",inet_ntoa(source.sin_addr));
										// printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(packet_icmph->type));
										servaddr.sin_family = AF_INET;
										char* addresss = inet_ntoa(dest.sin_addr);
										if (inet_aton(addresss, &servaddr.sin_addr)==0) {
											fprintf(stderr, "inet_aton() failed\n");
											exit(1);
										}
										//servaddr.sin_addr.s_addr = inet_ntoa(dest.sin_addr);
										memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
										cir_num_web = cir_num;
										if ((sent_size = sendto(webfd, clear_crypt_text, clear_crypt_text_len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
										{
											perror("send failed\n");
											break;
										}
									}
								}
								else {
									// memset(&save_src, 0, sizeof(save_src));
									// save_src.sin_addr.s_addr = packet_iph->saddr;
									// memset(&save_dst, 0, sizeof(save_dst));
									// save_dst.sin_addr.s_addr = packet_iph->daddr;
									//packet_iph->saddr = inet_addr(router_ip);
									buf[21]= out_ID[0]; 
									buf[22]= out_ID[1]; 
									char *fwd_pkt = buf+23;
									class_AES_set_decrypt_key(key, &enc_key);
									class_AES_decrypt_with_padding((unsigned char*)fwd_pkt, (recvlen-23), &clear_crypt_text, &clear_crypt_text_len, &enc_key);
									// struct iphdr *clear_packet_iph = (struct iphdr*)clear_crypt_text;
									// clear_packet_iph->saddr = inet_addr(router_ip);
									fprintf(fr_log,"relay encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x, incoming src:%s, ",in_ID8[cir_num][0],in_ID8[cir_num][1],out_ID[0],out_ID[1],inet_ntoa(source.sin_addr));
									fprintf(fr_log,"outgoing src: %s, dst: %s\n",router_ip,inet_ntoa(dest.sin_addr));
									fflush(fr_log);
									remaddr.sin_port = htons(out_port8[cir_num]);
									for(int i = 0; i<clear_crypt_text_len;i++){buf[23+i] = clear_crypt_text[i];}
									sendto(fd, buf, (23+(clear_crypt_text_len)), 0, (struct sockaddr *)&remaddr, slen);
								}
								if (in_ID8[cir_num][0] == 0x00 && pktCount[cir_num] > dieAfter && in_ID8[cir_num][1]-1 < hopsNo){
									//pktCount[cir_num] = 0;
									//printf("hops = %d, removed = %d",hopsNo,in_ID8[cir_num][1]);
									cr_cir_num = cir_num;
									if (fork()==0) {alarm(5); forked = 1;}
									// char recovery_pkt[16];
									// recovery_pkt[0]= out_port8[cir_num];
									// for(int i = 1; i<16;i++){recovery_pkt[i]= 0x00;}
									// char *fwd_pkt = recovery_pkt;
									// class_AES_set_encrypt_key(key, &enc_key);
									// class_AES_encrypt_with_padding((unsigned char*)fwd_pkt, 16, &crypt_text, &crypt_text_len, &enc_key);
									// buf[20] = 0x92;
									// buf[21] = in_ID8[cir_num][0];
									// buf[22] = in_ID8[cir_num][1];
									// for(int i=0; i<crypt_text_len;i++){buf[23+i]=crypt_text[i];}
									// remaddr.sin_port = htons(in_port8[cir_num]);
									// recvlen = sendto(fd, buf, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
									// print("sent %d bytes as recovery \n",recvlen );
								}
								
							}
							else if(buf[20]==0x64){
								char *fwd_pkt = buf+23;
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); 
								fprintf(fr_log,"relay reply encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1]);
								fflush(fr_log);
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								printf("relay reply encrypted packet, circuit incoming: 0x%02x%02x, outgoing: 0x%02x%02x\n",out_ID[0],out_ID[1],in_ID8[cir_num][0],in_ID8[cir_num][1]);
								buf[21] = in_ID8[cir_num][0];
								buf[22] = in_ID8[cir_num][1];
								//for(int i=0; i<recvlen-20;i++){printf("%02x", (unsigned char)buf[20+i]);}
								remaddr.sin_port = htons(in_port8[cir_num]);
								printf("i'm node %d sending back to port %d\n", router_number, in_port8[cir_num]);
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)fwd_pkt, recvlen-23, &crypt_text, &crypt_text_len, &enc_key);
								for(int i=0; i<crypt_text_len;i++){buf[23+i]=crypt_text[i];}
								//or(int i=0; i<crypt_text_len;i++){printf("%02x", (unsigned char)buf[20+i]);}
								recvlen = sendto(fd, buf, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
								printf("im' node %d  and %d bytes sent\n",router_number, recvlen);
							} 
							else if((unsigned char)buf[20]==0x91){
								printf("pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){printf("%02x",(unsigned char)buf[20+i]);} printf("\n");
								fprintf(fr_log,"pkt from port: %d, length: %d, contents: 0x",ntohs(remaddr.sin_port),(recvlen-20));
								for(int i = 0; i<recvlen-20;i++){fprintf(fr_log,"%02x",(unsigned char)buf[20+i]);} fprintf(fr_log,"\n"); fflush(fr_log);
								fprintf(fr_log,"router %d killed\n",router_number);
								fflush(fr_log);
								kill(getpid(), SIGKILL);
							} 
						}
					}
				}
				
				else if (FD_ISSET(webfd,&master_set))
				{
					memset((char *) &servaddr, 0, sizeof(servaddr));
					if ((sent_size = recvfrom(webfd, buf, 8192, 0, (struct sockaddr *)&servaddr, &addrlen)) < 1) 
					{
					perror("recv failed\n");
					break;
				}
				else{
					struct iphdr *iph = (struct iphdr*)buf;
					unsigned short iphdrlen = iph->ihl*4;
					struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen);
					memset((char *) &servaddr, 0, sizeof(servaddr));
					memset(&buf1, 0, sizeof(buf1));
					memset(&source, 0, sizeof(source));
					source.sin_addr.s_addr = iph->saddr;
					memset(&dest, 0, sizeof(dest));
					dest.sin_addr.s_addr = iph->daddr;
					
					if(iph->protocol == 1 ){
						if(stageNo == 3 || stageNo == 4){
							
							fprintf(fr_log,"ICMP from raw sock, src: %s, ",inet_ntoa(source.sin_addr));
							fprintf(fr_log,"dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(icmph->type));
							fflush(fr_log);
							iph->daddr = source_orgin.sin_addr.s_addr;
							// iph->frag_off = fragment_off;
							// iph->ttl = ttl_size;
							iph->check = 0;
							iph->check = in_cksum ((u16 *) iph, sizeof (struct iphdr));
							memset(&source, 0, sizeof(source));
							source.sin_addr.s_addr = iph->saddr;
							memset(&dest, 0, sizeof(dest));
							dest.sin_addr.s_addr = iph->daddr;
							printf("child preparing to send to proxy: src: %s, ",inet_ntoa(source.sin_addr));
							printf("dst: %s, type: %d\n",inet_ntoa(dest.sin_addr),(unsigned int)(icmph->type));
							sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&remaddr, slen);
						}
						else if(stageNo == 5){
							printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID[0],in_ID[1]);					
							fprintf(fr_log,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID[0],in_ID[1]);
							fflush(fr_log);
							//printf("\n");
							struct iphdr *iph = (struct iphdr*)buf1;
							unsigned short iphdrlen = 20;
							remaddr.sin_family = AF_INET;
							remaddr.sin_port = htons(in_port);
							char *server = "127.0.0.1";
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							buf1[iphdrlen] = 0x54;
							buf1[iphdrlen+1] = in_ID[0];
							buf1[iphdrlen+2] = in_ID[1];
							for(int i=0; i<recvlen;i++){buf1[iphdrlen+3+i]=buf[i];}
							sendto(fd, buf1, (recvlen), 0, (struct sockaddr *)&remaddr, slen);
							
						} 
						else if(stageNo == 6 || stageNo == 7){
							printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID[0],in_ID[1]);					
							fprintf(fr_log,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID[0],in_ID[1]);
							fflush(fr_log);
							struct iphdr *iph = (struct iphdr*)buf1;
							unsigned short iphdrlen = 20;
							remaddr.sin_family = AF_INET;
							remaddr.sin_port = htons(in_port);
							char *server = "127.0.0.1";
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							buf1[iphdrlen] = 0x64;
							buf1[iphdrlen+1] = in_ID[0];
							buf1[iphdrlen+2] = in_ID[1];
							class_AES_set_encrypt_key(key, &enc_key);
							class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
							printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
							for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
							sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
							
							
						}
						else if(stageNo == 8){
							printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);					
							fprintf(fr_log,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);
							fflush(fr_log);
							struct iphdr *iph = (struct iphdr*)buf1;
							unsigned short iphdrlen = 20;
							remaddr.sin_family = AF_INET;
							remaddr.sin_port = htons(in_port8[cir_num_web]);
							char *server = "127.0.0.1";
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							buf1[iphdrlen] = 0x64;
							buf1[iphdrlen+1] = in_ID8[cir_num_web][0];
							buf1[iphdrlen+2] = in_ID8[cir_num_web][1];
							class_AES_set_encrypt_key(key, &enc_key);
							class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
							printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
							for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
							sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
							
							
						} 
						else if(stageNo == 9){
							printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);					
							fprintf(fr_log,"incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);
							fflush(fr_log);
							struct iphdr *iph = (struct iphdr*)buf1;
							unsigned short iphdrlen = 20;
							remaddr.sin_family = AF_INET;
							remaddr.sin_port = htons(in_port8[cir_num_web]);
							char *server = "127.0.0.1";
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							buf1[iphdrlen] = 0x64;
							buf1[iphdrlen+1] = in_ID8[cir_num_web][0];
							buf1[iphdrlen+2] = in_ID8[cir_num_web][1];
							class_AES_set_encrypt_key(key, &enc_key);
							class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
							printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
							for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
							sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen);
							
							
						}
						/* else if(stageNo == 7){
							struct tcphdr *tcph = (struct tcphdr *) (buf + sizeof (struct ip));
							printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID[0],in_ID[1]);					
							fprintf(fr_log,"incoming TCP packet, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),ntohs(tcph->source),router_ip,ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq),in_ID[0],in_ID[1]);
							//fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
							//fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
							fflush(fr_log);
							struct iphdr *iph = (struct iphdr*)buf1;
							unsigned short iphdrlen = 20;
							remaddr.sin_family = AF_INET;
							remaddr.sin_port = htons(in_port);
							char *server = "127.0.0.1";
							iph->saddr = inet_addr(server);
							iph->daddr = inet_addr(server);
							iph->protocol = 253;
							buf1[iphdrlen] = 0x64;
							buf1[iphdrlen+1] = in_ID[0];
							buf1[iphdrlen+2] = in_ID[1];
							class_AES_set_encrypt_key(key, &enc_key);
							class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
							printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
							for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
							sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen); 
							// printf("hi mom \n");
							
							
						} */
					}
					// else{
					
					// }
				}
				}
				else if (FD_ISSET(webfd1,&master_set))
				{
					memset((char *) &servaddr, 0, sizeof(servaddr));
					if ((sent_size = recvfrom(webfd1, buf, 8192, 0, (struct sockaddr *)&servaddr, &addrlen)) < 1) 
					{
						perror("recv failed\n");
						break;
					}
					else{
						struct iphdr *iph = (struct iphdr*)buf;
						// unsigned short iphdrlen = iph->ihl*4;
						// struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen);
						memset((char *) &servaddr, 0, sizeof(servaddr));
						memset(&buf1, 0, sizeof(buf1));
						memset(&source, 0, sizeof(source));
						source.sin_addr.s_addr = iph->saddr;
						memset(&dest, 0, sizeof(dest));
						dest.sin_addr.s_addr = iph->daddr;
						
						if(iph->protocol == 6){
							if(stageNo == 7){
								struct tcphdr *tcph = (struct tcphdr *) (buf + sizeof (struct ip));
								printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID[0],in_ID[1]);					
								fprintf(fr_log,"incoming TCP packet, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),ntohs(tcph->source),router_ip,ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq),in_ID[0],in_ID[1]);
								//fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
								//fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
								fflush(fr_log);
								struct iphdr *iph = (struct iphdr*)buf1;
								unsigned short iphdrlen = 20;
								remaddr.sin_family = AF_INET;
								remaddr.sin_port = htons(in_port);
								char *server = "127.0.0.1";
								iph->saddr = inet_addr(server);
								iph->daddr = inet_addr(server);
								iph->protocol = 253;
								buf1[iphdrlen] = 0x64;
								buf1[iphdrlen+1] = in_ID[0];
								buf1[iphdrlen+2] = in_ID[1];
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
								printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
								for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
								sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen); 
								// printf("hi mom \n");
								
								
							}
							else if(stageNo == 8){
								struct tcphdr *tcph = (struct tcphdr *) (buf + sizeof (struct ip));
								printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);					
								fprintf(fr_log,"incoming TCP packet, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),ntohs(tcph->source),router_ip,ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq),in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);
								//fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
								//fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
								fflush(fr_log);
								struct iphdr *iph = (struct iphdr*)buf1;
								unsigned short iphdrlen = 20;
								remaddr.sin_family = AF_INET;
								remaddr.sin_port = htons(in_port8[cir_num_web]);
								char *server = "127.0.0.1";
								iph->saddr = inet_addr(server);
								iph->daddr = inet_addr(server);
								iph->protocol = 253;
								buf1[iphdrlen] = 0x64;
								buf1[iphdrlen+1] = in_ID8[cir_num_web][0];
								buf1[iphdrlen+2] = in_ID8[cir_num_web][1];
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
								printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
								for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
								sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen); 
								// printf("hi mom \n");
								
								
							}
							else if(stageNo == 9){
								struct tcphdr *tcph = (struct tcphdr *) (buf + sizeof (struct ip));
								printf("incoming packet, src: %s, dst: %s, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),router_ip,in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);					
								fprintf(fr_log,"incoming TCP packet, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u, outgoing circuit: 0x%02x%02x\n",inet_ntoa(source.sin_addr),ntohs(tcph->source),router_ip,ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq),in_ID8[cir_num_web][0],in_ID8[cir_num_web][1]);
								//fprintf(fr_log,"outgoing TCP packet, circuit incoming: 0x%02x%02x, incoming src IP/port: %s:%u, ",in_ID[0],in_ID[1],inet_ntoa(source.sin_addr),ntohs(tcph->source));
								//fprintf(fr_log,"outgoing  outgoing src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",router_ip,ntohs(tcph->source), inet_ntoa(dest.sin_addr),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq));
								fflush(fr_log);
								struct iphdr *iph = (struct iphdr*)buf1;
								unsigned short iphdrlen = 20;
								remaddr.sin_family = AF_INET;
								remaddr.sin_port = htons(in_port8[cir_num_web]);
								char *server = "127.0.0.1";
								iph->saddr = inet_addr(server);
								iph->daddr = inet_addr(server);
								iph->protocol = 253;
								buf1[iphdrlen] = 0x64;
								buf1[iphdrlen+1] = in_ID8[cir_num_web][0];
								buf1[iphdrlen+2] = in_ID8[cir_num_web][1];
								class_AES_set_encrypt_key(key, &enc_key);
								class_AES_encrypt_with_padding((unsigned char*)buf, sent_size, &crypt_text, &crypt_text_len, &enc_key);
								printf("recived %d bytes and it became %d bytes after encryption\n", sent_size, crypt_text_len);
								for(int i=0; i<crypt_text_len;i++){buf1[iphdrlen+3+i]=crypt_text[i];}
								sendto(fd, buf1, (23+crypt_text_len), 0, (struct sockaddr *)&remaddr, slen); 
								// printf("hi mom \n");
								
								
							}
						}
						// else{
						
						// }
					}
				}
			}
		}
	}
	
	
	close(fd);
	return 0;
}

int main(int argc, char **argv){
	
	if (argc != 1){ //command line input detected
		char *ethernet_address[]= {"192.168.201.2","192.168.202.2","192.168.203.2","192.168.204.2","192.168.205.2","192.168.206.2"};
		int srvfd = init_soc(argv);
		signal(SIGALRM, crashTimer);
		printf("port=%d\n", ntohs(proxy_addr.sin_port));
		//FILE *fp_log = fopen("stage1.proxy.out", "wb+");
		FILE * f;
		f=fopen(argv[1],"rt");
		fseek(f, 0, SEEK_END);
		int size = ftell(f);
		fseek(f, 0, SEEK_SET);
		char *line = (char*)malloc(size), *word;
		while(fgets (line, size, f)!=NULL){
			// printf("%s",line);
			if (line[0] != '#'){
				word = strtok(line," ");
				// printf("%s\n", word);
				if (!strcmp(word, "stage")){word = strtok(NULL," "); stageNo=atoi(word);}
				else if (!strcmp(word, "num_routers")) {word=strtok(NULL," "); routerNo=atoi(word);}
				else if (!strcmp(word, "minitor_hops")) {word=strtok(NULL," "); hopsNo=atoi(word);}
				else if (!strcmp(word, "die_after")) {word=strtok(NULL," "); dieAfter=atoi(word);}
			}	
		}
		printf("stage=%d, router#=%d hops#=%d\n", stageNo,routerNo,hopsNo);
		if (fork()==0){
			//printf("Hello from router! pid=%d\n", getpid());
			// init_router();
			int i,pid;
			for(i = 0; i < routerNo; i++) {
				pid = fork();
				if(pid < 0) {
					printf("Error");
					exit(1);
					} else if (pid == 0) {
					
					printf("Child (%d): %d\n", i + 1, getpid());
					init_router((i+1),ethernet_address[i]);
					exit(0); 
					} else  {
					usleep(10000);
					// wait(NULL);
				}
			}
		}
		
		
		// parent process because return value non-zero.
		else{	
			char filename[20];
			unsigned char key[16];
			snprintf(filename, sizeof(filename), "stage%d.proxy.out", stageNo);
			// printf("%s",filename);
			FILE *fp_log = fopen(filename, "wb+");
			// printf("Hello from proxy! pid=%d\n",getpid()); 
			fprintf(fp_log,"proxy port: %d\n",port);
			fflush(fp_log);
			struct sockaddr_in remaddr;
			socklen_t addrlen = sizeof(remaddr);
			unsigned char buf[2048];
			unsigned int recvlen,re_port[routerNo];
			for (int i = 0; i < routerNo; i++){
				recvlen = recvfrom(srvfd, buf, 2048, 0, (struct sockaddr *)&remaddr, &addrlen);
				if (recvlen > 0) {
					buf[recvlen] = 0;
					printf("received message: \"%s\" (%d bytes) from port %d\n", buf, recvlen, ntohs(remaddr.sin_port));
					if(stageNo > 4){fprintf(fp_log,"router: %d, pid: %s, port: %d, IP: %s\n",i+1,buf,ntohs(remaddr.sin_port), ethernet_address[i]);}
					else{fprintf(fp_log,"router: %d, pid: %s, port: %d\n",i+1,buf,ntohs(remaddr.sin_port));}
					fflush(fp_log);
					re_port[i]= ntohs(remaddr.sin_port);	
				}
			}
			if (stageNo == 5 || stageNo == 6 || stageNo == 7 || stageNo == 8 || stageNo == 9 ){
				srand (time(NULL));
				hops_list= malloc(hopsNo);
				int Duplicate;
				for (int I = 0; I < hopsNo; I++)
				{
					do
					{
						Duplicate = 0;
						hops_list[I] = (rand()%routerNo); 
						for (int J = I - 1; J > -1; J--) // works backwards from the recently generated element to element 0
						if (hops_list[I] == hops_list[J]) //checks if number is already used
						Duplicate = 1; //sets Duplicate to true to indicate there is a repeat
					} while (Duplicate); //loops until a new, distinct number is generated
					printf("hop: %d, router: %d\n",(I+1),(hops_list[I]+1));
					if (stageNo == 5){
						fprintf(fp_log,"hop: %d, router: %d\n",(I+1),(hops_list[I]+1));
						fflush(fp_log);
					}
				}
				for (int i = 0; i < sizeof(key); i++) {
					key[i] = rand() % 256;
				}
				printf("key is: ");
				for (int i = 0; i < sizeof(key); i++) {printf("%02x",key[i]);} printf("\n");
				if (stageNo == 5 || stageNo == 6 || stageNo == 7){
					init_circuit(srvfd,fp_log,re_port,key,1);
				}
			}
			if (stageNo > 1){tunnel_reader(srvfd,fp_log,re_port,key);}
			// close(fp_log);
			close(srvfd);
		}
		
	}
}	
