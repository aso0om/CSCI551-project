////////////////////////////////////////////////////////////////////////////////////
///////// main.h is used for linking the c files.
///////// 
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
#include <openssl/aes.h>
#include <limits.h>
#include <assert.h>

struct entry_s {
	char *key;
	char *value;
	struct entry_s *next;
};

typedef struct entry_s entry_t;

struct hashtable_s {
	int size;
	struct entry_s **table;	
};

typedef struct hashtable_s hashtable_t;

int init_router(int router_number, char* router_ip);
int tunnel_reader(int srv_fd, FILE *fp, unsigned int* rport, unsigned char *key);
int tun_alloc(char *dev, int flags);
int init_circuit(int srv_fd, FILE *fp, unsigned int *rport, unsigned char *key, int circuitNo);
void class_AES_set_encrypt_key(unsigned char *key_text, AES_KEY *enc_key);
void class_AES_set_decrypt_key(unsigned char *key_text, AES_KEY *dec_key);
void class_AES_encrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *enc_key);
void class_AES_decrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *dec_key);
hashtable_t *ht_create( int size );
int ht_hash( hashtable_t *hashtable, char *key );
entry_t *ht_newpair( char *key, char *value );
void ht_set( hashtable_t *hashtable, char *key, char *value );
char *ht_get( hashtable_t *hashtable, char *key );

