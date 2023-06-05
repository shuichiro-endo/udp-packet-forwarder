/*
 * Title:  udp packet forwarder server (Linux)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "server.h"
#include "serverkey.h"

#define BUFFER_SIZE 65507	// 65535 bytes - ipv4 header(20 bytes) - udp header(8 bytes)


char *local_server_ip = NULL;		// tcp
char *local_server_port = NULL;		// tcp
char *client_ip = NULL;			// tcp
char *client_port = NULL;		// tcp
char *bind_ip = NULL;			// udp
char *bind_port = NULL;			// udp
char *target_ip = NULL;			// udp
char *target_port = NULL;		// udp
int reverse_flag = 0;
int tls_flag = 0;

char cipher_suite_tls1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
char cipher_suite_tls1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3


int forwarder(int client_sock, int target_sock, struct sockaddr *target_addr, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	long t = 0;
	socklen_t target_addr_length = 0;
	struct sockaddr *target_addr2 = NULL;
	socklen_t target_addr2_length = 0;
	unsigned char *buffer = calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	
	if(target_addr->sa_family == AF_INET){	// ipv4
		target_addr_length = sizeof(struct sockaddr_in);
		target_addr2 = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
		target_addr2_length = sizeof(struct sockaddr_in);
	}else{	// ipv6
		target_addr_length = sizeof(struct sockaddr_in6);
		target_addr2 = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
		target_addr2_length = sizeof(struct sockaddr_in6);
	}
	
	while(1){
		bzero(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			if((rec = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(target_sock, buffer+send_length, len, 0, target_addr, target_addr_length);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							free(target_addr2);
							return -1;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
		
		bzero(buffer, BUFFER_SIZE+1);
		
		if(FD_ISSET(target_sock, &readfds)){
			if((rec = recvfrom(target_sock, buffer, BUFFER_SIZE, 0, target_addr2, &target_addr2_length)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, buffer+send_length, len, 0);
				
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							free(target_addr2);
							return -1;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
	}
	
	free(buffer);
	free(target_addr2);
	return 0;
}


int forwarder_tls(int client_sock, SSL *local_server_ssl, int target_sock, struct sockaddr *target_addr, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	long t = 0;
	socklen_t target_addr_length = 0;
	struct sockaddr *target_addr2 = NULL;
	socklen_t target_addr2_length = 0;
	unsigned char *buffer = calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int err = 0;
	
	if(target_addr->sa_family == AF_INET){	// ipv4
		target_addr_length = sizeof(struct sockaddr_in);
		target_addr2 = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
		target_addr2_length = sizeof(struct sockaddr_in);
	}else{	// ipv6
		target_addr_length = sizeof(struct sockaddr_in6);
		target_addr2 = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
		target_addr2_length = sizeof(struct sockaddr_in6);
	}
	
	while(1){
		bzero(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			rec = SSL_read(local_server_ssl, buffer, BUFFER_SIZE);
			err = SSL_get_error(local_server_ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(target_sock, buffer+send_length, len, 0, target_addr, target_addr_length);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							free(target_addr2);
							return -2;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				free(buffer);
				free(target_addr2);
				return -2;
			}
		}
		
		bzero(buffer, BUFFER_SIZE+1);
		
		if(FD_ISSET(target_sock, &readfds)){
			if((rec = recvfrom(target_sock, buffer, BUFFER_SIZE, 0, target_addr2, &target_addr2_length)) > 0){
				while(1){
					sen = SSL_write(local_server_ssl, buffer, rec);
					err = SSL_get_error(local_server_ssl, sen);
					
					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
						continue;
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
						continue;
					}else{
#ifdef _DEBUG
						printf("[E] SSL_write error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						free(buffer);
						free(target_addr2);
						return -2;
					}
				}
			}else{
				break;
			}
		}
	}
	
	free(buffer);
	free(target_addr2);
	return 0;
}


void fini_ssl(struct ssl_param *param)
{
	if(param->local_server_ssl != NULL){
		SSL_shutdown(param->local_server_ssl);
		SSL_free(param->local_server_ssl);
	}
	if(param->local_server_ctx != NULL){
		SSL_CTX_free(param->local_server_ctx);
	}
	
	return;
}


char *get_ipv6_addr_string(const char *addr)
{
	char *percent = NULL;
	char *addr2 = calloc(INET6_ADDRSTRLEN+1, sizeof(char));
	unsigned int length = strlen(addr);
	
	percent = strstr(addr, "%");	// separator
	if(percent != NULL){
		memcpy(addr2, addr, percent-addr);
	}else{
		if(length <= INET6_ADDRSTRLEN){
			memcpy(addr2, addr, length);
		}else{
			memcpy(addr2, addr, INET6_ADDRSTRLEN);
		}
	}
	
#ifdef _DEBUG
//	printf("[I] ipv6 address:%s\n", addr2);
#endif
	
	return addr2;
}


char *get_ipv6_interface_name(const char *addr)
{
	char *percent = NULL;
	char *interface_name = calloc(IFNAMSIZ+1, sizeof(char));
	
	percent = strstr(addr, "%");	// separator
	if(percent != NULL){
		memcpy(interface_name, percent+1, strlen(addr)-(percent-addr));
#ifdef _DEBUG
//		printf("[I] interface name:%s\n", interface_name);
#endif
		return interface_name;
	}
	
	free(interface_name);
	return NULL;
}


unsigned int get_ipv6_scope_id(const char *addr)
{
	char *interface_name = NULL;
	unsigned int scope_id = 0;
	
	interface_name = get_ipv6_interface_name(addr);
	if(interface_name != NULL){
		scope_id = if_nametoindex((const char *)interface_name);
#ifdef _DEBUG
//		printf("[I] scope_id:%d\n", scope_id);
#endif
	}
	
	free(interface_name);
	return scope_id;
}


int check_ip(const char *addr)
{
	char *colon = NULL;
	char buffer[16];
	bzero(&buffer, 16);
	char *addr2 = NULL;
	
	colon = strstr(addr, ":");
	if(colon == NULL){	// ipv4?
		if(inet_pton(AF_INET, addr, buffer) > 0){
			return 4;
		}
	}else{	// ipv6?
		addr2 = get_ipv6_addr_string(addr);
		if(inet_pton(AF_INET6, addr2, buffer) > 0){
			free(addr2);
			return 6;
		}else{
			free(addr2);
		}
	}
	
	return 0;
}


void usage(char *filename)
{
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h local_server_ip(tcp) -p local_server_port(tcp) -H bind_ip(udp) -P bind_port(udp) -a target_ip(udp) -b target_port(udp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s -t 300 -u 0\n", filename);
	printf("             : %s -h :: -p 9000 -H ::1 -P 60000 -a ::1 -b 10053\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9000 -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 60000 -a fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -b 10053 -s\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9000 -H 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -P 60000 -a 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -b 53 -s\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h client_ip(tcp) -p client_port(tcp) -H bind_ip(udp) -P bind_port(udp) -a target_ip(udp) -b target_port(udp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s -t 300 -u 0\n", filename);
	printf("             : %s -r -h ::1 -p 1234 -H ::1 -P 60000 -a ::1 -b 10053\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 1234 -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 60000 -a fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -b 10053 -s\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 1234 -H 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -P 60000 -a 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -b 53 -s\n", filename);
}


int main(int argc, char **argv)
{
	int opt;
	const char* optstring = "rh:p:H:P:a:b:st:u:";
	opterr = 0;
	long forwarder_tv_sec = 300;
	long forwarder_tv_usec = 0;
	
	while((opt=getopt(argc, argv, optstring)) != -1){
		switch(opt){
		case 'r':
			reverse_flag = 1;
			break;
			
		case 'h':
			local_server_ip = optarg;
			client_ip = optarg;
			break;
			
		case 'p':
			local_server_port = optarg;
			client_port = optarg;
			break;
			
		case 'H':
			bind_ip = optarg;
			break;
			
		case 'P':
			bind_port = optarg;
			break;
			
		case 'a':
			target_ip = optarg;
			break;
		
		case 'b':
			target_port = optarg;
			break;
			
		case 's':
			tls_flag = 1;
			break;
			
		case 't':
			forwarder_tv_sec = atol(optarg);
			break;
			
		case 'u':
			forwarder_tv_usec = atol(optarg);
			break;
			
		default:
			usage(argv[0]);
			exit(1);
			
		}
	}
	
	if(reverse_flag == 0 && (local_server_ip == NULL || local_server_port == NULL || bind_ip == NULL || bind_port == NULL || target_ip == NULL || target_port == NULL)){
		usage(argv[0]);
		exit(1);
	}else if(reverse_flag == 1 && (client_ip == NULL || client_port == NULL || bind_ip == NULL || bind_port == NULL || target_ip == NULL || target_port == NULL)){
		usage(argv[0]);
		exit(1);
	}
	
	if(forwarder_tv_sec < 0 || forwarder_tv_sec > 3600 || forwarder_tv_usec < 0 || forwarder_tv_usec > 1000000){
		forwarder_tv_sec = 300;
		forwarder_tv_usec = 0;
	}else if(forwarder_tv_sec == 0 && forwarder_tv_usec == 0){
		forwarder_tv_sec = 300;
		forwarder_tv_usec = 0;
	}
	
	
	int local_server_sock, client_sock, target_sock;
	struct sockaddr_in local_server_addr, client_addr, target_addr, bind_addr;
	struct sockaddr_in6 local_server_addr6, client_addr6, target_addr6, bind_addr6;
	socklen_t client_addr_length = 0;
	char client_addr6_string[INET6_ADDRSTRLEN+1];
	bzero(&client_addr6_string, INET6_ADDRSTRLEN+1);
	char *client_addr6_string_pointer = client_addr6_string;
	char *ipv6_addr_string = NULL;
	char *interface_name = NULL;
	unsigned int scope_id = 0;
	int flags = 0;
	int err = 0;
	int ret = 0;
	
	SSL_CTX *local_server_ctx = NULL;
	SSL *local_server_ssl = NULL;
	BIO *bio = NULL;
	EVP_PKEY *sprivatekey = NULL;
	X509 *scert = NULL;
	
	struct ssl_param ssl_param;
	ssl_param.local_server_ctx = NULL;
	ssl_param.local_server_ssl = NULL;
	
	
	if(reverse_flag == 0){	// Nomal mode
#ifdef _DEBUG
		printf("[I] Nomal mode\n");
#endif	
		if(tls_flag == 1){
#ifdef _DEBUG
			printf("[I] TLS:on\n");
#endif
		}else{
#ifdef _DEBUG
			printf("[I] TLS:off\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec tv_usec(0-1000000 microsec):%ld microsec\n", forwarder_tv_sec, forwarder_tv_usec);
#endif
		
		ret = check_ip(local_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(local_server_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				return -1;
			}
			
			memset((char *)&local_server_addr, 0, sizeof(struct sockaddr_in));
			local_server_addr.sin_family = AF_INET;
			local_server_addr.sin_port = htons(atoi(local_server_port));
			err = inet_pton(AF_INET, local_server_ip, &local_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(local_server_sock);
				return -1;
			}
			
			//bind
			if(bind(local_server_sock, (struct sockaddr *)&local_server_addr, sizeof(struct sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				close(local_server_sock);
				return -1;
			}
			
			// listen
			listen(local_server_sock, 5);
			
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server_ip, local_server_port);
#endif
			
			// accept
			memset((char *)&client_addr, 0, sizeof(struct sockaddr_in));
			client_addr_length = sizeof(struct sockaddr_in);
			client_sock = accept(local_server_sock, (struct sockaddr *)&client_addr, &client_addr_length);
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(local_server_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(local_server_ip);
			scope_id = get_ipv6_scope_id(local_server_ip);
			
			memset((char *)&local_server_addr6, 0, sizeof(struct sockaddr_in6));
			local_server_addr6.sin6_family = AF_INET6;
			local_server_addr6.sin6_port = htons(atoi(local_server_port));
			local_server_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(local_server_sock);
				return -1;
			}
			
			//bind
			if(bind(local_server_sock, (struct sockaddr *)&local_server_addr6, sizeof(struct sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				close(local_server_sock);
				return -1;
			}
			
			
			// listen
			listen(local_server_sock, 5);
			
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server_ip, local_server_port);
#endif
			
			// accept
			memset((char *)&client_addr6, 0, sizeof(struct sockaddr_in6));
			client_addr_length = sizeof(struct sockaddr_in6);
			client_sock = accept(local_server_sock, (struct sockaddr *)&client_addr6, &client_addr_length);
			
#ifdef _DEBUG
			inet_ntop(AF_INET6, &client_addr6.sin6_addr, client_addr6_string_pointer, INET6_ADDRSTRLEN);
			if(client_addr6.sin6_scope_id == 0){
				printf("[I] Connected(tcp) %s:%d\n", client_addr6_string_pointer, ntohs(client_addr6.sin6_port));
			}else{
				interface_name = calloc(IFNAMSIZ+1, sizeof(char));
				printf("[I] Connected(tcp) %s%%%s:%d\n", client_addr6_string_pointer, if_indextoname((unsigned int)client_addr6.sin6_scope_id, interface_name), ntohs(client_addr6.sin6_port));
				free(interface_name);
			}
#endif
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			return -1;
		}
		
		
		if(tls_flag == 1){
			// Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
			
			// SSL TLS connection
			local_server_ctx = SSL_CTX_new(TLS_server_method());
			if(local_server_ctx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error\n");
#endif
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			ssl_param.local_server_ctx = local_server_ctx;
			
			// server private key
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_privatekey, strlen(server_privatekey));
			PEM_read_bio_PrivateKey(bio, &sprivatekey, NULL, NULL);
			BIO_free(bio);
			
			// server X509 certificate
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_certificate, strlen(server_certificate));
			PEM_read_bio_X509(bio, &scert, NULL, NULL);
			BIO_free(bio);
			
			ret = SSL_CTX_use_certificate(local_server_ctx, scert);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_certificate error\n");
#endif
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			ret = SSL_CTX_use_PrivateKey(local_server_ctx, sprivatekey);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_PrivateKey error\n");
#endif
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			ret = SSL_CTX_check_private_key(local_server_ctx);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error\n");
#endif
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			ret = SSL_CTX_set_min_proto_version(local_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			ret = SSL_CTX_set_cipher_list(local_server_ctx, cipher_suite_tls1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			ret = SSL_CTX_set_ciphersuites(local_server_ctx, cipher_suite_tls1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			local_server_ssl = SSL_new(local_server_ctx);
			if(local_server_ssl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			ssl_param.local_server_ssl = local_server_ssl;
			
			if(SSL_set_fd(local_server_ssl, client_sock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
#ifdef _DEBUG
			printf("[I] Try TLS connection (SSL_accept)\n");
#endif
			ret = SSL_accept(local_server_ssl);
			if(ret <= 0){
				err = SSL_get_error(local_server_ssl, ret);
#ifdef _DEBUG
				printf("[E] SSL_accept error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_accept)\n");
#endif
		}
		
		ret = check_ip(bind_ip);
		if(ret == 4){	// ipv4
			// create socket
			target_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(target_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -1;
			}
			
			memset((char *)&bind_addr, 0, sizeof(struct sockaddr_in));
			bind_addr.sin_family = AF_INET;
			bind_addr.sin_port = htons(atoi(bind_port));
			err = inet_pton(AF_INET, bind_ip, &bind_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
			
			// bind
			if(bind(target_sock, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			memset((char *)&target_addr, 0, sizeof(struct sockaddr_in));
			target_addr.sin_family = AF_INET;
			target_addr.sin_port = htons(atoi(target_port));
			err = inet_pton(AF_INET, target_ip, &target_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
		}else if(ret == 6){	// ipv6
			// create socket
			target_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if(target_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(bind_ip);
			scope_id = get_ipv6_scope_id(bind_ip);
			
			memset((char *)&bind_addr6, 0, sizeof(struct sockaddr_in6));
			bind_addr6.sin6_family = AF_INET6;
			bind_addr6.sin6_port = htons(atoi(bind_port));
			bind_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &bind_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
			
			// bind
			if(bind(target_sock, (struct sockaddr *)&bind_addr6, sizeof(struct sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			ipv6_addr_string = get_ipv6_addr_string(target_ip);
			scope_id = get_ipv6_scope_id(target_ip);
			
			memset((char *)&target_addr, 0, sizeof(struct sockaddr_in));
			memset((char *)&target_addr6, 0, sizeof(struct sockaddr_in6));
			target_addr6.sin6_family = AF_INET6;
			target_addr6.sin6_port = htons(atoi(target_port));
			target_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &target_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			fini_ssl(&ssl_param);
			close(client_sock);
			close(target_sock);
			close(local_server_sock);
			return -1;
		}
		
		
		// non blocking
		flags = fcntl(client_sock, F_GETFL, 0);
		fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);
		
		flags = fcntl(target_sock, F_GETFL, 0);
		fcntl(target_sock, F_SETFL, flags | O_NONBLOCK);
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder(client_sock, target_sock, (struct sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder(client_sock, target_sock, (struct sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}else{
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder_tls(client_sock, local_server_ssl, target_sock, (struct sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder_tls(client_sock, local_server_ssl, target_sock, (struct sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		close(client_sock);
		close(target_sock);
		close(local_server_sock);
	}else{	// Reverse mode
#ifdef _DEBUG
		printf("[I] Reverse mode\n");
#endif	
		if(tls_flag == 1){
#ifdef _DEBUG
			printf("[I] TLS:on\n");
#endif
		}else{
#ifdef _DEBUG
			printf("[I] TLS:off\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec tv_usec(0-1000000 microsec):%ld microsec\n", forwarder_tv_sec, forwarder_tv_usec);
#endif
		
		ret = check_ip(client_ip);
		if(ret == 4){	// ipv4
			// create socket
			client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(client_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				return -1;
			}
			
			memset((char *)&client_addr, 0, sizeof(struct sockaddr_in));
			client_addr.sin_family = AF_INET;
			client_addr.sin_port = htons(atoi(client_port));
			err = inet_pton(AF_INET, client_ip, &client_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(client_sock);
				return -1;
			}
			
			// connect
			if((err = connect(client_sock, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				close(client_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", client_ip, client_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			client_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(client_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(client_ip);
			scope_id = get_ipv6_scope_id(client_ip);
			
			memset((char *)&client_addr6, 0, sizeof(struct sockaddr_in6));
			client_addr6.sin6_family = AF_INET6;
			client_addr6.sin6_port = htons(atoi(client_port));
			client_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &client_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(client_sock);
				return -1;
			}
			
			// connect
			if((err = connect(client_sock, (struct sockaddr *)&client_addr6, sizeof(struct sockaddr_in6))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				close(client_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", client_ip, client_port);
#endif
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			return -1;
		}
		
		
		if(tls_flag == 1){
			// Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
			
			// SSL TLS connection
			local_server_ctx = SSL_CTX_new(TLS_server_method());
			if(local_server_ctx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error\n");
#endif
				close(client_sock);
				return -2;
			}
			ssl_param.local_server_ctx = local_server_ctx;
			
			// server private key
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_privatekey, strlen(server_privatekey));
			PEM_read_bio_PrivateKey(bio, &sprivatekey, NULL, NULL);
			BIO_free(bio);
			
			// server X509 certificate
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_certificate, strlen(server_certificate));
			PEM_read_bio_X509(bio, &scert, NULL, NULL);
			BIO_free(bio);
			
			ret = SSL_CTX_use_certificate(local_server_ctx, scert);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_certificate error\n");
#endif
				close(client_sock);
				return -2;
			}
			
			ret = SSL_CTX_use_PrivateKey(local_server_ctx, sprivatekey);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_PrivateKey error\n");
#endif
				close(client_sock);
				return -2;
			}
			
			ret = SSL_CTX_check_private_key(local_server_ctx);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error\n");
#endif
				close(client_sock);
				return -2;
			}
			
			ret = SSL_CTX_set_min_proto_version(local_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(local_server_sock);
				return -2;
			}
			
			ret = SSL_CTX_set_cipher_list(local_server_ctx, cipher_suite_tls1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -2;
			}
			
			ret = SSL_CTX_set_ciphersuites(local_server_ctx, cipher_suite_tls1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -2;
			}
			
			local_server_ssl = SSL_new(local_server_ctx);
			if(local_server_ssl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -2;
			}
			ssl_param.local_server_ssl = local_server_ssl;
			
			if(SSL_set_fd(local_server_ssl, client_sock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -2;
			}
			
#ifdef _DEBUG
			printf("[I] Try TLS connection (SSL_accept)\n");
#endif
			ret = SSL_accept(local_server_ssl);
			if(ret <= 0){
				err = SSL_get_error(local_server_ssl, ret);
#ifdef _DEBUG
				printf("[E] SSL_accept error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_accept)\n");
#endif
		}
		
		ret = check_ip(bind_ip);
		if(ret == 4){	// ipv4
			// create socket
			target_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(target_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -1;
			}
			
			memset((char *)&bind_addr, 0, sizeof(struct sockaddr_in));
			bind_addr.sin_family = AF_INET;
			bind_addr.sin_port = htons(atoi(bind_port));
			err = inet_pton(AF_INET, bind_ip, &bind_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				return -1;
			}
			
			// bind
			if(bind(target_sock, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			memset((char *)&target_addr, 0, sizeof(struct sockaddr_in));
			target_addr.sin_family = AF_INET;
			target_addr.sin_port = htons(atoi(target_port));
			err = inet_pton(AF_INET, target_ip, &target_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				close(local_server_sock);
				return -1;
			}
		}else if(ret == 6){	// ipv6
			// create socket
			target_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if(target_sock == -1){
#ifdef _DEBUG
				printf("[E] socket error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(bind_ip);
			scope_id = get_ipv6_scope_id(bind_ip);
			
			memset((char *)&bind_addr6, 0, sizeof(struct sockaddr_in6));
			bind_addr6.sin6_family = AF_INET6;
			bind_addr6.sin6_port = htons(atoi(bind_port));
			bind_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &bind_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				return -1;
			}
			
			// bind
			if(bind(target_sock, (struct sockaddr *)&bind_addr6, sizeof(struct sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			ipv6_addr_string = get_ipv6_addr_string(target_ip);
			scope_id = get_ipv6_scope_id(target_ip);
			
			memset((char *)&target_addr, 0, sizeof(struct sockaddr_in));
			memset((char *)&target_addr6, 0, sizeof(struct sockaddr_in6));
			target_addr6.sin6_family = AF_INET6;
			target_addr6.sin6_port = htons(atoi(target_port));
			target_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &target_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(client_sock);
				close(target_sock);
				return -1;
			}
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			fini_ssl(&ssl_param);
			close(client_sock);
			close(target_sock);
			return -1;
		}
		
		
		// non blocking
		flags = fcntl(client_sock, F_GETFL, 0);
		fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);
		
		flags = fcntl(target_sock, F_GETFL, 0);
		fcntl(target_sock, F_SETFL, flags | O_NONBLOCK);
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder(client_sock, target_sock, (struct sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder(client_sock, target_sock, (struct sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}else{
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder_tls(client_sock, local_server_ssl, target_sock, (struct sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder_tls(client_sock, local_server_ssl, target_sock, (struct sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		close(client_sock);
		close(target_sock);
	}
	
	return 0;	
}

