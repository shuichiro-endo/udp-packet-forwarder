/*
 * Title:  udp packet forwarder client (Linux)
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

#include "client.h"

#define BUFFER_SIZE 65507	// 65535 bytes - ipv4 header(20 bytes) - udp header(8 bytes)


char *local_server_ip = NULL;		// udp
char *local_server_port = NULL;		// udp
char *local_server2_ip = NULL;		// tcp
char *local_server2_port = NULL;	// tcp
char *remote_server_ip = NULL;		// tcp
char *remote_server_port = NULL;	// tcp
int reverse_flag = 0;
int tls_flag = 0;
int ipv6_flag = 0;

char server_certificate_filename[256] = "server.crt";	// server certificate file name
char server_certificate_file_directory_path[256] = ".";	// server certificate file directory path


int forwarder(int local_server_sock, socklen_t local_server_addr_length, int remote_server_sock, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	long t = 0;
	struct sockaddr *client_addr = NULL;
	socklen_t client_addr_length = 0;
	unsigned char *buffer = calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	
	if(local_server_addr_length == sizeof(struct sockaddr_in)){	// ipv4
		client_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
		client_addr_length = sizeof(struct sockaddr_in);	
	}else{	// ipv6
		client_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
		client_addr_length = sizeof(struct sockaddr_in6);
	}
	
	while(1){
		bzero(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(local_server_sock, &readfds);
		FD_SET(remote_server_sock, &readfds);
		nfds = (local_server_sock > remote_server_sock ? local_server_sock : remote_server_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(local_server_sock, &readfds)){
			if((rec = recvfrom(local_server_sock, buffer, BUFFER_SIZE, 0, client_addr, &client_addr_length)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(remote_server_sock, buffer+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							free(client_addr);
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
			
		if(FD_ISSET(remote_server_sock, &readfds)){
			if((rec = recv(remote_server_sock, buffer, BUFFER_SIZE, 0)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(local_server_sock, buffer+send_length, len, 0, client_addr, client_addr_length);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							free(client_addr);
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
	free(client_addr);
	return 0;
}


int forwarder_tls(int local_server_sock, socklen_t local_server_addr_length, int remote_server_sock, SSL *remote_server_ssl, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	long t = 0;
	struct sockaddr *client_addr = NULL;
	socklen_t client_addr_length = 0;
	unsigned char *buffer = calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int err = 0;
	
	if(local_server_addr_length == sizeof(struct sockaddr_in)){	// ipv4
		client_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
		client_addr_length = sizeof(struct sockaddr_in);	
	}else{	// ipv6
		client_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
		client_addr_length = sizeof(struct sockaddr_in6);
	}
	
	while(1){
		bzero(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(local_server_sock, &readfds);
		FD_SET(remote_server_sock, &readfds);
		nfds = (local_server_sock > remote_server_sock ? local_server_sock : remote_server_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(local_server_sock, &readfds)){
			if((rec = recvfrom(local_server_sock, buffer, BUFFER_SIZE, 0, client_addr, &client_addr_length)) > 0){
				while(1){
					sen = SSL_write(remote_server_ssl, buffer, rec);
					err = SSL_get_error(remote_server_ssl, sen);
					
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
						free(client_addr);
						return -2;
					}
				}
			}else{
				break;
			}
		}
		
		bzero(buffer, BUFFER_SIZE+1);
		
		if(FD_ISSET(remote_server_sock, &readfds)){
			rec = SSL_read(remote_server_ssl, buffer, BUFFER_SIZE);
			err = SSL_get_error(remote_server_ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(local_server_sock, buffer+send_length, len, 0, client_addr, client_addr_length);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(buffer);
							free(client_addr);
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
				free(client_addr);
				return -2;
			}
		}
	}
	
	free(buffer);
	free(client_addr);
	return 0;
}


void fini_ssl(struct ssl_param *param)
{
	if(param->remote_server_ssl != NULL){
		SSL_shutdown(param->remote_server_ssl);
		SSL_free(param->remote_server_ssl);
	}
	if(param->remote_server_ctx != NULL){
		SSL_CTX_free(param->remote_server_ctx);
	}
	
	return;
}


char *get_ipv6_addr_string(const char *addr)
{
	char *percent = NULL;
	char *addr2 = calloc(INET6_ADDRSTRLEN+1, sizeof(char));
	
	percent = strstr(addr, "%");	// separator
	if(percent != NULL){
		memcpy(addr2, addr, percent-addr);
	}else{
		memcpy(addr2, addr, strlen(addr));
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
	char *percent = NULL;
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
	printf("usage        : %s -h local_server_ip(udp) -p local_server_port(udp) -H remote_server_ip(tcp) -P remote_server_port(tcp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000\n", filename);
	printf("             : %s -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s\n", filename);
	printf("             : %s -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s -t 300 -u 0\n", filename);
	printf("             : %s -h :: -p 5000 -H ::1 -P 9000\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 5000 -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 9000 -s\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r local_server_ip(udp) -p local_server_port(udp) -H local_server2_ip(tcp) -P local_server2_port(tcp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s -t 300 -u 0\n", filename);
	printf("             : %s -r -h :: -p 5000 -H :: -P 1234\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 5000 -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 1234 -s\n", filename);
}


int main(int argc, char **argv)
{
	int opt;
	const char* optstring = "rh:p:H:P:st:u:";
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
			break;
			
		case 'p':
			local_server_port = optarg;
			break;
			
		case 'H':
			remote_server_ip = optarg;
			local_server2_ip = optarg;
			break;
			
		case 'P':
			remote_server_port = optarg;
			local_server2_port = optarg;
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
	
	if(reverse_flag == 0 && (local_server_ip == NULL || local_server_port == NULL || remote_server_ip == NULL || remote_server_port == NULL)){
		usage(argv[0]);
		exit(1);
	}else if(reverse_flag == 1 && (local_server_ip == NULL || local_server_port == NULL || local_server2_ip == NULL || local_server2_port == NULL)){
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
	
	
	int local_server_sock, local_server2_sock, remote_server_sock;
	struct sockaddr_in local_server_addr, local_server2_addr, remote_server_addr, client_addr;
	struct sockaddr_in6 local_server_addr6, local_server2_addr6, remote_server_addr6, client_addr6;
	socklen_t local_server_addr_length = 0;
	socklen_t remote_server_addr_length = 0;
	char remote_server_addr6_string[INET6_ADDRSTRLEN+1];
	bzero(&remote_server_addr6_string, INET6_ADDRSTRLEN+1);
	char *remote_server_addr6_string_pointer = remote_server_addr6_string;
	char *ipv6_addr_string = NULL;
	char *interface_name = NULL;
	unsigned int scope_id = 0;
	int reuse = 1;
	int flags = 0;
	int err = 0;
	int ret = 0;
	
	SSL_CTX *remote_server_ctx = NULL;
	SSL *remote_server_ssl = NULL;
	
	struct ssl_param ssl_param;
	ssl_param.remote_server_ctx = NULL;
	ssl_param.remote_server_ssl = NULL;
	
	
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
		
		ret = check_ip(remote_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			remote_server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		
			memset((char *)&remote_server_addr, 0, sizeof(struct sockaddr_in));
			remote_server_addr.sin_family = AF_INET;
			remote_server_addr.sin_port = htons(atoi(remote_server_port));
			err = inet_pton(AF_INET, remote_server_ip, &remote_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(remote_server_sock);
				return -1;
			}
			
			// connect
			err = connect(remote_server_sock, (struct sockaddr *)&remote_server_addr, sizeof(struct sockaddr_in));
			if(err < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				close(remote_server_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", remote_server_ip, remote_server_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			remote_server_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			
			ipv6_addr_string = get_ipv6_addr_string(remote_server_ip);
			scope_id = get_ipv6_scope_id(remote_server_ip);
						
			memset((char *)&remote_server_addr6, 0, sizeof(struct sockaddr_in6));
			remote_server_addr6.sin6_family = AF_INET6;
			remote_server_addr6.sin6_port = htons(atoi(remote_server_port));
			remote_server_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &remote_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(remote_server_sock);
				return -1;
			}
			
			// connect
			err = connect(remote_server_sock, (struct sockaddr *)&remote_server_addr6, sizeof(struct sockaddr_in6));
			
			if(err < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				close(remote_server_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", remote_server_ip, remote_server_port);
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
			remote_server_ctx = SSL_CTX_new(TLS_client_method());
			if(remote_server_ctx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error\n");
#endif
				close(remote_server_sock);
				return -2;
			}
			ssl_param.remote_server_ctx = remote_server_ctx;
			
			ret = SSL_CTX_set_min_proto_version(remote_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				return -2;
			}
			
			SSL_CTX_set_default_verify_paths(remote_server_ctx);
			SSL_CTX_load_verify_locations(remote_server_ctx, server_certificate_filename, server_certificate_file_directory_path);
			SSL_CTX_set_verify(remote_server_ctx, SSL_VERIFY_PEER, NULL);
			
			remote_server_ssl = SSL_new(remote_server_ctx);
			if(remote_server_ssl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				return -2;
			}
			ssl_param.remote_server_ssl = remote_server_ssl;
			
			if(SSL_set_fd(remote_server_ssl, remote_server_sock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				return -2;
			}
			
#ifdef _DEBUG
			printf("[I] Try TLS connection (SSL_connect)\n");
#endif
			ret = SSL_connect(remote_server_ssl);
			if(ret <= 0){
				err = SSL_get_error(remote_server_ssl, ret);
#ifdef _DEBUG
				printf("[E] SSL_connect error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_connect)\n");
#endif
		}
		
		
		ret = check_ip(local_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			
			memset((char *)&local_server_addr, 0, sizeof(struct sockaddr_in));
			local_server_addr_length = sizeof(struct sockaddr_in);
			local_server_addr.sin_family = AF_INET;
			local_server_addr.sin_port = htons(atoi(local_server_port));
			err = inet_pton(AF_INET, local_server_ip, &local_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server_sock);
				return -1;
			}
			
			// bind
			if(bind(local_server_sock, (struct sockaddr *)&local_server_addr, sizeof(struct sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server_sock);
				return -1;
			}
		
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			
			ipv6_addr_string = get_ipv6_addr_string(local_server_ip);
			scope_id = get_ipv6_scope_id(local_server_ip);
			
			memset((char *)&local_server_addr6, 0, sizeof(struct sockaddr_in6));
			local_server_addr_length = sizeof(struct sockaddr_in6);
			local_server_addr6.sin6_family = AF_INET6;
			local_server_addr6.sin6_port = htons(atoi(local_server_port));
			local_server_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server_sock);
				return -1;
			}
			
			// bind
			if(bind(local_server_sock, (struct sockaddr *)&local_server_addr6, sizeof(struct sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server_sock);
				return -1;
			}
		
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			fini_ssl(&ssl_param);
			close(remote_server_sock);
			return -1;
		}
		
		
		// non blocking
		flags = fcntl(local_server_sock, F_GETFL, 0);
		fcntl(local_server_sock, F_SETFL, flags | O_NONBLOCK);
		
		flags = fcntl(remote_server_sock, F_GETFL, 0);
		fcntl(remote_server_sock, F_SETFL, flags | O_NONBLOCK);
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			err = forwarder(local_server_sock, local_server_addr_length, remote_server_sock, forwarder_tv_sec, forwarder_tv_usec);
		}else{
			err = forwarder_tls(local_server_sock, local_server_addr_length, remote_server_sock, remote_server_ssl, forwarder_tv_sec, forwarder_tv_usec);
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		close(remote_server_sock);
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
		
		ret = check_ip(local_server2_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server2_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			
			memset((char *)&local_server2_addr, 0, sizeof(struct sockaddr_in));
			local_server2_addr.sin_family = AF_INET;
			local_server2_addr.sin_port = htons(atoi(local_server2_port));
			err = inet_pton(AF_INET, local_server2_ip, &local_server2_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(local_server2_sock);
				return -1;
			}
			
			//bind
			if(bind(local_server2_sock, (struct sockaddr *)&local_server2_addr, sizeof(struct sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				close(local_server2_sock);
				return -1;
			}
			
			// listen
			listen(local_server2_sock, 5);
		
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server2_ip, local_server2_port);
#endif
			
			// accept
			memset((char *)&remote_server_addr, 0, sizeof(struct sockaddr_in));
			remote_server_addr_length = sizeof(struct sockaddr_in);
			remote_server_sock = accept(local_server2_sock, (struct sockaddr *)&remote_server_addr, &remote_server_addr_length);
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%d\n", inet_ntoa(remote_server_addr.sin_addr), ntohs(remote_server_addr.sin_port));
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server2_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			
			ipv6_addr_string = get_ipv6_addr_string(local_server2_ip);
			scope_id = get_ipv6_scope_id(local_server2_ip);
			
			memset((char *)&local_server2_addr6, 0, sizeof(struct sockaddr_in6));
			local_server2_addr6.sin6_family = AF_INET6;
			local_server2_addr6.sin6_port = htons(atoi(local_server2_port));
			local_server2_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server2_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				close(local_server2_sock);
				return -1;
			}
			
			//bind
			if(bind(local_server2_sock, (struct sockaddr *)&local_server2_addr6, sizeof(struct sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				close(local_server2_sock);
				return -1;
			}
			
			// listen
			listen(local_server2_sock, 5);
		
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server2_ip, local_server2_port);
#endif
			
			// accept
			memset((char *)&remote_server_addr6, 0, sizeof(struct sockaddr_in6));
			remote_server_addr_length = sizeof(struct sockaddr_in6);
			remote_server_sock = accept(local_server2_sock, (struct sockaddr *)&remote_server_addr6, &remote_server_addr_length);
			
#ifdef _DEBUG
			inet_ntop(AF_INET6, &remote_server_addr6.sin6_addr, remote_server_addr6_string_pointer, INET6_ADDRSTRLEN);
			if(remote_server_addr6.sin6_scope_id == 0){
				printf("[I] Connected(tcp) %s:%d\n", remote_server_addr6_string_pointer, ntohs(remote_server_addr6.sin6_port));
			}else{
				interface_name = calloc(IFNAMSIZ+1, sizeof(char));
				printf("[I] Connected(tcp) %s%%%s:%d\n", remote_server_addr6_string_pointer, if_indextoname((unsigned int)remote_server_addr6.sin6_scope_id, interface_name), ntohs(remote_server_addr6.sin6_port));
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
			remote_server_ctx = SSL_CTX_new(TLS_client_method());
			if(remote_server_ctx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error\n");
#endif
				close(remote_server_sock);
				close(local_server2_sock);
				return -2;
			}
			ssl_param.remote_server_ctx = remote_server_ctx;
			
			ret = SSL_CTX_set_min_proto_version(remote_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				return -2;
			}
			
			SSL_CTX_set_default_verify_paths(remote_server_ctx);
			SSL_CTX_load_verify_locations(remote_server_ctx, server_certificate_filename, server_certificate_file_directory_path);
			SSL_CTX_set_verify(remote_server_ctx, SSL_VERIFY_PEER, NULL);
			
			remote_server_ssl = SSL_new(remote_server_ctx);
			if(remote_server_ssl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				return -2;
			}
			ssl_param.remote_server_ssl = remote_server_ssl;
			
			if(SSL_set_fd(remote_server_ssl, remote_server_sock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				return -2;
			}
			
#ifdef _DEBUG
			printf("[I] Try TLS connection (SSL_connect)\n");
#endif
			ret = SSL_connect(remote_server_ssl);
			if(ret <= 0){
				err = SSL_get_error(remote_server_ssl, ret);
#ifdef _DEBUG
				printf("[E] SSL_connect error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_connect)\n");
#endif
		}
		
		
		ret = check_ip(local_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			
			memset((char *)&local_server_addr, 0, sizeof(struct sockaddr_in));
			local_server_addr_length = sizeof(struct sockaddr_in);
			local_server_addr.sin_family = AF_INET;
			local_server_addr.sin_port = htons(atoi(local_server_port));
			err = inet_pton(AF_INET, local_server_ip, &local_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				close(local_server_sock);
				return -1;
			}
			
			// bind
			if(bind(local_server_sock, (struct sockaddr *)&local_server_addr, sizeof(struct sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				close(local_server_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			
			ipv6_addr_string = get_ipv6_addr_string(local_server_ip);
			scope_id = get_ipv6_scope_id(local_server_ip);
			
			memset((char *)&local_server_addr6, 0, sizeof(struct sockaddr_in6));
			local_server_addr_length = sizeof(struct sockaddr_in6);
			local_server_addr6.sin6_family = AF_INET6;
			local_server_addr6.sin6_port = htons(atoi(local_server_port));
			local_server_addr6.sin6_scope_id = (uint32_t)scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				close(local_server_sock);
				return -1;
			}
			
			// bind
			if(bind(local_server_sock, (struct sockaddr *)&local_server_addr6, sizeof(struct sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				close(remote_server_sock);
				close(local_server2_sock);
				close(local_server_sock);
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}
		
		
		// non blocking
		flags = fcntl(local_server_sock, F_GETFL, 0);
		fcntl(local_server_sock, F_SETFL, flags | O_NONBLOCK);
		
		flags = fcntl(remote_server_sock, F_GETFL, 0);
		fcntl(remote_server_sock, F_SETFL, flags | O_NONBLOCK);
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			err = forwarder(local_server_sock, local_server_addr_length, remote_server_sock, forwarder_tv_sec, forwarder_tv_usec);
		}else{
			err = forwarder_tls(local_server_sock, local_server_addr_length, remote_server_sock, remote_server_ssl, forwarder_tv_sec, forwarder_tv_usec);
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		close(remote_server_sock);
		close(local_server2_sock);
		close(local_server_sock);
	}
	
	return 0;	
}

