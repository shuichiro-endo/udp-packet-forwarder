/*
 * Title:  udp packet forwarder server (Windows)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <winsock2.h>
#include <Mstcpip.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <netioapi.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "server.h"
#include "serverkey.h"

#pragma comment(lib,"ws2_32.lib")	// Winsock Library
#pragma comment(lib,"Iphlpapi.lib")	// IP Helper Library
#pragma comment(lib,"libssl.lib")	// OpenSSL Library
#pragma comment(lib,"libcrypto.lib")	// OpenSSL Library

#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#define IFNAMSIZ 16
#define BUFFER_SIZE 65507	// 65535 bytes - ipv4 header(20 bytes) - udp header(8 bytes)

int optstringIndex = 0;
char *optarg = NULL;

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


int forwarder(SOCKET client_socket, SOCKET target_socket, sockaddr *target_addr, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	long t = 0;
	int target_addr_length = 0;
	sockaddr *target_addr2 = NULL;
	int target_addr2_length = 0;
	char *buffer = (char *)calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int err = 0;
	
	if(target_addr->sa_family == AF_INET){	// ipv4
		target_addr_length = sizeof(sockaddr_in);
		target_addr2 = (sockaddr *)calloc(1, sizeof(sockaddr_in));
		target_addr2_length = sizeof(sockaddr_in);
	}else{	// ipv6
		target_addr_length = sizeof(sockaddr_in6);
		target_addr2 = (sockaddr *)calloc(1, sizeof(sockaddr_in6));
		target_addr2_length = sizeof(sockaddr_in6);
	}
	
	while(1){
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(client_socket, &readfds);
		FD_SET(target_socket, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(client_socket, &readfds)){
			rec = recv(client_socket, buffer, BUFFER_SIZE, 0);
			if(rec > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(target_socket, buffer+send_length, len, 0, target_addr, target_addr_length);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] sendto error:%d\n", err);
#endif
						free(buffer);
						free(target_addr2);
						return -1;
					}
					send_length += sen;
					len -= sen;
				}
			}else if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] recv error:%d\n", err);
#endif
				free(buffer);
				free(target_addr2);
				return -1;
			}else{
				break;
			}
		}
		
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		if(FD_ISSET(target_socket, &readfds)){
			rec = recvfrom(target_socket, buffer, BUFFER_SIZE, 0, target_addr2, &target_addr2_length);
			if(rec > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_socket, buffer+send_length, len, 0);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] send error:%d\n", err);
#endif
						free(buffer);
						free(target_addr2);
						return -1;
					}
					send_length += sen;
					len -= sen;
				}
			}else if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] recvfrom error:%d\n", err);
#endif
				free(buffer);
				free(target_addr2);
				return -1;
			}else{
				break;
			}
		}
	}
	
	free(buffer);
	free(target_addr2);
	return 0;
}


int forwarder_tls(SOCKET client_socket, SSL *local_server_ssl, SOCKET target_socket, sockaddr *target_addr, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	long t = 0;
	int target_addr_length = 0;
	sockaddr *target_addr2 = NULL;
	int target_addr2_length = 0;
	char *buffer = (char *)calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int err = 0;
	
	if(target_addr->sa_family == AF_INET){	// ipv4
		target_addr_length = sizeof(sockaddr_in);
		target_addr2 = (sockaddr *)calloc(1, sizeof(sockaddr_in));
		target_addr2_length = sizeof(sockaddr_in);
	}else{	// ipv6
		target_addr_length = sizeof(sockaddr_in6);
		target_addr2 = (sockaddr *)calloc(1, sizeof(sockaddr_in6));
		target_addr2_length = sizeof(sockaddr_in6);
	}
	
	while(1){
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(client_socket, &readfds);
		FD_SET(target_socket, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(client_socket, &readfds)){
			rec = SSL_read(local_server_ssl, buffer, BUFFER_SIZE);
			err = SSL_get_error(local_server_ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(target_socket, buffer+send_length, len, 0, target_addr, target_addr_length);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] sendto error:%d\n", err);
#endif
						free(buffer);
						free(target_addr2);
						return -1;
					}
					send_length += sen;
					len -= sen;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				Sleep(5);
			}else if(err == SSL_ERROR_WANT_WRITE){
				Sleep(5);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				free(buffer);
				free(target_addr2);
				return -2;
			}
		}
		
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		if(FD_ISSET(target_socket, &readfds)){
			rec = recvfrom(target_socket, buffer, BUFFER_SIZE, 0, target_addr2, &target_addr2_length);
			if(rec > 0){
				while(1){
					sen = SSL_write(local_server_ssl, buffer, rec);
					err = SSL_get_error(local_server_ssl, sen);
					
					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						Sleep(5);
						continue;
					}else if(err == SSL_ERROR_WANT_READ){
						Sleep(5);
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
			}else if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] recvfrom error:%d\n", err);
#endif
				free(buffer);
				free(target_addr2);
				return -1;
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
	const char *percent = NULL;
	char *addr2 = (char *)calloc(INET6_ADDRSTRLEN+1, sizeof(char));
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
	const char *percent = NULL;
	char *interface_name = (char *)calloc(IFNAMSIZ+1, sizeof(char));
	
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


unsigned long get_ipv6_scope_id(const char *addr)
{
	char *interface_name = NULL;
	unsigned long scope_id = 0;
	char *end;
	
	interface_name = get_ipv6_interface_name(addr);
	if(interface_name != NULL){
//		scope_id = if_nametoindex((const char *)interface_name);
		scope_id = strtol(interface_name, &end, 10);
		if(*end != '\0'){
#ifdef _DEBUG
			printf("[E] strtol error\n");
#endif
			scope_id = 0;
		}
#ifdef _DEBUG
		printf("[I] scope_id:%ld\n", scope_id);
#endif
	}
	
	free(interface_name);
	return scope_id;
}


int check_ip(const char *addr)
{
	const char *colon = NULL;
	char buffer[16];
	ZeroMemory(&buffer, 16);
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
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%10 -p 9000 -H fe80::xxxx:xxxx:xxxx:xxxx%%10 -P 60000 -a fe80::xxxx:xxxx:xxxx:xxxx%%10 -b 10053 -s\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h client_ip(tcp) -p client_port(tcp) -H bind_ip(udp) -P bind_port(udp) -a target_ip(udp) -b target_port(udp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s -t 300 -u 0\n", filename);
	printf("             : %s -r -h ::1 -p 1234 -H ::1 -P 60000 -a ::1 -b 10053\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%10 -p 1234 -H fe80::xxxx:xxxx:xxxx:xxxx%%10 -P 60000 -a fe80::xxxx:xxxx:xxxx:xxxx%%10 -b 10053 -s\n", filename);
}


int getopt(int argc, char **argv, char *optstring)
{
	unsigned char opt = '\0';
	unsigned char next = '\0';
	char *argtmp = NULL;

	while(1){
		opt = *(optstring + optstringIndex);
		optstringIndex++;
		if(opt == '\0'){
			break;
		}
	
		next = *(optstring + optstringIndex);
		if(next == ':'){
			optstringIndex++;
		}
	
		for(int i=1; i<argc; i++){
			argtmp = argv[i];
			if(argtmp[0] == '-'){
				if(argtmp[1] == opt){
					if(next == ':'){
						optarg = argv[i+1];
						return (int)opt;
					}else{
						return (int)opt;
					}
				}
			}
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	int opt;
	char optstring[] = "rh:p:H:P:a:b:st:u:";
	long forwarder_tv_sec = 300;
	long forwarder_tv_usec = 0;
	
	while((opt=getopt(argc, argv, optstring)) > 0){
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
	
	
	WSADATA wsaData;
	SOCKET local_server_socket = INVALID_SOCKET;
	SOCKET client_socket = INVALID_SOCKET;
	SOCKET target_socket = INVALID_SOCKET;
	sockaddr_in local_server_addr, client_addr, target_addr, bind_addr;
	sockaddr_in6 local_server_addr6, client_addr6, target_addr6, bind_addr6;
	int client_addr_length = 0;
	char client_addr6_string[INET6_ADDRSTRLEN+1];
	ZeroMemory(&client_addr6_string, INET6_ADDRSTRLEN+1);
	char *client_addr6_string_pointer = client_addr6_string;
	char *ipv6_addr_string = NULL;
	char *interface_name = NULL;
	unsigned long scope_id = 0;
	unsigned long iMode = 1;	// non-blocking mode
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
	
	
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(err != 0){
#ifdef _DEBUG
		printf("[E] WSAStartup error:%d.\n", err);
#endif
		return -1;
	}
	
	
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
			local_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(local_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			memset((char *)&local_server_addr, 0, sizeof(sockaddr_in));
			local_server_addr.sin_family = AF_INET;
			local_server_addr.sin_port = htons(atoi(local_server_port));
			err = inet_pton(AF_INET, local_server_ip, &local_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			//bind
			if(bind(local_server_socket, (sockaddr *)&local_server_addr, sizeof(sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// listen
			listen(local_server_socket, 5);
			
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server_ip, local_server_port);
#endif
			
			// accept
			memset((char *)&client_addr, 0, sizeof(sockaddr_in));
			client_addr_length = sizeof(sockaddr_in);
			client_socket = accept(local_server_socket, (sockaddr *)&client_addr, &client_addr_length);
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(local_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(local_server_ip);
			scope_id = get_ipv6_scope_id(local_server_ip);
			
			memset((char *)&local_server_addr6, 0, sizeof(sockaddr_in6));
			local_server_addr6.sin6_family = AF_INET6;
			local_server_addr6.sin6_port = htons(atoi(local_server_port));
			local_server_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			//bind
			if(bind(local_server_socket, (sockaddr *)&local_server_addr6, sizeof(sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			
			// listen
			listen(local_server_socket, 5);
			
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server_ip, local_server_port);
#endif
			
			// accept
			memset((char *)&client_addr6, 0, sizeof(sockaddr_in6));
			client_addr_length = sizeof(sockaddr_in6);
			client_socket = accept(local_server_socket, (sockaddr *)&client_addr6, &client_addr_length);
			
#ifdef _DEBUG
			inet_ntop(AF_INET6, &client_addr6.sin6_addr, client_addr6_string_pointer, INET6_ADDRSTRLEN);
			if(client_addr6.sin6_scope_id == 0){
				printf("[I] Connected(tcp) %s:%d\n", client_addr6_string_pointer, ntohs(client_addr6.sin6_port));
			}else{
				interface_name = (char *)calloc(IFNAMSIZ+1, sizeof(char));
				printf("[I] Connected(tcp) %s%%%s:%d\n", client_addr6_string_pointer, if_indextoname((unsigned int)client_addr6.sin6_scope_id, interface_name), ntohs(client_addr6.sin6_port));
				free(interface_name);
			}
#endif
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			WSACleanup();
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
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
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
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_use_PrivateKey(local_server_ctx, sprivatekey);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_PrivateKey error\n");
#endif
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_check_private_key(local_server_ctx);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error\n");
#endif
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_set_min_proto_version(local_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_set_cipher_list(local_server_ctx, cipher_suite_tls1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_set_ciphersuites(local_server_ctx, cipher_suite_tls1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			local_server_ssl = SSL_new(local_server_ctx);
			if(local_server_ssl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			ssl_param.local_server_ssl = local_server_ssl;
			
			if(SSL_set_fd(local_server_ssl, client_socket) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
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
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_accept)\n");
#endif
		}
		
		ret = check_ip(bind_ip);
		if(ret == 4){	// ipv4
			// create socket
			target_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(target_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			memset((char *)&bind_addr, 0, sizeof(sockaddr_in));
			bind_addr.sin_family = AF_INET;
			bind_addr.sin_port = htons(atoi(bind_port));
			err = inet_pton(AF_INET, bind_ip, &bind_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// windows udp sockets: recvfrom() fails with error 10054
			BOOL new_behavior = FALSE;
			DWORD bytes_returned = 0;
			WSAIoctl(target_socket, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), NULL, 0, &bytes_returned, NULL, NULL);
			
			// bind
			if(bind(target_socket, (sockaddr *)&bind_addr, sizeof(sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			memset((char *)&target_addr, 0, sizeof(sockaddr_in));
			target_addr.sin_family = AF_INET;
			target_addr.sin_port = htons(atoi(target_port));
			err = inet_pton(AF_INET, target_ip, &target_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
		}else if(ret == 6){	// ipv6
			// create socket
			target_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if(target_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(bind_ip);
			scope_id = get_ipv6_scope_id(bind_ip);
			
			memset((char *)&bind_addr6, 0, sizeof(sockaddr_in6));
			bind_addr6.sin6_family = AF_INET6;
			bind_addr6.sin6_port = htons(atoi(bind_port));
			bind_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &bind_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// windows udp sockets: recvfrom() fails with error 10054
			BOOL new_behavior = FALSE;
			DWORD bytes_returned = 0;
			WSAIoctl(target_socket, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), NULL, 0, &bytes_returned, NULL, NULL);
			
			// bind
			if(bind(target_socket, (sockaddr *)&bind_addr6, sizeof(sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			ipv6_addr_string = get_ipv6_addr_string(target_ip);
			scope_id = get_ipv6_scope_id(target_ip);
			
			memset((char *)&target_addr, 0, sizeof(sockaddr_in));
			memset((char *)&target_addr6, 0, sizeof(sockaddr_in6));
			target_addr6.sin6_family = AF_INET6;
			target_addr6.sin6_port = htons(atoi(target_port));
			target_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &target_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			fini_ssl(&ssl_param);
			closesocket(client_socket);
			closesocket(target_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}
		
		
		// non blocking
		err = ioctlsocket(client_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(client_socket);
			closesocket(target_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}
		
		err = ioctlsocket(target_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(client_socket);
			closesocket(target_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}		
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder(client_socket, target_socket, (sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder(client_socket, target_socket, (sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}else{
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder_tls(client_socket, local_server_ssl, target_socket, (sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder_tls(client_socket, local_server_ssl, target_socket, (sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		closesocket(client_socket);
		closesocket(target_socket);
		closesocket(local_server_socket);
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
			client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(client_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			memset((char *)&client_addr, 0, sizeof(sockaddr_in));
			client_addr.sin_family = AF_INET;
			client_addr.sin_port = htons(atoi(client_port));
			err = inet_pton(AF_INET, client_ip, &client_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(client_socket);
				WSACleanup();
				return -1;
			}
			
			// connect
			if((err = connect(client_socket, (sockaddr *)&client_addr, sizeof(sockaddr_in))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				closesocket(client_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", client_ip, client_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			client_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(client_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(client_ip);
			scope_id = get_ipv6_scope_id(client_ip);
			
			memset((char *)&client_addr6, 0, sizeof(sockaddr_in6));
			client_addr6.sin6_family = AF_INET6;
			client_addr6.sin6_port = htons(atoi(client_port));
			client_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &client_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(client_socket);
				WSACleanup();
				return -1;
			}
			
			// connect
			if((err = connect(client_socket, (sockaddr *)&client_addr6, sizeof(sockaddr_in6))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				closesocket(client_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", client_ip, client_port);
#endif
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			WSACleanup();
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
				closesocket(client_socket);
				WSACleanup();
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
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_use_PrivateKey(local_server_ctx, sprivatekey);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_PrivateKey error\n");
#endif
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_check_private_key(local_server_ctx);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error\n");
#endif
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_set_min_proto_version(local_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_set_cipher_list(local_server_ctx, cipher_suite_tls1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_set_ciphersuites(local_server_ctx, cipher_suite_tls1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
			
			local_server_ssl = SSL_new(local_server_ctx);
			if(local_server_ssl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
			ssl_param.local_server_ssl = local_server_ssl;
			
			if(SSL_set_fd(local_server_ssl, client_socket) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				WSACleanup();
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
				closesocket(client_socket);
				WSACleanup();
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_accept)\n");
#endif
		}
		
		ret = check_ip(bind_ip);
		if(ret == 4){	// ipv4
			// create socket
			target_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(target_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				WSACleanup();
				return -1;
			}
			
			memset((char *)&bind_addr, 0, sizeof(sockaddr_in));
			bind_addr.sin_family = AF_INET;
			bind_addr.sin_port = htons(atoi(bind_port));
			err = inet_pton(AF_INET, bind_ip, &bind_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				WSACleanup();
				return -1;
			}
			
			// windows udp sockets: recvfrom() fails with error 10054
			BOOL new_behavior = FALSE;
			DWORD bytes_returned = 0;
			WSAIoctl(target_socket, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), NULL, 0, &bytes_returned, NULL, NULL);
			
			// bind
			if(bind(target_socket, (sockaddr *)&bind_addr, sizeof(sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			memset((char *)&target_addr, 0, sizeof(sockaddr_in));
			target_addr.sin_family = AF_INET;
			target_addr.sin_port = htons(atoi(target_port));
			err = inet_pton(AF_INET, target_ip, &target_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
		}else if(ret == 6){	// ipv6
			// create socket
			target_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if(target_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(bind_ip);
			scope_id = get_ipv6_scope_id(bind_ip);
			
			memset((char *)&bind_addr6, 0, sizeof(sockaddr_in6));
			bind_addr6.sin6_family = AF_INET6;
			bind_addr6.sin6_port = htons(atoi(bind_port));
			bind_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &bind_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				WSACleanup();
				return -1;
			}
			
			// windows udp sockets: recvfrom() fails with error 10054
			BOOL new_behavior = FALSE;
			DWORD bytes_returned = 0;
			WSAIoctl(target_socket, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), NULL, 0, &bytes_returned, NULL, NULL);
			
			// bind
			if(bind(target_socket, (sockaddr *)&bind_addr6, sizeof(sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", bind_ip, bind_port);
#endif
			
			ipv6_addr_string = get_ipv6_addr_string(target_ip);
			scope_id = get_ipv6_scope_id(target_ip);
			
			memset((char *)&target_addr, 0, sizeof(sockaddr_in));
			memset((char *)&target_addr6, 0, sizeof(sockaddr_in6));
			target_addr6.sin6_family = AF_INET6;
			target_addr6.sin6_port = htons(atoi(target_port));
			target_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &target_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(client_socket);
				closesocket(target_socket);
				WSACleanup();
				return -1;
			}
		}else{
#ifdef _DEBUG
			printf("[E] check_ip error\n");
#endif
			fini_ssl(&ssl_param);
			closesocket(client_socket);
			closesocket(target_socket);
			WSACleanup();
			return -1;
		}
		
		
		// non blocking
		err = ioctlsocket(client_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(client_socket);
			closesocket(target_socket);
			WSACleanup();
			return -1;
		}
		
		err = ioctlsocket(target_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(client_socket);
			closesocket(target_socket);
			WSACleanup();
			return -1;
		}
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder(client_socket, target_socket, (sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder(client_socket, target_socket, (sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}else{
			if(target_addr.sin_family == AF_INET){	// ipv4
				err = forwarder_tls(client_socket, local_server_ssl, target_socket, (sockaddr *)&target_addr, forwarder_tv_sec, forwarder_tv_usec);
			}else{	// ipv6
				err = forwarder_tls(client_socket, local_server_ssl, target_socket, (sockaddr *)&target_addr6, forwarder_tv_sec, forwarder_tv_usec);
			}
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		closesocket(client_socket);
		closesocket(target_socket);
	}
	
	WSACleanup();
	return 0;	
}

