/*
 * Title:  udp packet forwarder client (Windows)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <winsock2.h>
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

#include "client.h"

#pragma comment(lib,"ws2_32.lib")	// Winsock Library
#pragma comment(lib,"Iphlpapi.lib")	// IP Helper Library
#pragma comment(lib,"libssl.lib")	// OpenSSL Library
#pragma comment(lib,"libcrypto.lib")	// OpenSSL Library

#define IFNAMSIZ 16
#define BUFFER_SIZE 65507	// 65535 bytes - ipv4 header(20 bytes) - udp header(8 bytes)

int optstringIndex = 0;
char *optarg = NULL;

char *local_server_ip = NULL;		// udp
char *local_server_port = NULL;		// udp
char *local_server2_ip = NULL;		// tcp
char *local_server2_port = NULL;	// tcp
char *remote_server_ip = NULL;		// tcp
char *remote_server_port = NULL;	// tcp
int reverse_flag = 0;
int tls_flag = 0;

char server_certificate_filename[256] = "server.crt";	// server certificate file name
char server_certificate_file_directory_path[256] = ".";	// server certificate file directory path


int forwarder(SOCKET local_server_socket, int local_server_addr_length, SOCKET remote_server_socket, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	long t = 0;
	sockaddr *client_addr = NULL;
	int client_addr_length = 0;
	char *buffer = (char *)calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int err = 0;
	
	if(local_server_addr_length == sizeof(sockaddr_in)){	// ipv4
		client_addr = (sockaddr *)calloc(1, sizeof(sockaddr_in));
		client_addr_length = sizeof(sockaddr_in);	
	}else{	// ipv6
		client_addr = (sockaddr *)calloc(1, sizeof(sockaddr_in6));
		client_addr_length = sizeof(sockaddr_in6);
	}
	
	while(1){
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(local_server_socket, &readfds);
		FD_SET(remote_server_socket, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(local_server_socket, &readfds)){
			rec = recvfrom(local_server_socket, buffer, BUFFER_SIZE, 0, client_addr, &client_addr_length);
			if(rec > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(remote_server_socket, buffer+send_length, len, 0);
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
						free(client_addr);
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
				free(client_addr);
				return -1;
			}else{
				break;
			}
		}
		
		ZeroMemory(buffer, BUFFER_SIZE+1);
			
		if(FD_ISSET(remote_server_socket, &readfds)){
			rec = recv(remote_server_socket, buffer, BUFFER_SIZE, 0);
			if(rec > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(local_server_socket, buffer+send_length, len, 0, client_addr, client_addr_length);
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
						free(client_addr);
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
				free(client_addr);
				return -1;
			}else{
				break;
			}
		}
	}
	
	free(buffer);
	free(client_addr);
	return 0;
}


int forwarder_tls(SOCKET local_server_socket, int local_server_addr_length, SOCKET remote_server_socket, SSL *remote_server_ssl, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	long t = 0;
	sockaddr *client_addr = NULL;
	socklen_t client_addr_length = 0;
	char *buffer = (char *)calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int err = 0;
	
	if(local_server_addr_length == sizeof(sockaddr_in)){	// ipv4
		client_addr = (sockaddr *)calloc(1, sizeof(sockaddr_in));
		client_addr_length = sizeof(sockaddr_in);	
	}else{	// ipv6
		client_addr = (sockaddr *)calloc(1, sizeof(sockaddr_in6));
		client_addr_length = sizeof(sockaddr_in6);
	}
	
	while(1){
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		FD_ZERO(&readfds);
		FD_SET(local_server_socket, &readfds);
		FD_SET(remote_server_socket, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		t = tv_sec * 1000000 + tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder select timeout:%ld microsec\n", t);
#endif
			break;
		}
		
		if(FD_ISSET(local_server_socket, &readfds)){
			rec = recvfrom(local_server_socket, buffer, BUFFER_SIZE, 0, client_addr, &client_addr_length);
			if(rec > 0){
				while(1){
					sen = SSL_write(remote_server_ssl, buffer, rec);
					err = SSL_get_error(remote_server_ssl, sen);
					
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
						free(client_addr);
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
				free(client_addr);
				return -1;
			}else{
				break;
			}
		}
		
		ZeroMemory(buffer, BUFFER_SIZE+1);
		
		if(FD_ISSET(remote_server_socket, &readfds)){
			rec = SSL_read(remote_server_ssl, buffer, BUFFER_SIZE);
			err = SSL_get_error(remote_server_ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = sendto(local_server_socket, buffer+send_length, len, 0, client_addr, client_addr_length);
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
						free(client_addr);
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
	printf("usage        : %s -h local_server_ip(udp) -p local_server_port(udp) -H remote_server_ip(tcp) -P remote_server_port(tcp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000\n", filename);
	printf("             : %s -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s\n", filename);
	printf("             : %s -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s -t 300 -u 0\n", filename);
	printf("             : %s -h :: -p 5000 -H ::1 -P 9000\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%10 -p 5000 -H fe80::xxxx:xxxx:xxxx:xxxx%%10 -P 9000 -s\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%10 -p 5000 -H 192.168.1.10 -P 9000 -s\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r local_server_ip(udp) -p local_server_port(udp) -H local_server2_ip(tcp) -P local_server2_port(tcp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s -t 300 -u 0\n", filename);
	printf("             : %s -r -h :: -p 5000 -H :: -P 1234\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%10 -p 5000 -H fe80::xxxx:xxxx:xxxx:xxxx%%10 -P 1234 -s\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%10 -p 5000 -H 0.0.0.0 -P 1234 -s\n", filename);
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
	char optstring[] = "rh:p:H:P:st:u:";
	long forwarder_tv_sec = 300;
	long forwarder_tv_usec = 0;
	
	while((opt=getopt(argc, argv, optstring)) > 0){
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
	
	
	WSADATA wsaData;
	SOCKET local_server_socket = INVALID_SOCKET;
	SOCKET local_server2_socket = INVALID_SOCKET;
	SOCKET remote_server_socket = INVALID_SOCKET;
	sockaddr_in local_server_addr, local_server2_addr, remote_server_addr, client_addr;
	sockaddr_in6 local_server_addr6, local_server2_addr6, remote_server_addr6, client_addr6;
	int local_server_addr_length = 0;
	int remote_server_addr_length = 0;
	char remote_server_addr6_string[INET6_ADDRSTRLEN+1];
	ZeroMemory(&remote_server_addr6_string, INET6_ADDRSTRLEN+1);
	char *remote_server_addr6_string_pointer = remote_server_addr6_string;
	char *ipv6_addr_string = NULL;
	char *interface_name = NULL;
	unsigned long scope_id = 0;
	unsigned long iMode = 1;	// non-blocking mode
	int err = 0;
	int ret = 0;
	
	SSL_CTX *remote_server_ctx = NULL;
	SSL *remote_server_ssl = NULL;
	
	struct ssl_param ssl_param;
	ssl_param.remote_server_ctx = NULL;
	ssl_param.remote_server_ssl = NULL;
	
	
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
		
		ret = check_ip(remote_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			remote_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(remote_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
		
			memset((char *)&remote_server_addr, 0, sizeof(sockaddr_in));
			remote_server_addr.sin_family = AF_INET;
			remote_server_addr.sin_port = htons(atoi(remote_server_port));
			err = inet_pton(AF_INET, remote_server_ip, &remote_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(remote_server_socket);
				WSACleanup();
				return -1;
			}
			
			// connect
			err = connect(remote_server_socket, (sockaddr *)&remote_server_addr, sizeof(sockaddr_in));
			if(err < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				closesocket(remote_server_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", remote_server_ip, remote_server_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			remote_server_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(remote_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(remote_server_ip);
			scope_id = get_ipv6_scope_id(remote_server_ip);
						
			memset((char *)&remote_server_addr6, 0, sizeof(sockaddr_in6));
			remote_server_addr6.sin6_family = AF_INET6;
			remote_server_addr6.sin6_port = htons(atoi(remote_server_port));
			remote_server_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &remote_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(remote_server_socket);
				WSACleanup();
				return -1;
			}
			
			// connect
			err = connect(remote_server_socket, (sockaddr *)&remote_server_addr6, sizeof(sockaddr_in6));
			
			if(err < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				closesocket(remote_server_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%s\n", remote_server_ip, remote_server_port);
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
			remote_server_ctx = SSL_CTX_new(TLS_client_method());
			if(remote_server_ctx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error\n");
#endif
				closesocket(remote_server_socket);
				WSACleanup();
				return -2;
			}
			ssl_param.remote_server_ctx = remote_server_ctx;
			
			ret = SSL_CTX_set_min_proto_version(remote_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				WSACleanup();
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
				closesocket(remote_server_socket);
				WSACleanup();
				return -2;
			}
			ssl_param.remote_server_ssl = remote_server_ssl;
			
			if(SSL_set_fd(remote_server_ssl, remote_server_socket) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				WSACleanup();
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
				closesocket(remote_server_socket);
				WSACleanup();
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_connect)\n");
#endif
		}
		
		
		ret = check_ip(local_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(local_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				WSACleanup();
				return -1;
			}
			
			memset((char *)&local_server_addr, 0, sizeof(sockaddr_in));
			local_server_addr_length = sizeof(sockaddr_in);
			local_server_addr.sin_family = AF_INET;
			local_server_addr.sin_port = htons(atoi(local_server_port));
			err = inet_pton(AF_INET, local_server_ip, &local_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// bind
			if(bind(local_server_socket, (sockaddr *)&local_server_addr, sizeof(sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
		
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if(local_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(local_server_ip);
			scope_id = get_ipv6_scope_id(local_server_ip);
			
			memset((char *)&local_server_addr6, 0, sizeof(sockaddr_in6));
			local_server_addr_length = sizeof(sockaddr_in6);
			local_server_addr6.sin6_family = AF_INET6;
			local_server_addr6.sin6_port = htons(atoi(local_server_port));
			local_server_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// bind
			if(bind(local_server_socket, (sockaddr *)&local_server_addr6, sizeof(sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server_socket);
				WSACleanup();
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
			closesocket(remote_server_socket);
			WSACleanup();
			return -1;
		}
		
		
		// non blocking
		err = ioctlsocket(local_server_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(remote_server_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}
		
		err = ioctlsocket(remote_server_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(remote_server_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			err = forwarder(local_server_socket, local_server_addr_length, remote_server_socket, forwarder_tv_sec, forwarder_tv_usec);
		}else{
			err = forwarder_tls(local_server_socket, local_server_addr_length, remote_server_socket, remote_server_ssl, forwarder_tv_sec, forwarder_tv_usec);
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		closesocket(remote_server_socket);
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
		
		ret = check_ip(local_server2_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server2_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(local_server2_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			memset((char *)&local_server2_addr, 0, sizeof(sockaddr_in));
			local_server2_addr.sin_family = AF_INET;
			local_server2_addr.sin_port = htons(atoi(local_server2_port));
			err = inet_pton(AF_INET, local_server2_ip, &local_server2_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(local_server2_socket);
				WSACleanup();
				return -1;
			}
			
			//bind
			if(bind(local_server2_socket, (sockaddr *)&local_server2_addr, sizeof(sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				closesocket(local_server2_socket);
				WSACleanup();
				return -1;
			}
			
			// listen
			listen(local_server2_socket, 5);
		
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server2_ip, local_server2_port);
#endif
			
			// accept
			memset((char *)&remote_server_addr, 0, sizeof(sockaddr_in));
			remote_server_addr_length = sizeof(sockaddr_in);
			remote_server_socket = accept(local_server2_socket, (sockaddr *)&remote_server_addr, &remote_server_addr_length);
			
#ifdef _DEBUG
			printf("[I] Connected(tcp) %s:%d\n", inet_ntoa(remote_server_addr.sin_addr), ntohs(remote_server_addr.sin_port));
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server2_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if(local_server2_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(local_server2_ip);
			scope_id = get_ipv6_scope_id(local_server2_ip);
			
			memset((char *)&local_server2_addr6, 0, sizeof(sockaddr_in6));
			local_server2_addr6.sin6_family = AF_INET6;
			local_server2_addr6.sin6_port = htons(atoi(local_server2_port));
			local_server2_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server2_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				closesocket(local_server2_socket);
				WSACleanup();
				return -1;
			}
			
			//bind
			if(bind(local_server2_socket, (sockaddr *)&local_server2_addr6, sizeof(sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				closesocket(local_server2_socket);
				WSACleanup();
				return -1;
			}
			
			// listen
			listen(local_server2_socket, 5);
		
#ifdef _DEBUG
			printf("[I] Listen(tcp)    %s:%s\n", local_server2_ip, local_server2_port);
#endif
			
			// accept
			memset((char *)&remote_server_addr6, 0, sizeof(sockaddr_in6));
			remote_server_addr_length = sizeof(sockaddr_in6);
			remote_server_socket = accept(local_server2_socket, (sockaddr *)&remote_server_addr6, &remote_server_addr_length);
			
#ifdef _DEBUG
			inet_ntop(AF_INET6, &remote_server_addr6.sin6_addr, remote_server_addr6_string_pointer, INET6_ADDRSTRLEN);
			if(remote_server_addr6.sin6_scope_id == 0){
				printf("[I] Connected(tcp) %s:%d\n", remote_server_addr6_string_pointer, ntohs(remote_server_addr6.sin6_port));
			}else{
				interface_name = (char *)calloc(IFNAMSIZ+1, sizeof(char));
				printf("[I] Connected(tcp) %s%%%s:%d\n", remote_server_addr6_string_pointer, if_indextoname((unsigned long)remote_server_addr6.sin6_scope_id, interface_name), ntohs(remote_server_addr6.sin6_port));
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
			remote_server_ctx = SSL_CTX_new(TLS_client_method());
			if(remote_server_ctx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error\n");
#endif
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
				return -2;
			}
			ssl_param.remote_server_ctx = remote_server_ctx;
			
			ret = SSL_CTX_set_min_proto_version(remote_server_ctx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
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
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
				return -2;
			}
			ssl_param.remote_server_ssl = remote_server_ssl;
			
			if(SSL_set_fd(remote_server_ssl, remote_server_socket) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
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
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed TLS connection (SSL_connect)\n");
#endif
		}
		
		
		ret = check_ip(local_server_ip);
		if(ret == 4){	// ipv4
			// create socket
			local_server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(local_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
				return -1;
			}
			
			memset((char *)&local_server_addr, 0, sizeof(sockaddr_in));
			local_server_addr_length = sizeof(sockaddr_in);
			local_server_addr.sin_family = AF_INET;
			local_server_addr.sin_port = htons(atoi(local_server_port));
			err = inet_pton(AF_INET, local_server_ip, &local_server_addr.sin_addr);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// bind
			if(bind(local_server_socket, (sockaddr *)&local_server_addr, sizeof(sockaddr_in)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}else if(ret == 6){	// ipv6
			// create socket
			local_server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if(local_server_socket == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] socket error:%d\n", WSAGetLastError());
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				WSACleanup();
				return -1;
			}
			
			ipv6_addr_string = get_ipv6_addr_string(local_server_ip);
			scope_id = get_ipv6_scope_id(local_server_ip);
			
			memset((char *)&local_server_addr6, 0, sizeof(sockaddr_in6));
			local_server_addr_length = sizeof(sockaddr_in6);
			local_server_addr6.sin6_family = AF_INET6;
			local_server_addr6.sin6_port = htons(atoi(local_server_port));
			local_server_addr6.sin6_scope_id = scope_id;
			err = inet_pton(AF_INET6, ipv6_addr_string, &local_server_addr6.sin6_addr);
			free(ipv6_addr_string);
			if(err <= 0){
#ifdef _DEBUG
				printf("[E] inet_pton error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
			// bind
			if(bind(local_server_socket, (sockaddr *)&local_server_addr6, sizeof(sockaddr_in6)) == -1){
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				fini_ssl(&ssl_param);
				closesocket(remote_server_socket);
				closesocket(local_server2_socket);
				closesocket(local_server_socket);
				WSACleanup();
				return -1;
			}
			
#ifdef _DEBUG
			printf("[I] Bind(udp)      %s:%s\n", local_server_ip, local_server_port);
#endif
		}
		
		
		// non blocking
		err = ioctlsocket(local_server_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(remote_server_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}
		
		err = ioctlsocket(remote_server_socket, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n", err);
#endif
			fini_ssl(&ssl_param);
			closesocket(remote_server_socket);
			closesocket(local_server_socket);
			WSACleanup();
			return -1;
		}
		
		
		// forwarder
#ifdef _DEBUG
		printf("[I] Forwarder start\n");
#endif
		
		if(tls_flag == 0){
			err = forwarder(local_server_socket, local_server_addr_length, remote_server_socket, forwarder_tv_sec, forwarder_tv_usec);
		}else{
			err = forwarder_tls(local_server_socket, local_server_addr_length, remote_server_socket, remote_server_ssl, forwarder_tv_sec, forwarder_tv_usec);
		}
		
#ifdef _DEBUG
		printf("[I] Forwarder end\n");
#endif
		
		fini_ssl(&ssl_param);
		closesocket(remote_server_socket);
		closesocket(local_server2_socket);
		closesocket(local_server_socket);
	}
	
	WSACleanup();
	return 0;	
}


