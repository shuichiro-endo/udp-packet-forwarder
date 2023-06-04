/*
 * Title:  udp packet forwarder server header (Windows)
 * Author: Shuichiro Endo
 */

int forwarder(SOCKET client_socket, SOCKET target_socket, sockaddr *target_addr, long tv_sec, long tv_usec);
int forwarder_tls(SOCKET client_socket, SSL *local_server_ssl, SOCKET target_socket, sockaddr *target_addr, long tv_sec, long tv_usec);
char *get_ipv6_addr_string(const char *addr);
char *get_ipv6_interface_name(const char *addr);
unsigned long get_ipv6_scope_id(const char *addr);
int check_ip(const char *addr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

struct ssl_param {
	SSL_CTX *local_server_ctx;
	SSL *local_server_ssl;
};

void fini_ssl(struct ssl_param *param);

