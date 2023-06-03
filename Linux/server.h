/*
 * Title:  udp packet forwarder server header (Linux)
 * Author: Shuichiro Endo
 */

int forwarder(int client_sock, int target_sock, struct sockaddr *target_addr, long tv_sec, long tv_usec);
int forwarder_tls(int client_sock, SSL *local_server_ssl, int target_sock, struct sockaddr *target_addr, long tv_sec, long tv_usec);
char *get_ipv6_addr_string(const char *addr);
char *get_ipv6_interface_name(const char *addr);
unsigned int get_ipv6_scope_id(const char *addr);
int check_ip(const char *addr);
void usage(char *filename);

struct ssl_param {
	SSL_CTX *local_server_ctx;
	SSL *local_server_ssl;
};

void fini_ssl(struct ssl_param *param);

