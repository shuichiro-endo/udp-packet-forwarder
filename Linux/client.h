/*
 * Title:  udp packet forwarder client header (Linux)
 * Author: Shuichiro Endo
 */

int forwarder(int local_server_sock, socklen_t local_server_addr_length, int remote_server_sock, long tv_sec, long tv_usec);
int forwarder_tls(int local_server_sock, socklen_t local_server_addr_length, int remote_server_sock, SSL *remote_server_ssl, long tv_sec, long tv_usec);
char *get_ipv6_addr_string(const char *addr);
char *get_ipv6_interface_name(const char *addr);
unsigned int get_ipv6_scope_id(const char *addr);
int check_ip(const char *addr);
void usage(char *filename);

struct ssl_param {
	SSL_CTX *remote_server_ctx;
	SSL *remote_server_ssl;
};

void fini_ssl(struct ssl_param *param);


