/*
 * Title:  udp packet forwarder client header (Windows)
 * Author: Shuichiro Endo
 */

int forwarder(SOCKET local_server_socket, int local_server_addr_length, SOCKET remote_server_socket, long tv_sec, long tv_usec);
int forwarder_tls(SOCKET local_server_socket, int local_server_addr_length, SOCKET remote_server_socket, SSL *remote_server_ssl, long tv_sec, long tv_usec);
char *get_ipv6_addr_string(const char *addr);
char *get_ipv6_interface_name(const char *addr);
unsigned long get_ipv6_scope_id(const char *addr);
int check_ip(const char *addr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

struct ssl_param {
	SSL_CTX *remote_server_ctx;
	SSL *remote_server_ssl;
};

void fini_ssl(struct ssl_param *param);


