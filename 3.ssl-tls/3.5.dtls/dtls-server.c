#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include "common.h"

struct passinfo {
	struct sockaddr_in server_addr, client_addr;
	SSL *ssl;
};


int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	// This function should ask the user if he trusts the received certificate.  Here we always trust.
	return 1;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memcpy(cookie, "cookie", 6);
    *cookie_len = 6;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return 1;
}

void* connection_handle(void *info)
{
	ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct passinfo *pinfo = (struct passinfo*) info;
	SSL *ssl = pinfo->ssl;
	int fd, ret;
	const int on = 1, off = 0;
	struct timeval timeout;

	pthread_detach(pthread_self());

	OPENSSL_assert(pinfo->client_addr.sin_family == pinfo->server_addr.sin_family);
	fd = socket(pinfo->client_addr.sin_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto cleanup;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
	if (bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in))) {
		perror("bind");
		goto cleanup;
	}
	if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in))) {
		perror("connect");
		goto cleanup;
	}

	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr);

	/* Finish handshake */
	do {
		ret = SSL_accept(ssl);
	} while (ret == 0);

	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		goto cleanup;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	printf ("\nThread %lx: accepted connection from %s:%d\n", pthread_self(),
			inet_ntop(AF_INET, &pinfo->client_addr.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			ntohs(pinfo->client_addr.sin_port));

	printf ("------------------------------------------------------------\n");
	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1, XN_FLAG_MULTILINE);
	printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	printf ("\n------------------------------------------------------------\n\n");

	len = SSL_read(ssl, buf, sizeof(buf));
	printf("Thread %lx: read %d bytes\n", pthread_self(), (int) len);

	if (len > 0)
		len = SSL_write(ssl, buf, len);

	SSL_shutdown(ssl);

cleanup:
	close(fd);
	free(info);
	SSL_free(ssl);
	printf("Thread %lx: done, connection closed.\n", pthread_self());
	pthread_exit( (void *) NULL );
}

void start_server(char *local_address, int port) {
	int fd;
	pthread_t tid;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct passinfo *info;
	struct sockaddr_in server_addr, client_addr;

	struct timeval timeout;
	const int on = 1, off = 0;

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	ctx = SSL_CTX_new(DTLS_server_method());
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, "/home/egkim/certs/newcerts/server.crt.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "/home/egkim/certs/private/server.key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

	fd = socket(server_addr.sin_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

	if (bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in))) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	while (1) {
		memset(&client_addr, 0, sizeof(client_addr));

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);	// do handshake with cookie

		info = malloc (sizeof(struct passinfo));
		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_in));
		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_in));
		info->ssl = ssl;

		if (pthread_create(&tid, NULL, connection_handle, info) != 0) {
			perror("pthread_create");
			exit(-1);
		}
	}
}


int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf (stderr, "usage: server local-ip-addr local-port\n");
		exit (1);
	}
	start_server(argv[1], atoi(argv[2]));
}

