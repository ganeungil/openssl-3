#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "common.h"


void start_client(char *server_address, int server_port, char *message)
{
	int fd;
	socklen_t len;
	SSL_CTX * ctx;
	SSL * ssl;
	BIO * bio;
	struct timeval timeout;
	struct sockaddr_in remote_addr, local_addr;
	char buf[BUFFER_SIZE], addrbuf[INET6_ADDRSTRLEN];

	memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
	memset((void *) &local_addr, 0, sizeof(struct sockaddr_in));

	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(server_port);

	if ((fd = socket(remote_addr.sin_family, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(-1);
	}

	ctx = SSL_CTX_new(DTLS_client_method());

	if (!SSL_CTX_use_certificate_file (ctx, "/home/egkim/certs/newcerts/client.crt.pem", SSL_FILETYPE_PEM))
		printf("error: no certificate found!");
	if (!SSL_CTX_use_PrivateKey_file (ctx, "/home/egkim/certs/private/client.key.pem", SSL_FILETYPE_PEM))
		printf("error: no private key found!");
	if (!SSL_CTX_check_private_key(ctx))
		printf("error: invalid private key!");

	SSL_CTX_set_verify_depth(ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);
	ssl = SSL_new(ctx);

	/* Create BIO, connect and set to already connected */ 
	bio = BIO_new_dgram(fd, BIO_CLOSE);
	if (connect (fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in))) {
		perror("connect");
	}
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

	SSL_set_bio(ssl, bio, bio);

	if (SSL_connect(ssl) < 0)	// initiate the TLS/SSL handshake with an TLS/SSL server
		exit(EXIT_FAILURE);

	/* Set and activate timeouts */ 
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	printf("\nConnected to %s\n", inet_ntop(AF_INET, &remote_addr.sin_addr, addrbuf, 4));
	printf ("------------------------------------------------------------\n");
	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate (ssl)), 1, XN_FLAG_MULTILINE);
	printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	printf ("\n------------------------------------------------------------\n\n");

	len = SSL_write(ssl, message, strlen(message));
	printf("write %d bytes: [%s]\n", (int) len, message);

	memset (buf, 0x00, sizeof(buf));
	len = SSL_read(ssl, buf, sizeof(buf));
	printf("read %d bytes: [%s]\n", (int) len, buf);

	SSL_shutdown(ssl);
	close(fd);

	printf("Connection closed.\n");
}


int main(int argc, char *argv[])
{
	char message[512];

	if (argc == 1) {
		fprintf (stderr, "usage: client server-ip-addr server-port-number\n");
		exit (1);
	}

	printf ("input message\n");
	memset (message, 0x00, sizeof(message));
	fgets (message, 512, stdin);

	start_client(argv[1], atoi(argv[2]), message);	
}

