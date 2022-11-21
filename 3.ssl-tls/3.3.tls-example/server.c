// server.c

#include "common.h"
#include <signal.h>

SSL_CTX *setupServerCtx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	
	if (SSL_CTX_use_certificate_chain_file(ctx, SRV_CERT) != 1)
		printErr("SSL_CTX_use_certificate_chain_file() error");
	
	if (SSL_CTX_use_PrivateKey_file(ctx, SRV_PRIV, SSL_FILETYPE_PEM) != 1)
		printErr("SSL_CTX_use_PrivateKey_file() error");

	return ctx;
}

int serverLoop(SSL * ssl)
{
	int err, nread;
	char buf[80];

	// treats an unexpected EOF from the peer as if normally shutdown
	SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);

	do {
		for (nread = 0; nread < sizeof(buf); nread += err) {
			err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
			if (err <= 0)
				break;
		}
		fwrite(buf, 1, nread, stdout);
	}	while (err > 0);

	SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
	return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}

void * serverThread(void *arg)
{
	SSL *ssl = (SSL *) arg;

	pthread_detach(pthread_self());

	if (SSL_accept(ssl) <= 0)
		printErr("SSL_accept() error");
	fprintf(stderr, "SSL Connection opened\n");

	if (serverLoop(ssl))
		SSL_shutdown(ssl);
	else
		SSL_clear(ssl);

	fprintf(stderr, "SSL Connection closed\n");

	SSL_free(ssl);
}

int main(int argc, char *argv[])
{
	BIO *acc, *client;
	SSL *ssl;
	SSL_CTX *ctx;
	pthread_t tid;

	ctx = setupServerCtx();

	if (!(acc = BIO_new_accept(PORT)))
		printErr("BIO_new_accept() error");

	if (BIO_do_accept(acc) <= 0)
		printErr("1st BIO_do_accept() error");

	for (;;) {
		if (BIO_do_accept(acc) <= 0)
			printErr("2nd BIO_do_accept() error ");

		client = BIO_pop(acc);
		if (!(ssl = SSL_new(ctx)))
			printErr("SSL_new() error");

		SSL_set_bio(ssl, client, client);
		pthread_create (&tid, NULL, serverThread, ssl);
	}

	SSL_CTX_free(ctx);
	BIO_free(acc);
	return 0;
}
