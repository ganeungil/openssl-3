#include "common.h"

SSL_CTX *setupClientCtx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_client_method());
	if (SSL_CTX_load_verify_locations(ctx, CA_CERT, 0) != 1)
		printErr("SSL_CTX_load_verify_locations() error");
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		printErr("SSL_CTX_set_default_verify_paths() error");
	if (SSL_CTX_use_certificate_chain_file(ctx, CLI_CERT) != 1)
		printErr("SSL_CTX_use_certificate_chain_file() error");
	if (SSL_CTX_use_PrivateKey_file(ctx, CLI_PRIV, SSL_FILETYPE_PEM) != 1)
		printErr("SSL_CTX_use_PrivateKey_file() error");

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
	SSL_CTX_set_verify_depth(ctx, 4);

	return ctx;
}

int clientLoop(SSL *ssl)
{
	int  err, nwritten;
	char buf[80];

	for (;;)
	{
		if (!fgets(buf, sizeof(buf), stdin))
			break;
		for (nwritten = 0;  nwritten < sizeof(buf);  nwritten += err)
		{
			err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
			if (err <= 0)
				return 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	BIO     *conn;
	SSL     *ssl;
	SSL_CTX *ctx;
	long    err, postCheck(SSL *, char *);

	ctx = setupClientCtx();

	conn = BIO_new_connect(SERVER ":" PORT);
	if (!conn)
		printErr("BIO_new_connect() error");

	if (BIO_do_connect(conn) <= 0)
		printErr("BIO_do_connect() error");

	assert ((ssl = SSL_new(ctx)) != 0);
	SSL_set_bio(ssl, conn, conn);

	if (SSL_connect(ssl) <= 0)
		printErr("SSL_connect() error");

	if ((err = postCheck(ssl, SERVER)) != X509_V_OK)
	{
		fprintf(stderr, "-Error: peer certificate: %s\n",
				X509_verify_cert_error_string(err));
		printErr("Error checking SSL object after connection");
	}
	fprintf(stderr, "SSL Connection opened\n");

	if (clientLoop(ssl))
		SSL_shutdown(ssl);
	else
		SSL_clear(ssl);
	fprintf(stderr, "SSL Connection closed\n");

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}
