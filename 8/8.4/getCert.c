#include <resolv.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
	
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define DEST_URL	"https://www.google.com"
#define	PORT_NUM	"443"

int createSocket(char *, BIO *);

int main() 
{
	BIO *certBio = NULL, *outbio = NULL;
	X509 *cert = NULL;
	X509_NAME *certName = NULL;
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	int server = 0, ret, i;
	char *subj, *issuer;
	
	certBio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	method = TLS_client_method();
	
	if ((ctx = SSL_CTX_new(method)) == NULL)
		BIO_printf(outbio, "Unable to create a new SSL context.\n");
	
	ssl = SSL_new(ctx);
	
	server = createSocket(DEST_URL, outbio);
	if (server != 0)
		BIO_printf(outbio, "connected to %s.\n", DEST_URL);
	
	SSL_set_tlsext_host_name(ssl, "example sni");	// set sni

	// attach the TLS session to the socket descriptor
	SSL_set_fd(ssl, server);
	
	// initiates the TLS/SSL handshake with a server.
	if (SSL_connect(ssl) != 1)
		BIO_printf(outbio, "\tTLS handshake failed\n");
	else
		BIO_printf(outbio, "\tTLS handshake finished successfully\n");
	
	// get remote cert
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
		BIO_printf(outbio, "\tGeting a certificate failed.\n");
	else
		BIO_printf(outbio, "\tserver certificate retrieved.\n");
	
	// extract cert info
	
	subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	printf ("subject: %s\n issuer: %s\n", subj, issuer);
	free (subj); 
	free(issuer);
	
	// free all
	SSL_free(ssl);
	close(server);
	SSL_CTX_free(ctx);
	BIO_printf(outbio, "Finished SSL/TLS connection with server.\n");

	return (0);
}


// creates tcp connection to server *
int createSocket(char url_str[], BIO * out) 
{
	int sockfd, port;
	char hostName[256] = "";
	char *tmp_ptr = NULL;
	struct hostent *host;
	struct sockaddr_in destAddr;
	
	// extract host name
	strncpy(hostName, strstr(url_str, "://") + 3, sizeof(hostName));
	
	// extract port number, if exist
	if (strchr(hostName, ':')) {
		tmp_ptr = strchr(hostName, ':');
		/* the last : starts the port number, if avail, i.e. 8443 */ 
		strncpy(PORT_NUM, tmp_ptr + 1, sizeof(PORT_NUM));
		*tmp_ptr = '\0';
	}

	port = atoi(PORT_NUM);
	if ((host = gethostbyname(hostName)) == NULL) {
		BIO_printf(out, "Error: Cannot resolve hostName %s.\n", hostName);
		abort();
	}
	
	// create tcp socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = htons(port);
	destAddr.sin_addr.s_addr = *(long *) (host->h_addr);
	
	// clear memory
	memset(&(destAddr.sin_zero), '\0', 8);
	tmp_ptr = inet_ntoa(destAddr.sin_addr);
	
	// try to connect
	if (connect (sockfd, (struct sockaddr *) &destAddr,
			 					sizeof(struct sockaddr)) == -1) {
		BIO_printf(out, "Error: Cannot connect to \
				%s [%s] on port %d.\n", hostName, tmp_ptr, port);
	}

	return sockfd;
}
