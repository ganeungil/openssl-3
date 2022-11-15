// util.c
#include "common.h"

void printErr(const char *msg) 
{
	int flags, line;
	const char *data, *file, *func;
	unsigned long code;

	printf ("ERROR-->: [%s]\n", msg);
	code = ERR_get_error_all(&file, &line, &func, &data, &flags);
	while (code) {
		printf("\terror code: %lu in %s func %s line %d.\n", code, file, func, line);
		if (data && (flags & ERR_TXT_STRING))		// if (data가 문자열을 포함)
			printf("\t\terror data: %s\n", data);
		code = ERR_get_error_all(&file, &line, &func, &data, &flags);
	}
}

long postCheck(SSL *ssl, char *host)
{
	X509	*cert;
	char	*str;

	if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
		goto err_occured;

	printf ("peer certificate:\n");
	
	str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	printf ("\t subject: %s\n", str);
	
	str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	printf ("\t issuer: %s\n", str);
	
	free (str);
	X509_free(cert);

	return SSL_get_verify_result(ssl);

err_occured:
	if (cert)
		X509_free(cert);

	return (X509_V_ERR_APPLICATION_VERIFICATION);
}

