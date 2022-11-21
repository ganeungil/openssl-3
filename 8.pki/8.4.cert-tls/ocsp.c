#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/ui.h>
#include <openssl/ossl_typ.h>
#include <openssl/pkcs12.h>


#define FORMAT_PEM		3
#define FORMAT_ASN1	1
#define FORMAT_NETSCAPE	4
#define FORMAT_PKCS12	5
#define NETSCAPE_CERT_HDR	"certificate"
#define UI_INPUT_FLAG_DEFAULT_PWD	0x02
#define UI_CTRL_PRINT_ERRORS		1
#define PW_MIN_LENGTH			4
#define UI_CTRL_IS_REDOABLE		2

#define openssl_fdset(a,b) FD_SET(a, b)
#define OPENSSL_EXIT(n) return(n)

typedef struct pw_cb_data {
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;


/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD	(5 * 60)

BIO *bio_err = NULL;
CONF *config=NULL;
static UI_METHOD *ui_method = NULL;


X509 *load_cert(BIO *err, const char *file, int format,
		const char *pass, ENGINE *e, const char *cert_descrip);
OCSP_RESPONSE *process_responder(BIO *err,
		OCSP_REQUEST *req, char *host, char *path, char *port,
		int use_ssl, STACK_OF(CONF_VALUE) *headers,
		int req_timeout);
int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, 
		X509_STORE *st, unsigned long flags);
X509_STORE *setup_verify(BIO *bp, char *CAfile, char *CApath);
int password_callback(char *buf, int bufsiz, int verify,
		PW_CB_DATA *cb_tmp);
static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
		const EVP_MD *cert_id_md,X509 *issuer,
		STACK_OF(OCSP_CERTID) *ids);
static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio,
		char *path, STACK_OF(CONF_VALUE) *headers,
		OCSP_REQUEST *req, int req_timeout);
static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs,
		OCSP_REQUEST *req, STACK_OF(OPENSSL_STRING) *names,
		STACK_OF(OCSP_CERTID) *ids, long nsec, long maxage);
UI *UI_new_method(const UI_METHOD *method);
char *UI_construct_prompt(UI *ui, const char *object_desc,
		const char *object_name);
static int load_pkcs12(BIO *err, BIO *in, const char *desc,
		pem_password_cb *pem_cb,  void *cb_data,
		EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
int main()
{
	char *CAfile 		= "ca-cert.pem";
	char *issuerFile	= "ca-cert.pem";
	char *certFile		= "client.crt.pem";
	char *url			= "http://127.0.0.1:8888";
	char *host = NULL, *port = NULL, *path = "/";
	char *verify_certfile = NULL;
	X509_STORE *store = NULL;
	X509 *issuer = NULL, *cert = NULL;
	X509 *signer = NULL, *rsigner = NULL;
	ENGINE *e = NULL;
	const EVP_MD *cert_id_md = NULL;
	OCSP_REQUEST *req = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_BASICRESP *bs = NULL;
	STACK_OF(OCSP_CERTID) *ids = NULL;
	STACK_OF(OPENSSL_STRING) *reqnames = NULL;
	STACK_OF(CONF_VALUE) *headers = NULL;
	STACK_OF(X509) *verify_other = NULL;
	BIO *out = NULL, *acbio = NULL;
	int use_ssl = -1, resp_text = 1, req_timeout = -1;
	int noverify = 0, i, badarg = 0;
	int ignore_err = 0, ret = 1;
	unsigned long verify_flags = 0;
	long nsec = MAX_VALIDITY_PERIOD, maxage = -1;

	if (bio_err == NULL)
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	reqnames = sk_OPENSSL_STRING_new_null();
	ids = sk_OCSP_CERTID_new_null();

	// process -CAfile option
	if ((store = setup_verify(bio_err, CAfile, 0)) == NULL) {
		printf ("setup_verify() error.\n");
		exit (1);
	}

	// process -issuer option
	X509_free(issuer);
	issuer = load_cert(bio_err, issuerFile, FORMAT_PEM, NULL, 
						e, "issuer certificate");
	if(!issuer)
		goto end;

	// process -cert option
	X509_free(cert);
	cert = load_cert(bio_err, certFile, FORMAT_PEM, NULL, 
							e, "certificate");
	if(!cert)
		goto end;

	if (!cert_id_md)
		cert_id_md = EVP_sha1();
	
	if(!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
		goto end;
	
	if(!sk_OPENSSL_STRING_push(reqnames, certFile))
		goto end;
	
	// process -url option
	if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl)) {
		BIO_printf(bio_err, "Error parsing URL\n");
		badarg = 1;
	}
	printf ("host=[%s], port=[%s], path=[%s]\n", host, port, path);

	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	if(!out) {
		BIO_printf(bio_err, "Error opening output file\n");
		goto end;
	}

	if (host) {
		resp = process_responder(bio_err, req, host, path,
		                      port, use_ssl, headers, req_timeout);
		if (!resp)
			goto end;
	}

	i = OCSP_response_status(resp);

	if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		BIO_printf(out, "Responder Error: %s (%d)\n",
		           OCSP_response_status_str(i), i);
		// if (ignore_err)
		// goto redo_accept;
		ret = 0;
		goto end;
	}

	if (resp_text)
		OCSP_RESPONSE_print(out, resp, 0);

	bs = OCSP_response_get1_basic(resp);

	if (!bs) {
		BIO_printf(bio_err, "Error parsing response\n");
		goto end;
	}

	if (!noverify) {	// verify
		if (req && ((i = OCSP_check_nonce(req, bs)) <= 0)) {
			if (i == -1)
				BIO_printf(bio_err, "WARNING: no nonce in response\n");
			else {
				BIO_printf(bio_err, "Nonce Verify error\n");
				goto end;
			}
		}

		i = OCSP_basic_verify(bs, verify_other, store, verify_flags);
		if (i < 0)
			i = OCSP_basic_verify(bs, NULL, store, 0);

		if(i <= 0) {
			BIO_printf(bio_err, "Response Verify Failure\n");
			ERR_print_errors(bio_err);
		} else
			BIO_printf(bio_err, "Response verify OK\n");

	}

	if (!print_ocsp_summary(out, bs, req, reqnames, ids, nsec, maxage))
		goto end;

	ret = 0;

end:
	ERR_print_errors(bio_err);
	X509_STORE_free(store);
	X509_free(issuer);
	X509_free(cert);
	X509_free(rsigner);
	BIO_free_all(acbio);
	BIO_free(out);
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	OCSP_BASICRESP_free(bs);
	sk_OPENSSL_STRING_free(reqnames);
	sk_OCSP_CERTID_free(ids);
	sk_X509_pop_free(verify_other, X509_free);
	sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);

	if (use_ssl != -1) {
		OPENSSL_free(host);
		OPENSSL_free(port);
		OPENSSL_free(path);
	}

	OPENSSL_EXIT(ret);
}

X509 *load_cert(BIO *err, const char *file, int format,
		const char *pass, ENGINE *e, const char *cert_descrip)
{
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL) {
		ERR_print_errors(err);
		goto end;
	}

	if (file == NULL) {
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
		setvbuf(stdin, NULL, _IONBF, 0);
# endif /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
		BIO_set_fp(cert, stdin, BIO_NOCLOSE);
	} else {
		if (BIO_read_filename(cert, file) <= 0) {
			BIO_printf(err, "Error opening %s %s\n",
			           cert_descrip, file);
			ERR_print_errors(err);
			goto end;
		}
	}

	if 	(format == FORMAT_ASN1)
		x = d2i_X509_bio(cert,NULL);
	else if (format == FORMAT_PEM)
		x = PEM_read_bio_X509_AUX(cert,NULL,
			(pem_password_cb *)password_callback, NULL);
	else if (format == FORMAT_PKCS12) {
		if (!load_pkcs12(err, cert,cert_descrip, NULL, NULL,
								NULL, &x, NULL))
			goto end;
	} else	{
		BIO_printf(err,"bad input format specified for %s\n",
		           cert_descrip);
		goto end;
	}
end:
	if (x == NULL) {
		BIO_printf(err,"unable to load certificate\n");
		ERR_print_errors(err);
	}
	if (cert != NULL) BIO_free(cert);
	return(x);
}

X509_STORE *setup_verify(BIO *bp, char *CAfile, char *CApath)
{
	X509_STORE *store;
	X509_LOOKUP *lookup;
	
	if(!(store = X509_STORE_new()))
		goto end;

	lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
	if (lookup == NULL)
		goto end;

	if (CAfile) {
		if(!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
			BIO_printf(bp, "Error loading file %s\n", CAfile);
			goto end;
		}
	}
	else X509_LOOKUP_load_file(lookup, NULL,X509_FILETYPE_DEFAULT);

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
	if (lookup == NULL)
		goto end;
	
	if (CApath) {
		if(!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
			BIO_printf(bp, "Error loading directory %s\n", CApath);
			goto end;
		}
	}
	else X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

	ERR_clear_error();
	return store;
end:
	X509_STORE_free(store);
	return NULL;
}

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert, 
				const EVP_MD *cert_id_md,X509 *issuer,
				STACK_OF(OCSP_CERTID) *ids)
{
	OCSP_CERTID *id;
	
	if(!issuer) {
		BIO_printf(bio_err, "No issuer certificate specified\n");
		return 0;
	}
	
	if(!*req)
		*req = OCSP_REQUEST_new();
	if(!*req)
		goto err;

	id = OCSP_cert_to_id(cert_id_md, cert, issuer);

	if(!id || !sk_OCSP_CERTID_push(ids, id))
		goto err;

	if(!OCSP_request_add0_id(*req, id))
		goto err;

	return 1;

err:
	BIO_printf(bio_err, "Error Creating OCSP request\n");
	return 0;
}

OCSP_RESPONSE *process_responder(BIO *err, OCSP_REQUEST *req,
			char *host, char *path, char *port, int use_ssl,
			STACK_OF(CONF_VALUE) *headers, int req_timeout)
{
	BIO *cbio = NULL;
	SSL_CTX *ctx = NULL;
	OCSP_RESPONSE *resp = NULL;
	
	cbio = BIO_new_connect(host);
	if (!cbio) {
		BIO_printf(err, "Error creating connect BIO\n");
		goto end;
	}
	
	if (port) BIO_set_conn_port(cbio, port);
	if (use_ssl == 1) {
		BIO *sbio;
		ctx = SSL_CTX_new(TLS_client_method());

		if (ctx == NULL) {
			BIO_printf(err, "Error creating SSL context.\n");
			goto end;
		}
		
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		sbio = BIO_new_ssl(ctx, 1);
		cbio = BIO_push(sbio, cbio);
	}
	
	resp = query_responder(err, cbio, path, headers, req, req_timeout);
	if (!resp)
		BIO_printf(bio_err, "Error querying OCSP responsder\n");
end:
	if (cbio)
		BIO_free_all(cbio);
	if (ctx)
		SSL_CTX_free(ctx);
	return resp;
}
static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, 
		OCSP_REQUEST *req, STACK_OF(OPENSSL_STRING) *names,
		STACK_OF(OCSP_CERTID) *ids, long nsec,
		long maxage)
{
	OCSP_CERTID *id;
	char *name;
	int i;

	int status, reason;

	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

	if (!bs || !req || !sk_OPENSSL_STRING_num(names) || 
										!sk_OCSP_CERTID_num(ids))
		return 1;

	for (i = 0; i < sk_OCSP_CERTID_num(ids); i++) {
		id = sk_OCSP_CERTID_value(ids, i);
		name = sk_OPENSSL_STRING_value(names, i);
		BIO_printf(out, "%s: ", name);

		if(!OCSP_resp_find_status(bs, id, &status, &reason,
		                          &rev, &thisupd, &nextupd)) {
			BIO_puts(out, "ERROR: No Status found.\n");
			continue;
		}

		/* Check validity: if invalid write to output BIO so we
		 * know which response this refers to.
		 */
		if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
			BIO_puts(out, "WARNING: Status times invalid.\n");
			ERR_print_errors(out);
		}
		BIO_printf(out, "%s\n", OCSP_cert_status_str(status));

		BIO_puts(out, "\tThis Update: ");
		ASN1_GENERALIZEDTIME_print(out, thisupd);
		BIO_puts(out, "\n");

		if(nextupd) {
			BIO_puts(out, "\tNext Update: ");
			ASN1_GENERALIZEDTIME_print(out, nextupd);
			BIO_puts(out, "\n");
		}

		if (status != V_OCSP_CERTSTATUS_REVOKED)
			continue;

		if (reason != -1)
			BIO_printf(out, "\tReason: %s\n",
			           OCSP_crl_reason_str(reason));

		BIO_puts(out, "\tRevocation Time: ");
		ASN1_GENERALIZEDTIME_print(out, rev);
		BIO_puts(out, "\n");
	}

	return 1;
}

int password_callback(char *buf, int bufsiz, int verify,
							PW_CB_DATA *cb_tmp)
{
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data) {
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password) {
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		
		return res;
	}

	ui = UI_new_method(ui_method);
	if (ui) {
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
			                         PW_MIN_LENGTH, BUFSIZ-1);
		if (ok >= 0 && verify) {
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui, prompt, ui_flags, buff, PW_MIN_LENGTH,BUFSIZ-1, buf);
		}
		if (ok >= 0)
			do {
				ok = UI_process(ui);
			} while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff) {
			OPENSSL_cleanse(buff,(unsigned int)bufsiz);
			OPENSSL_free(buff);
		}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1) {
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors(bio_err);
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		if (ok == -2) {
			BIO_printf(bio_err,"aborted!\n");
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		UI_free(ui);
		OPENSSL_free(prompt);
	}

	return res;
}


struct ui_st {
	const UI_METHOD *meth;
	STACK_OF(UI_STRING)	*strings; /* We might want to prompt for more than one thing at a time, and with different echoing status.  */
	void *user_data;
	CRYPTO_EX_DATA ex_data;

#define UI_FLAG_REDOABLE	0x0001
#define UI_FLAG_PRINT_ERRORS	0x0100
	int flags;
};
typedef struct ui_st UI;

UI *UI_new_method(const UI_METHOD *method)
{
	UI *ret;

	ret = (UI *) OPENSSL_malloc(sizeof(UI));
	if (ret == NULL) {
		UIerr(UI_F_UI_NEW_METHOD, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	if (method == NULL)
		ret->meth = UI_get_default_method();
	else
		ret->meth = method;

	ret->strings = NULL;
	ret->user_data = NULL;
	ret->flags = 0;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_UI, ret, &ret->ex_data);

	return ret;
}

static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio,
			char *path, STACK_OF(CONF_VALUE) *headers,
			OCSP_REQUEST *req, int req_timeout)
{
	int fd;
	int rv;
	int i;
	OCSP_REQ_CTX *ctx = NULL;
	OCSP_RESPONSE *rsp = NULL;
	fd_set confds;
	struct timeval tv;

	if (req_timeout != -1)
		BIO_set_nbio(cbio, 1);

	rv = BIO_do_connect(cbio);

	if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
		BIO_puts(err, "Error connecting BIO\n");
		return NULL;
	}

	if (BIO_get_fd(cbio, &fd) <= 0) {
		BIO_puts(err, "Can't get connection fd\n");
		goto err;
	}

	if (req_timeout != -1 && rv <= 0) {
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = req_timeout;
		rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		if (rv == 0) {
			BIO_puts(err, "Timeout on connect\n");
			return NULL;
		}
	}

	ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
	if (!ctx)
		return NULL;

	for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
		CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
		if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
			goto err;
	}

	if (!OCSP_REQ_CTX_set1_req(ctx, req))
		goto err;

	for (;;) {
		rv = OCSP_sendreq_nbio(&rsp, ctx);
		if (rv != -1)
			break;
		
		if (req_timeout == -1)
			continue;
		
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = req_timeout;
		
		if (BIO_should_read(cbio))
			rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
		else if (BIO_should_write(cbio))
			rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		else {
			BIO_puts(err, "Unexpected retry condition\n");
			goto err;
		}
		
		if (rv == 0) {
			BIO_puts(err, "Timeout on request\n");
			break;
		}
		if (rv == -1) {
			BIO_puts(err, "Select error\n");
			break;
		}

	}
err:
	if (ctx)
		OCSP_REQ_CTX_free(ctx);

	return rsp;
}

static int load_pkcs12(BIO *err, BIO *in, const char *desc,
                       pem_password_cb *pem_cb,  void *cb_data,
                       EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
	const char *pass;
	char tpass[PEM_BUFSIZE];
	int len, ret = 0;
	PKCS12 *p12;
	
	p12 = d2i_PKCS12_bio(in, NULL);
	if (p12 == NULL) {
		BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);
		goto die;
	}
	
	/* See if an empty password will do */
	if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
		pass = "";
	else {
		if (!pem_cb)
			pem_cb = (pem_password_cb *)password_callback;
		
		len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
		if (len < 0) {
			BIO_printf(err, "Passpharse callback error for %s\n",
			           desc);
			goto die;
		}
		if (len < PEM_BUFSIZE)
			tpass[len] = 0;
		
		if (!PKCS12_verify_mac(p12, tpass, len)) {
			BIO_printf(err,
					"Mac verify error (wrong password?) in PKCS12 file for %s\n",
					desc);
			goto die;
		}
		pass = tpass;
	}
	ret = PKCS12_parse(p12, pass, pkey, cert, ca);
die:
	if (p12)
		PKCS12_free(p12);
	return ret;
}

int load_config(BIO *err, CONF *cnf)
{
	static int load_config_called = 0;

	if (load_config_called)
		return 1;
	
	load_config_called = 1;
	if (!cnf)
		cnf = config;
	if (!cnf)
		return 1;

	OPENSSL_load_builtin_modules();

	if (CONF_modules_load(cnf, NULL, 0) <= 0) {
		BIO_printf(err, "Error configuring OpenSSL\n");
		ERR_print_errors(err);
		return 0;
	}
	return 1;
}
