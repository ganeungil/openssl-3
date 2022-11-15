#include <string.h>
#include <openssl/params.h>

int main() {
	char bar[1024], buf[1024];
	const char *foo = NULL, *cptr;

	OSSL_PARAM params[] = {	// initialize
		OSSL_PARAM_utf8_ptr("foo", &foo, 0),	// (key, address, size)
		OSSL_PARAM_utf8_string("bar", bar, sizeof (bar)),
		OSSL_PARAM_END
	};

	OSSL_PARAM *p;
	if ((p = OSSL_PARAM_locate(params, "foo")) != NULL) {	// if ((p=find())== success)
		cptr = buf;
		OSSL_PARAM_set_utf8_ptr(p, "foo value");	// set value
		OSSL_PARAM_get_utf8_ptr(p, &cptr);			// get value
		printf ("[%s]\n", cptr);
	}

	if ((p = OSSL_PARAM_locate(params, "bar")) != NULL) {
		cptr = buf;
		OSSL_PARAM_set_utf8_string(p, "bar value");
		OSSL_PARAM_get_utf8_string_ptr(p, &cptr);
        printf ("[%s]\n", cptr);
    }

	if ((p = OSSL_PARAM_locate(params, "cookie")) != NULL) {
		cptr = buf;
		OSSL_PARAM_set_utf8_ptr(p, "cookie value");
		OSSL_PARAM_get_utf8_ptr(p, &cptr);
        printf ("[%s]\n", cptr);
    }
	else
		printf ("no cookie\n");
}
