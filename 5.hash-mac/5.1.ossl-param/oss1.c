#include <string.h>
#include <openssl/params.h>

int main() {
    const char *foo = NULL;
    size_t foo_l;
    char bar[1024];
    size_t bar_l;
    OSSL_PARAM *params;
    OSSL_PARAM request[] = {
        { "foo", OSSL_PARAM_UTF8_PTR, &foo, 0 /*irrelevant*/, 0 },
        { "bar", OSSL_PARAM_UTF8_STRING, &bar, sizeof(bar), 0 },
        { NULL, 0, NULL, 0, 0 }
    };
    
    int i;
    params = request;
    for (i = 0; params[i].key != NULL; i++) {
        if (strcmp(params[i].key, "foo") == 0) {
            *(char **)params[i].data = "foo value";
            params[i].return_size = 9; /* length of "foo value" string */
            printf ("[%s]\n", *(char**)params[i].data);
        } else if (strcmp(params[i].key, "bar") == 0) {
            memcpy(params[i].data, "bar value", 10);
            params[i].return_size = 9; /* length of "bar value" string */
            printf ("[%s]\n", params[i].data);
        }
    }
}
