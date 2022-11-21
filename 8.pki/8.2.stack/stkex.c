#include <err.h>
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/safestack.h>

int main(void)
{
    STACK_OF(X509) *stack;
    X509 *x;

    if ((stack = sk_X509_new_null()) == NULL) // allocate a new empty stack
        err(1, NULL);
    if ((x = X509_new()) == NULL)
        err(1, NULL);
    if (sk_X509_push(stack, x) == 0)	// stack: x
        err(1, NULL);
    if (sk_X509_push(stack, x) == 0)	// stack: x - x
        err(1, NULL);

    printf("%d pointers: %p, %p\n", sk_X509_num(stack),
        sk_X509_value(stack, 0), sk_X509_value(stack, 1));

    sk_X509_pop_free(stack, X509_free);
}
