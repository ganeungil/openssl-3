// commoh.h
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>
#define PORT    "23456"
#define SERVER  "127.0.0.1" // server IP addr
#define CLIENT  "127.0.0.1" // client IP addr

#define CLI_CERT "./client.crt.pem"
#define CLI_PRIV "./client.key.pem"
#define SRV_CERT "./server.crt.pem"
#define SRV_PRIV "./server.key.pem"

#define CA_CERT "./ca-cert.pem"

void printErr(const char *msg);
int verifyCallback(int, X509_STORE_CTX *);
