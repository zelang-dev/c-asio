
#include "asio.h"

int uv_main(int argc, char **argv) {
    string_t name = asio_hostname();

    /* Generate the key. */
    puts("Generating RSA key..."CLR_LN);
    EVP_PKEY *pkey = rsa_pkey(4096);
    if (!pkey) {
        return 1;
    }

    /* Generate the certificate. */
    puts("Generating x509 certificate..."CLR_LN);
    X509 *x509 = x509_self(pkey, NULL, NULL, name);
    if (!x509) {
        return 1;
    }

    /* Write the private key and certificate out to disk. */
    puts("Writing key and certificate to disk..."CLR_LN);
    if (x509_self_export(pkey, x509, name)) {
        puts("Success!");
        return 0;
    }

    return 1;
}
