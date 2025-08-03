#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "asio.h"

#ifdef _WIN32
#include <Wincrypt.h>
/* These are from Wincrypt.h, they conflict with OpenSSL */
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#endif

struct x509_request {
    CONF *global_config;	/* Global SSL config */
    CONF *req_config;		/* SSL config for this request */
    const EVP_MD *md_alg;
    const EVP_MD *digest;
    string section_name,
        config_filename,
        digest_name,
        extensions_section,
        request_extensions_section;
    int priv_key_bits;
    int priv_key_type;

    int priv_key_encrypt;

#ifdef HAVE_EVP_PKEY_EC
    int curve_name;
#endif

    EVP_PKEY *priv_key;

    const EVP_CIPHER *priv_key_encrypt_cipher;
};

static void_t x509_thread(args_t args) {
    EVP_PKEY *pkey = args[0].object;
    X509 *x509 = args[1].object;
    string_t hostname = args[2].char_ptr;

    /* Open the PEM file for writing the key to disk. */
    char key[UV_MAXHOSTNAMESIZE + 4];
    char crt[UV_MAXHOSTNAMESIZE + 4];

    int r = snprintf(key, sizeof(key), "%s.key", hostname);
    BIO *pOut = BIO_new_file(key, "w");
    if (!pOut) {
        RAII_INFO("Unable to open \"%s\" for writing.\n", key);
        return nullptr;
    }

    /* Write the key to disk. */
    if (!PEM_write_bio_PrivateKey(pOut, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        RAII_LOG("Unable to write private key to disk.");
        return nullptr;
    }
    BIO_free_all(pOut);

    /* Open the PEM file for writing the certificate to disk. */
    r = snprintf(crt, sizeof(crt), "%s.crt", hostname);
    BIO *x509file = BIO_new_file(crt, "w");
    if (!x509file) {
        RAII_INFO("Unable to open \"%s\" for writing.\n", crt);
        return nullptr;
    }

    /* Write the certificate to disk. */
    if (!PEM_write_bio_X509(x509file, x509)) {
        RAII_LOG("Unable to write certificate to disk.");
        return nullptr;
    }
    BIO_free_all(x509file);

    return $(true);
}

static void_t rsa_pkey_thread(args_t args) {
    EVP_PKEY *pkey = args[0].object;
    int keylength = args[1].integer;
    BIGNUM *bn = nullptr;
    char buf[UV_MAXHOSTNAMESIZE + 1] = {0};

    if ((bn = BN_new()) == nullptr || BN_set_word(bn, RSA_F4) != 1) {
        RAII_LOG("Unable to create BIGNUM structure.");
        return nullptr;
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        RAII_LOG("Unable to create RSA structure.");
        BN_free(bn);
        return nullptr;
    }

    /* Generate the RSA key and assign it to pkey. */
    if (!RSA_generate_key_ex(rsa, keylength, bn, nullptr) || !EVP_PKEY_assign_RSA(pkey, rsa)) {
        RAII_INFO("Unable to generate %d-bit RSA key, %s.", keylength, ERR_error_string(ERR_get_error(), buf));
        RSA_free(rsa);
        BN_free(bn);
        return nullptr;
    }

    /* The key has been generated, return it. */
    return $(pkey);
}

EVP_PKEY *rsa_pkey(int keylength) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        RAII_LOG("Unable to create EVP_PKEY structure.");
        return nullptr;
    }

    defer((func_t)EVP_PKEY_free, pkey);
    future fut = thrd_async(rsa_pkey_thread, 2, pkey, casting(keylength));
    if (!thrd_is_done(fut))
        thrd_until(fut);

    if (is_empty(thrd_get(fut).object))
        return nullptr;

    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 *x509_self_signed(EVP_PKEY *pkey, string_t country, string_t org, string_t domain) {
    /* Allocate memory for the X509 structure. */
    X509 *x509 = X509_new();
    if (!x509) {
        RAII_LOG("Unable to create X509 structure.");
        return nullptr;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (u_string_t)(country == nullptr ? "US" : country), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (u_string_t)(org == nullptr ? "selfSigned" : org), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (u_string_t)(domain == nullptr ? "localhost" : domain), -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        RAII_LOG("Error signing certificate.");
        X509_free(x509);
        return nullptr;
    }

    defer((func_t)X509_free, x509);
    return x509;
}

bool pkey_x509_export(EVP_PKEY *pkey, X509 *x509, string_t hostname) {
    future fut = thrd_async(x509_thread, 3, pkey, x509, hostname);
    if (!thrd_is_done(fut))
        thrd_until(fut);

    return thrd_get(fut).boolean;
}
