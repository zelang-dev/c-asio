#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#   include <openssl/engine.h>
#endif
#include <openssl/rand.h>
#include "asio.h"

#ifdef _WIN32
#include <Wincrypt.h>
/* These are from Wincrypt.h, they conflict with OpenSSL */
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#endif

static char default_ssl_conf_filename[UV_MAXHOSTNAMESIZE];
static char asio_directory[UV_MAXHOSTNAMESIZE] = nil;
static char asio_ca_cert[UV_MAXHOSTNAMESIZE + 4] = nil;
static char asio_cert[UV_MAXHOSTNAMESIZE + 4] = nil;
static char asio_csr[UV_MAXHOSTNAMESIZE + 4] = nil;
static char asio_pkey[UV_MAXHOSTNAMESIZE + 4] = nil;
static char asio_self_touch[UV_MAXHOSTNAMESIZE + 6] = nil;
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
    int curve_name;

#ifdef HAVE_EVP_PKEY_EC
#endif

    EVP_PKEY *priv_key;
    const EVP_CIPHER *priv_key_encrypt_cipher;
};

enum asio_ssl_key_type {
    OPENSSL_KEYTYPE_RSA,
    OPENSSL_KEYTYPE_DSA,
    OPENSSL_KEYTYPE_DH,
    OPENSSL_KEYTYPE_EC,
    OPENSSL_KEYTYPE_DEFAULT = OPENSSL_KEYTYPE_RSA
};

enum asio_cipher_type {
    CIPHER_RC2_40,
    CIPHER_RC2_128,
    CIPHER_RC2_64,
    CIPHER_DES,
    CIPHER_3DES,
    CIPHER_AES_128_CBC,
    CIPHER_AES_192_CBC,
    CIPHER_AES_256_CBC,
    CIPHER_DEFAULT = CIPHER_AES_128_CBC
};

/* OpenSSL Certificate */
struct certificate_object {
    asio_types type;
    void_t value;
    X509 *x509;
};

/* OpenSSL AsymmetricKey */
struct pkey_object {
    asio_types type;
    void_t value;
    bool is_private;
    EVP_PKEY *pkey;
};

/* OpenSSL Certificate Signing Request */
struct x509_request_object {
    asio_types type;
    void_t value;
    X509_REQ *csr;
};

typedef enum {
	ssl_generate_pkey = ca_file + 1,
	ssl_export_file,
	ssl_create_self,
	ssl_x509_pkey_write,
	ssl_worker
} thrd_worker_types;

#define ASIO_SSL_CONFIG_SYNTAX(var)	\
    if (req->var && config_check(#var, req->config_filename, req->var, req->req_config) == false) return false;

static const EVP_CIPHER *get_cipher(long algo) {
    switch (algo) {
        case CIPHER_RC2_40:
            return EVP_rc2_40_cbc();
            break;
        case CIPHER_RC2_64:
            return EVP_rc2_64_cbc();
            break;
        case CIPHER_RC2_128:
            return EVP_rc2_cbc();
            break;
        case CIPHER_DES:
            return EVP_des_cbc();
            break;
        case CIPHER_3DES:
            return EVP_des_ede3_cbc();
            break;
        case CIPHER_AES_128_CBC:
            return EVP_aes_128_cbc();
            break;
        case CIPHER_AES_192_CBC:
            return EVP_aes_192_cbc();
            break;
        case CIPHER_AES_256_CBC:
            return EVP_aes_256_cbc();
            break;
        default:
            return nullptr;
            break;
    }
}

#define SET_OPTIONAL_STRING_ARG(key, varname, defval)   \
	do {                \
        if (optional_args && (item = hash_get(optional_args, key)) != nullptr) {    \
            varname = raii_value(item).char_ptr;    \
		} else {        \
			varname = defval;   \
			insert_string(optional_args, key, varname);   \
			if (varname == nullptr) {  \
				ASIO_ssl_error();   \
			}   \
		}       \
	} while(0)

#define SET_OPTIONAL_LONG_ARG(key, varname, defval)	\
	if (optional_args && (item = hash_get(optional_args, key)) != nullptr) { \
		varname = raii_value(item).long_long; \
    } else { \
		varname = defval; \
        insert_unsigned(optional_args, key, varname);   \
    }

static bool add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value) {
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);
    if (!ex)
        return false;
    sk_X509_EXTENSION_push((struct stack_st_X509_EXTENSION*)sk, ex);
    return true;
}

static bool config_check(string_t section_label, string_t config_filename, string_t sections, CONF *config) {
    X509V3_CTX ctx;

    X509V3_set_ctx_test(&ctx);
    X509V3_set_nconf(&ctx, config);
    if (!X509V3_EXT_add_nconf(config, &ctx, (char *)sections, nullptr)) {
        ASIO_ssl_error();
        RAII_INFO("Error loading %s section %s of %s",
                  section_label,
                  sections,
                  config_filename);
        return false;
    }

    return true;
}

static string conf_string(CONF *conf, string_t group, string_t name) {
    /* OpenSSL reports an error if a configuration value is not found.
     * However, we don't want to generate errors for optional configuration. */
    ERR_set_mark();
    char *str = NCONF_get_string(conf, group, name);
    ERR_pop_to_mark();
    return str;
}

static long conf_number(CONF *conf, string_t group, string_t name) {
    long res = 0;
    ERR_set_mark();
    NCONF_get_number(conf, group, name, &res);
    ERR_pop_to_mark();
    return res;
}

static bool parse_config(struct x509_request *req, hash_t *optional_args) {
    char *str;
    void_t item;

    SET_OPTIONAL_STRING_ARG("config", req->config_filename, default_ssl_conf_filename);
    SET_OPTIONAL_STRING_ARG("config_section_name", req->section_name, "req");
    req->global_config = NCONF_new(nullptr);
    if (!NCONF_load(req->global_config, default_ssl_conf_filename, nullptr))
        ASIO_ssl_error();

    req->req_config = NCONF_new(nullptr);
    if (!NCONF_load(req->req_config, req->config_filename, nullptr))
        return false;

    SET_OPTIONAL_STRING_ARG("digest_alg", req->digest_name,
                            conf_string(req->req_config, req->section_name, "default_md"));
    SET_OPTIONAL_STRING_ARG("x509_extensions", req->extensions_section,
                            conf_string(req->req_config, req->section_name, "x509_extensions"));
    SET_OPTIONAL_STRING_ARG("req_extensions", req->request_extensions_section,
                            conf_string(req->req_config, req->section_name, "req_extensions"));
    SET_OPTIONAL_LONG_ARG("private_key_bits", req->priv_key_bits,
                          conf_number(req->req_config, req->section_name, "default_bits"));
    SET_OPTIONAL_LONG_ARG("private_key_type", req->priv_key_type, OPENSSL_KEYTYPE_RSA);

    if (optional_args && (item = hash_get(optional_args, "encrypt_key")) != nullptr) {
        req->priv_key_encrypt = raii_value(item).boolean;
    } else {
        str = conf_string(req->req_config, req->section_name, "encrypt_rsa_key");
        if (str == nullptr)
            str = conf_string(req->req_config, req->section_name, "encrypt_key");

        if (str != nullptr && strcmp(str, "no") == 0)
            req->priv_key_encrypt = false;
        else
            req->priv_key_encrypt = true;
    }

    if (req->priv_key_encrypt &&
        optional_args && (item = hash_get(optional_args, "encrypt_key_cipher")) != nullptr) {
        long cipher_algo = raii_value(item).s_long;
        const EVP_CIPHER *cipher = get_cipher(cipher_algo);
        if (cipher == nullptr) {
            RAII_LOG("Unknown cipher algorithm for private key");
            return false;
        } else {
            req->priv_key_encrypt_cipher = cipher;
        }
    } else {
        req->priv_key_encrypt_cipher = nullptr;
    }

    /* digest alg */
    if (req->digest_name == nullptr)
        req->digest_name = conf_string(req->req_config, req->section_name, "default_md");

    if (req->digest_name != nullptr)
        req->digest = req->md_alg = EVP_get_digestbyname(req->digest_name);

    if (req->md_alg == nullptr) {
        req->md_alg = req->digest = EVP_sha1();
        ASIO_ssl_error();
    }

    ASIO_SSL_CONFIG_SYNTAX(extensions_section);
	/* set the ec group curve name */
	req->curve_name = NID_undef;
	if (optional_args && (item = hash_get(optional_args, "curve_name")) != nullptr) {
        req->curve_name = OBJ_sn2nid(raii_value(item).char_ptr);
        if (req->curve_name == NID_undef) {
            RAII_INFO("Unknown elliptic curve (short) name %s", raii_value(item).char_ptr);
            return false;
		}
	}

    /* set the string mask */
    str = conf_string(req->req_config, req->section_name, "string_mask");
    if (str != nullptr && !ASN1_STRING_set_default_mask_asc(str)) {
        RAII_INFO("Invalid global string mask setting %s", str);
        return false;
    }
    ASIO_SSL_CONFIG_SYNTAX(request_extensions_section);

    return true;
}

static void dispose_config(struct x509_request *req) {
    if (req->priv_key) {
        EVP_PKEY_free(req->priv_key);
        req->priv_key = nullptr;
    }

    if (req->global_config) {
        NCONF_free(req->global_config);
        req->global_config = nullptr;
    }

    if (req->req_config) {
        NCONF_free(req->req_config);
        req->req_config = nullptr;
    }
}

#if defined(_WIN32) || OPENSSL_API_VERSION >= 0x10100
#   define RAND_ADD_TIME() ((void) 0)
#else
#   define RAND_ADD_TIME() rand_add_timeval()

static inline void rand_add_timeval(void) {
    struct timeval tv;

    gettimeofday(&tv, nullptr);
    RAND_add(&tv, sizeof(tv), 0.0);
}
#endif

static int load_rand_file(const char *file, int *egdsocket, int *seeded) {
    char buffer[UV_MAXHOSTNAMESIZE];

    *egdsocket = 0;
    *seeded = 0;

    if (file == nullptr) {
        file = RAND_file_name(buffer, sizeof(buffer));
    }

    if (file == nullptr || !RAND_load_file(file, -1)) {
        if (RAND_status() == 0) {
            ASIO_ssl_error();
            RAII_LOG("Unable to load random state; not enough random data!");
            return false;
        }
        return false;
    }
    *seeded = 1;
    return true;
}

static int write_rand_file(const char *file, int egdsocket, int seeded) {
    char buffer[UV_MAXHOSTNAMESIZE];

    if (egdsocket || !seeded) {
        /* if we did not manage to read the seed file, we should not write
         * a low-entropy seed file back */
        return false;
    }
    if (file == nullptr) {
        file = RAND_file_name(buffer, sizeof(buffer));
    }
    RAND_ADD_TIME();
    if (file == nullptr || !RAND_write_file(file)) {
        ASIO_ssl_error();
        RAII_LOG("Unable to write random state");
        return false;
    }

    return true;
}

static int evp_pkey_type(int key_type) {
    switch (key_type) {
        case OPENSSL_KEYTYPE_RSA:
            return EVP_PKEY_RSA;
        case OPENSSL_KEYTYPE_DSA:
            return EVP_PKEY_DSA;
        case OPENSSL_KEYTYPE_DH:
            return EVP_PKEY_DH;
        case OPENSSL_KEYTYPE_EC:
          return EVP_PKEY_EC;
        default:
            return -1;
    }
}

#define PKEY_MIN_LENGTH		384
static EVP_PKEY *gen_private_key(struct x509_request *req) {
    if (req->priv_key_bits < PKEY_MIN_LENGTH) {
        RAII_INFO("Private key length must be at least %d bits, configured to %d",
                  PKEY_MIN_LENGTH, req->priv_key_bits);
        return nullptr;
    }

    int type = req->priv_key_type;
    if (type < 0) {
        RAII_LOG("Unsupported private key type");
        return nullptr;
    }

    int egdsocket, seeded;
    char *randfile = conf_string(req->req_config, req->section_name, "RANDFILE");
    load_rand_file(randfile, &egdsocket, &seeded);
    RAND_ADD_TIME();

    EVP_PKEY *key = nullptr;
    EVP_PKEY *params = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, nullptr);
    if (!ctx) {
        ASIO_ssl_error();
        goto cleanup;
    }

    if (type != EVP_PKEY_RSA) {
        if (EVP_PKEY_paramgen_init(ctx) <= 0) {
            ASIO_ssl_error();
            goto cleanup;
        }

        switch (type) {
            case EVP_PKEY_DSA:
                if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, req->priv_key_bits) <= 0) {
                    ASIO_ssl_error();
                    goto cleanup;
                }
                break;
            case EVP_PKEY_DH:
                if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, req->priv_key_bits) <= 0) {
                    ASIO_ssl_error();
                    goto cleanup;
                }
                break;
            case EVP_PKEY_EC:
              if (req->curve_name == NID_undef) {
                RAII_LOG("Missing configuration value: \"curve_name\" not set");
                goto cleanup;
              }
              if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                    ctx, req->curve_name) <= 0 ||
                  EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <=
                    0) {
                ASIO_ssl_error();
                goto cleanup;
              }
              break;
            default:
                break;
        }

        if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
            ASIO_ssl_error();
            goto cleanup;
        }

        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(params, nullptr);
        if (!ctx) {
            ASIO_ssl_error();
            goto cleanup;
        }
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ASIO_ssl_error();
        goto cleanup;
    }

    if (type == EVP_PKEY_RSA && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, req->priv_key_bits) <= 0) {
        ASIO_ssl_error();
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        ASIO_ssl_error();
        goto cleanup;
    }

    req->priv_key = key;

cleanup:
    write_rand_file(randfile, egdsocket, seeded);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void add_bn_to_array(map_t ary, const BIGNUM *bn, const char *name) {
    if (bn != nullptr) {
        int len = BN_num_bytes(bn);
        string str = calloc_local(1, len + 1);
        BN_bn2bin(bn, str);
        map_insert(ary, kv_string(name, str));
    }
}

static bool make_csr_req(struct x509_request *req, X509_REQ *x, u32 num_pairs, va_list ap_copy) {
    u32 i;
    csr_option_types k;
    string v = nullptr, dn_txt[] = {"C", "ST", "L", "O", "OU", "CN"};
    X509_NAME *name = nullptr;
    struct stack_st_X509_EXTENSION *exts = nullptr;
    STACK_OF(CONF_VALUE) *dn_sk, *attr_sk = nullptr;
    char *dn_sect, *attr_sect;
    va_list ap;

    dn_sect = NCONF_get_string(req->req_config, req->section_name, "distinguished_name");
    if (dn_sect == nullptr)
        return false;

    dn_sk = NCONF_get_section(req->req_config, dn_sect);
    if (dn_sk == nullptr)
        return false;

    attr_sect = conf_string(req->req_config, req->section_name, "attributes");
    if (attr_sect == nullptr) {
        attr_sk = nullptr;
    } else {
        attr_sk = NCONF_get_section(req->req_config, attr_sect);
        if (attr_sk == nullptr)
            return false;
    }

    if (X509_REQ_set_version(x, 0L)) {
        if (num_pairs > 0) {
            name = X509_REQ_get_subject_name(x);
            exts = sk_X509_EXTENSION_new_null();

            va_copy(ap, ap_copy);
            for (i = 0; i < num_pairs; i++) {
                k = va_arg(ap, csr_option_types);
                v = va_arg(ap, string);
                switch (k) {
                    case dn_c:
                    case dn_st:
                    case dn_l:
                    case dn_o:
                    case dn_ou:
                    case dn_cn:
                        if (!X509_NAME_add_entry_by_txt(name, dn_txt[k - dn_c], MBSTRING_ASC, v, -1, -1, 0))
                            return false;
                        break;
                    case ext_san:
                    case ext_ku:
                    case ext_nct:
                        if (!add_ext((STACK_OF(X509_REQUEST) *)exts, k - dn_cn, v))
                            return false;
                        break;
                }
            }
            va_end(ap);
            X509_REQ_add_extensions(x, exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }

        if (X509_REQ_set_pubkey(x, req->priv_key))
            return true;
    }

    return false;
}

/*

// Special handling of subjectAltName, see CVE-2013-4073
 // Christian Heimes
static int openssl_x509v3_subjectAltName(BIO *bio, X509_EXTENSION *extension) {
    GENERAL_NAMES *names;
    const X509V3_EXT_METHOD *method = nullptr;
    ASN1_OCTET_STRING *extension_data;
    long i, length, num;
    const unsigned char *p;

    method = X509V3_EXT_get(extension);
    if (method == nullptr) {
        return -1;
    }

    extension_data = X509_EXTENSION_get_data(extension);
    p = extension_data->data;
    length = extension_data->length;
    if (method->it) {
        names = (GENERAL_NAMES *)(ASN1_item_d2i(nullptr, &p, length,
                                                ASN1_ITEM_ptr(method->it)));
    } else {
        names = (GENERAL_NAMES *)(method->d2i(nullptr, &p, length));
    }
    if (names == nullptr) {
        ASIO_ssl_error();
        return -1;
    }

    num = sk_GENERAL_NAME_num(names);
    for (i = 0; i < num; i++) {
        GENERAL_NAME *name;
        ASN1_STRING *as;
        name = sk_GENERAL_NAME_value(names, i);
        switch (name->type) {
            case GEN_EMAIL:
                BIO_puts(bio, "email:");
                as = name->d.rfc822Name;
                BIO_write(bio, ASN1_STRING_get0_data(as),
                          ASN1_STRING_length(as));
                break;
            case GEN_DNS:
                BIO_puts(bio, "DNS:");
                as = name->d.dNSName;
                BIO_write(bio, ASN1_STRING_get0_data(as),
                          ASN1_STRING_length(as));
                break;
            case GEN_URI:
                BIO_puts(bio, "URI:");
                as = name->d.uniformResourceIdentifier;
                BIO_write(bio, ASN1_STRING_get0_data(as),
                          ASN1_STRING_length(as));
                break;
            default:
                GENERAL_NAME_print(bio, name);
        }
        if (i < (num - 1)) {
            BIO_puts(bio, ", ");
        }
    }
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

    return 0;
}


static time_t php_openssl_asn1_time_to_time_t(ASN1_UTCTIME * timestr)
{
    /// This is how the time string is formatted:

      // snprintf(p, sizeof(p), "%02d%02d%02d%02d%02d%02dZ",ts->tm_year%100,
      //    ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
    time_t ret;
    struct tm thetime;
    char *strbuf;
    char *thestr;
    long gmadjust = 0;
    size_t timestr_len;

    if (ASN1_STRING_type(timestr) != V_ASN1_UTCTIME && ASN1_STRING_type(timestr) != V_ASN1_GENERALIZEDTIME) {
        RAII_LOG("Illegal ASN1 data type for timestamp");
        return (time_t)-1;
    }

    timestr_len = (size_t)ASN1_STRING_length(timestr);

    if (timestr_len != strlen((const char *)ASN1_STRING_get0_data(timestr))) {
        RAII_LOG("Illegal length in timestamp");
        return (time_t)-1;
    }

    if (timestr_len < 13 && timestr_len != 11) {
        RAII_LOG("Unable to parse time string %s correctly", timestr->data);
        return (time_t)-1;
    }

    if (ASN1_STRING_type(timestr) == V_ASN1_GENERALIZEDTIME && timestr_len < 15) {
        RAII_LOG("Unable to parse time string %s correctly", timestr->data);
        return (time_t)-1;
    }

    strbuf = estrdup((const char *)ASN1_STRING_get0_data(timestr));

    memset(&thetime, 0, sizeof(thetime));
    thestr = strbuf + timestr_len - 3;

    if (timestr_len == 11) {
        thetime.tm_sec = 0;
    } else {
        thetime.tm_sec = atoi(thestr);
        *thestr = '\0';
        thestr -= 2;
    }
    thetime.tm_min = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_hour = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_mday = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_mon = atoi(thestr) - 1;

    *thestr = '\0';
    if (ASN1_STRING_type(timestr) == V_ASN1_UTCTIME) {
        thestr -= 2;
        thetime.tm_year = atoi(thestr);

        if (thetime.tm_year < 68) {
            thetime.tm_year += 100;
        }
    } else if (ASN1_STRING_type(timestr) == V_ASN1_GENERALIZEDTIME) {
        thestr -= 4;
        thetime.tm_year = atoi(thestr) - 1900;
    }


    thetime.tm_isdst = -1;
    ret = mktime(&thetime);

#ifdef HAVE_STRUCT_TM_TM_GMTOFF
    gmadjust = thetime.tm_gmtoff;
#else
    gmadjust = -(thetime.tm_isdst ? (long)timezone - 3600 : (long)timezone);
#endif
    ret += gmadjust;

    efree(strbuf);

    return ret;
}

static void php_openssl_add_assoc_asn1_string(zval * val, char * key, ASN1_STRING * str)
{
    add_assoc_stringl(val, key, (char *)str->data, str->length);
}

static void php_openssl_add_assoc_name_entry(zval *val, char *key, X509_NAME *name, int shortname)
{
    zval *data;
    zval subitem, tmp;
    int i;
    char *sname;
    int nid;
    X509_NAME_ENTRY *ne;
    ASN1_STRING *str = nullptr;
    ASN1_OBJECT *obj;

    if (key != nullptr) {
        array_init(&subitem);
    } else {
        ZVAL_COPY_VALUE(&subitem, val);
    }

    for (i = 0; i < X509_NAME_entry_count(name); i++) {
        const unsigned char *to_add = nullptr;
        int to_add_len = 0;
        unsigned char *to_add_buf = nullptr;

        ne = X509_NAME_get_entry(name, i);
        obj = X509_NAME_ENTRY_get_object(ne);
        nid = OBJ_obj2nid(obj);

        if (shortname) {
            sname = (char *)OBJ_nid2sn(nid);
        } else {
            sname = (char *)OBJ_nid2ln(nid);
        }

        str = X509_NAME_ENTRY_get_data(ne);
        if (ASN1_STRING_type(str) != V_ASN1_UTF8STRING) {
            to_add_len = ASN1_STRING_to_UTF8(&to_add_buf, str);
            to_add = to_add_buf;
        } else {
            to_add = ASN1_STRING_get0_data(str);
            to_add_len = ASN1_STRING_length(str);
        }

        if (to_add_len != -1) {
            if ((data = zend_hash_str_find(Z_ARRVAL(subitem), sname, strlen(sname))) != nullptr) {
                if (Z_TYPE_P(data) == IS_ARRAY) {
                    add_next_index_stringl(data, (const char *)to_add, to_add_len);
                } else if (Z_TYPE_P(data) == IS_STRING) {
                    array_init(&tmp);
                    add_next_index_str(&tmp, zend_string_copy(Z_STR_P(data)));
                    add_next_index_stringl(&tmp, (const char *)to_add, to_add_len);
                    zend_hash_str_update(Z_ARRVAL(subitem), sname, strlen(sname), &tmp);
                }
            } else {
                add_assoc_stringl(&subitem, sname, (char *)to_add, to_add_len);
            }
        } else {
            ASIO_ssl_error();
        }

        if (to_add_buf != nullptr) {
            OPENSSL_free(to_add_buf);
        }
    }

    if (key != nullptr) {
        zend_hash_str_update(Z_ARRVAL_P(val), key, strlen(key), &subitem);
    }
}
*/

static bool create_self_ex(EVP_PKEY *pkey, X509 *x509) {
	BIO *x509file = nullptr, *pOut = nullptr;
	bool no_error = true;
	if (!(pOut = BIO_new_file(pkey_file(), _BIO_MODE_W(PKCS7_BINARY)))) {
		RAII_INFO("Unable to open \"%s\" for writing.\n", pkey_file());
		no_error = false;
	} else if (pOut
		&& !PEM_write_bio_PrivateKey(pOut, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
		RAII_LOG("Unable to write private key to disk.");
		BIO_free_all(pOut);
		no_error = false;
	} else if(pOut) {
		BIO_free_all(pOut);
	}

	if (!(x509file = BIO_new_file(cert_file(), _BIO_MODE_W(PKCS7_BINARY)))) {
		RAII_INFO("Unable to open \"%s\" for writing.\n", cert_file());
		no_error = false;
	} else if (x509file && !PEM_write_bio_X509(x509file, x509)) {
		RAII_LOG("Unable to write certificate to disk.");
		BIO_free_all(x509file);
		no_error = false;
	} else if (x509file) {
		BIO_free_all(x509file);
	}

	return no_error;
}

static bool generate_pkey_ex(EVP_PKEY *pkey, int keylength, int pkey_id) {
	EVP_PKEY_CTX *ctx = nullptr;
	bool no_error = true;
	switch (pkey_id) {
		case EVP_PKEY_RSA:
			if (is_empty(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr))
				|| (EVP_PKEY_keygen_init(ctx) <= 0)
				|| (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylength) <= 0)
				|| (EVP_PKEY_keygen(ctx, &pkey) <= 0)) {
				ASIO_ssl_error();
				no_error = false;
			}
			break;
		default:
			no_error = false;;
	}

	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return no_error;
}

static void_t thrd_worker_thread(args_t args) {
	thrd_worker_types preform = args[0].integer;
	EVP_PKEY *pkey = nullptr;
	X509 *x509 = nullptr;
	X509_REQ *csr = nullptr;
	bool no_error = true;
	switch (preform) {
		case ssl_generate_pkey:
			pkey = args[1].object;
			int keylength = args[2].integer;
			int pkey_id = args[3].integer;
			no_error = generate_pkey_ex(pkey, keylength, pkey_id);
			break;
		case ssl_create_self:
			pkey = EVP_PKEY_new();
			if (no_error = generate_pkey_ex(pkey, 4096, EVP_PKEY_RSA)) {
				no_error = false;
				x509 = x509_self(pkey, NULL, NULL, asio_hostname());
				if (x509) {
					no_error = create_self_ex(pkey, x509);
					X509_free(x509);
				}
			}
			EVP_PKEY_free(pkey);
			break;
		case ssl_x509_pkey_write:
			pkey = args[1].object;
			x509 = args[2].object;
			no_error = create_self_ex(pkey, x509);
			break;
		case ssl_export_file: {
			struct x509_request x509_req;
			string name = nullptr, passphrase = nullptr;
			BIO *x509file = nullptr, *pOut = nullptr, *bio_out = nullptr;
			hash_t *items = nullptr;
			size_t passphrase_len = 0, filename_len = 0;
			const EVP_CIPHER *cipher;
			int pem_write = 0;

			/* Open the PEM files for writing to disk. */
			char req[UV_MAXHOSTNAMESIZE + 4];
			char key[UV_MAXHOSTNAMESIZE + 4];
			char crt[UV_MAXHOSTNAMESIZE + 4];
			int r = 0;
			if (is_cert_req(args[1].object)) {
				csr = args[1].object;
				name = args[2].char_ptr;
				r = snprintf(req, sizeof(req), "%s.csr", name);
				bio_out = BIO_new_file(req, _BIO_MODE_W(PKCS7_BINARY));
				if (bio_out != nullptr) {
					if (!X509_REQ_print(bio_out, csr))
						ASIO_ssl_error();

					if (!PEM_write_bio_X509_REQ(bio_out, csr)) {
						ASIO_ssl_error();
						RAII_INFO("Error writing PEM to file %s", req);
						BIO_free(bio_out);
						return nullptr;
					}
					BIO_free(bio_out);
				} else {
					ASIO_ssl_error();
					RAII_INFO("Error opening file %s", req);
					return nullptr;
				}
			} else if (is_cert(args[1].object)) {
				x509 = args[1].object;
				name = args[2].char_ptr;
				r = snprintf(crt, sizeof(req), "%s.crt", name);
				bio_out = BIO_new_file(crt, _BIO_MODE_W(PKCS7_BINARY));
				if (bio_out) {
					if (!X509_print(bio_out, x509))
						ASIO_ssl_error();

					if (!PEM_write_bio_X509(bio_out, x509))
						ASIO_ssl_error();
				} else {
					ASIO_ssl_error();
					RAII_INFO("Error opening file %s", crt);
					return nullptr;
				}

				if (!BIO_free(bio_out)) {
					ASIO_ssl_error();
				}
			} else if (is_pkey(args[1].object)) {
				pkey = args[1].object;
				name = args[2].char_ptr;
				memset(&x509_req, 0, sizeof(*&x509_req));
				r = snprintf(key, sizeof(req), "%s.key", name);
				if (parse_config(&x509_req, (items = hash_create_ex(128)))) {
					bio_out = BIO_new_file(key, _BIO_MODE_W(PKCS7_BINARY));
					if (bio_out == nullptr) {
						ASIO_ssl_error();
						goto clean_exit;
					}

					if (passphrase && x509_req.priv_key_encrypt) {
						if (x509_req.priv_key_encrypt_cipher) {
							cipher = x509_req.priv_key_encrypt_cipher;
						} else {
							cipher = (EVP_CIPHER *)EVP_des_ede3_cbc();
						}
					} else {
						cipher = nullptr;
					}

					pem_write = PEM_write_bio_PrivateKey(
						bio_out, pkey, cipher,
						(unsigned char *)passphrase, (int)passphrase_len, nullptr, nullptr);
					if (!pem_write) {
						ASIO_ssl_error();
					}
				}

			clean_exit:
				dispose_config(&x509_req);
				BIO_free(bio_out);
				if (!pem_write)
					return nullptr;
			}
			break;
		}
		default:
			break;
	}

	return no_error ? $(true) : nullptr;
}

ASIO_pkey_t *pkey_create(u32 num_pairs, ...) {}

EVP_PKEY *rsa_pkey(int keylength) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        RAII_LOG("Unable to create EVP_PKEY structure.");
        return nullptr;
    }

	future fut = queue_work(thrd_worker_thread, 4, casting(ssl_generate_pkey), pkey, casting(keylength), casting(EVP_PKEY_RSA));

	if (!queue_get(fut).boolean) {
		EVP_PKEY_free(pkey);
		return nullptr;
	}

    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 *x509_self(EVP_PKEY *pkey, string_t country, string_t org, string_t domain) {
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

    return x509;
}

RAII_INLINE bool x509_self_export(EVP_PKEY *pkey, X509 *x509, string_t path_noext) {
	future fut = queue_work(thrd_worker_thread, 4, casting(ssl_create_self), pkey, x509, path_noext);

	return queue_get(fut).boolean;
}

RAII_INLINE bool x509_pkey_write(EVP_PKEY *pkey, X509 *x509) {
	future fut = queue_work(thrd_worker_thread, 3, casting(ssl_x509_pkey_write), pkey, x509);

	return queue_get(fut).boolean;
}

RAII_INLINE bool pkey_x509_export(EVP_PKEY *pkey, string_t path_noext) {
	future fut = queue_work(thrd_worker_thread, 3, casting(ssl_export_file), pkey, path_noext);

    return queue_get(fut).boolean;
}

RAII_INLINE bool csr_x509_export(X509_REQ *req, string_t path_noext) {
	future fut = queue_work(thrd_worker_thread, 3, casting(ssl_export_file), req, path_noext);

    return queue_get(fut).boolean;
}

RAII_INLINE bool cert_x509_export(X509 *cert, string_t path_noext) {
	future fut = queue_work(thrd_worker_thread, 3, casting(ssl_export_file), cert, path_noext);

    return queue_get(fut).boolean;
}

ASIO_req_t *csr_create(EVP_PKEY *pkey, u32 num_pairs, ...) {
    va_list ap;
    struct x509_request req;
    ASIO_req_t *x509_request_obj = nullptr;
    ASIO_pkey_t *pkey_object = nullptr;
    X509_REQ *csr = nullptr;
    hash_t *args = nullptr;
    bool is_good = false, is_bad = false;

    memset(&req, 0, sizeof(*&req));
    if (parse_config(&req, (args = hash_create_ex(128)))) {
        int we_made_the_key = 0;

        /* Generate or use a private key */
        if (!is_empty(pkey)) {
            req.priv_key = pkey;
        }

        if (req.priv_key == nullptr) {
            gen_private_key(&req);
            we_made_the_key = 1;
            pkey = req.priv_key;
        }

        if (req.priv_key == nullptr) {
            RAII_LOG("Unable to generate a private key");
        } else {
            if (!is_empty(csr = X509_REQ_new())) {
                va_start(ap, num_pairs);
                bool is_good = make_csr_req(&req, csr, num_pairs, ap);
                va_end(ap);
                if (is_good) {
                    X509V3_CTX ext_ctx;
                    X509V3_set_ctx(&ext_ctx, nullptr, nullptr, csr, nullptr, 0);
                    X509V3_set_nconf(&ext_ctx, req.req_config);

                    /* Add extensions */
                    if (req.request_extensions_section && !X509V3_EXT_REQ_add_nconf(req.req_config,
                                                                                    &ext_ctx, req.request_extensions_section, csr)) {
                        RAII_INFO("Error loading extension section %s", req.request_extensions_section);
                        is_bad = true;
                    } else {
                        if (X509_REQ_sign(csr, req.priv_key, req.digest)) {
                            x509_request_obj = calloc_local(1, sizeof(ASIO_req_t));
                            x509_request_obj->csr = csr;
                            x509_request_obj->value = nullptr;
                            x509_request_obj->type = ASIO_SSL_REQ;
                            defer((func_t)X509_REQ_free, csr);
                        } else {
                            RAII_LOG("Error signing request");
                            is_bad = true;
                        }

                        if (we_made_the_key && !is_bad) {
                            /* and an object for the private key */
                            ASIO_pkey_t *pkey_object = calloc_local(1, sizeof(ASIO_pkey_t));
                            pkey_object->is_private = true;
                            pkey_object->pkey = req.priv_key;
                            pkey_object->value = x509_request_obj;
                            pkey_object->type = ASIO_SSL_PKEY;
                            pkey = req.priv_key;
                            x509_request_obj->value = pkey_object;
                            req.priv_key = nullptr; /* make sure the cleanup code doesn't zap it! */
                        }
                    }
                } else {
                    is_bad = true;
                }
            } else {
                ASIO_ssl_error();
            }
        }
        dispose_config(&req);
    }

    if (is_bad) {
        ASIO_ssl_error();
        X509_REQ_free(csr);
    }

    return x509_request_obj;
}

X509 *csr_sign(ASIO_req_t *csr_s, ASIO_cert_t *ca, ASIO_pkey_t *pkey, int days, int serial, arrays_t options) {
    X509_REQ *csr;
    ASIO_cert_t *cert_object;
    hash_t *zpkey, *args = nullptr;
    long num_days;
    X509 *cert = nullptr, *new_cert = nullptr;
    EVP_PKEY * key = nullptr, *priv_key = nullptr;
    int i;
    struct x509_request req;

    csr = csr_s->csr;
    if (csr == nullptr) {
		RAII_LOG("X.509 Certificate Signing Request cannot be retrieved");
		return;
    }

    cert = ca->x509;
    if (cert == nullptr) {
		RAII_LOG("X.509 Certificate cannot be retrieved");
		goto cleanup;
    }

    priv_key = pkey->pkey;
    if (priv_key == nullptr) {
        RAII_LOG("Cannot get private key from parameter 3");
        goto cleanup;
    }

    memset(&req, 0, sizeof(*&req));
    if (cert && !X509_check_private_key(cert, priv_key)) {
        ASIO_ssl_error();
        RAII_LOG("Private key does not correspond to signing cert"); goto cleanup;
    }

    if (!parse_config(&req, args)) {
        goto cleanup;
    }

    key = X509_REQ_get_pubkey(csr);
    if (key == nullptr) {
        ASIO_ssl_error();
        RAII_LOG("Error unpacking public key");
        goto cleanup;
    }

    i = X509_REQ_verify(csr, key);

    if (i < 0) {
        ASIO_ssl_error();
        RAII_LOG("Signature verification problems");
        goto cleanup;
    } else if (i == 0) {
        RAII_LOG("Signature did not match the certificate request");
        goto cleanup;
    }

    new_cert = X509_new();
    if (new_cert == nullptr) {
        ASIO_ssl_error();
        RAII_LOG("No memory");
        goto cleanup;
    }

    if (!X509_set_version(new_cert, 2)) {
        goto cleanup;
    }

#if !defined (LIBRESSL_VERSION_NUMBER)
    ASN1_INTEGER_set_int64(X509_get_serialNumber(new_cert), serial);
#else
    ASN1_INTEGER_set(X509_get_serialNumber(new_cert), serial);
#endif

    X509_set_subject_name(new_cert, X509_REQ_get_subject_name(csr));
    if (cert == nullptr) {
		cert = new_cert;
    }

    if (!X509_set_issuer_name(new_cert, X509_get_subject_name(cert))) {
        ASIO_ssl_error();
        goto cleanup;
    }

    X509_gmtime_adj(X509_getm_notBefore(new_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(new_cert), 60*60*24*(long)num_days);
    i = X509_set_pubkey(new_cert, key);
    if (!i) {
        ASIO_ssl_error();
        goto cleanup;
    }

    if (req.extensions_section) {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, cert, new_cert, csr, nullptr, 0);
        X509V3_set_nconf(&ctx, req.req_config);
        if (!X509V3_EXT_add_nconf(req.req_config, &ctx, req.extensions_section, new_cert)) {
            ASIO_ssl_error();
            goto cleanup;
        }
    }

    if (!X509_sign(new_cert, priv_key, req.digest)) {
        ASIO_ssl_error();
        RAII_LOG("Failed to sign it");
        goto cleanup;
    }

    //cert_object = calloc_local(1, sizeof(ASIO_cert_t));
    //cert_object->x509 = new_cert;

cleanup:
    if (cert == new_cert) {
        cert = nullptr;
    }

    dispose_config(&req);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(key);

    return new_cert;
}

EVP_PKEY *pkey_get(string_t file_path) {
	EVP_PKEY *pkey = nullptr;
	BIO *file_in = BIO_new_file(file_path, _BIO_MODE_R(PKCS7_BINARY));
	if (is_empty(file_in))
		return nullptr;

	pkey = PEM_read_bio_PrivateKey(file_in, nullptr, nullptr, nullptr);
	BIO_free(file_in);
	if (is_empty(pkey))
		return nullptr;

	defer((func_t)EVP_PKEY_free, pkey);
	return pkey;
}

string x509_str(X509 *cert, bool show_details) {
	string out = nullptr;
	BIO *bio_out;

	if (cert == nullptr) {
		RAII_LOG("X.509 Certificate cannot be retrieved");
		return;
	}

	bio_out = BIO_new(BIO_s_mem());
	if (!bio_out) {
		ASIO_ssl_error();
		goto cleanup;
	}

	if (show_details && !X509_print(bio_out, cert)) {
		ASIO_ssl_error();
	}

	if (PEM_write_bio_X509(bio_out, cert)) {
		BUF_MEM *bio_buf;

		BIO_get_mem_ptr(bio_out, &bio_buf);
		out = str_dup(bio_buf->data);
	} else {
		ASIO_ssl_error();
	}

	BIO_free(bio_out);

cleanup:
	return out;
}

X509 *x509_get(string_t file_path) {
	X509 *cert;
	BIO *file_in = BIO_new_file(file_path, _BIO_MODE_R(PKCS7_BINARY));
	if (is_empty(file_in)) {
		ASIO_ssl_error();
		return nullptr;
	}

	cert = PEM_read_bio_X509(file_in, nullptr, nullptr, nullptr);
	if (!BIO_free(file_in)) {
		ASIO_ssl_error();
	}

	if (is_empty(cert)) {
		ASIO_ssl_error();
		return nullptr;
	}

	defer((func_t)X509_free, cert);
	return cert;
}

void ASIO_ssl_error(void) {
    int error_code = ERR_get_error();
    char buf[UV_MAXHOSTNAMESIZE] = {0};
    if (!error_code)
        return;

    cerr("Error: %s"CLR_LN, ERR_error_string(ERR_get_error(), buf));
}

RAII_INLINE bool is_pkey(void_t self) {
    return is_type(self, (raii_type)ASIO_SSL_PKEY);
}

RAII_INLINE bool is_cert_req(void_t self) {
    return is_type(self, (raii_type)ASIO_SSL_REQ);
}

RAII_INLINE bool is_cert(void_t self) {
    return is_type(self, (raii_type)ASIO_SSL_CERT);
}

static void cert_names_setup(void) {
	string name = (string)asio_hostname();
	if (is_str_empty((string_t)asio_cert)) {
		if (!(snprintf(asio_cert, sizeof(asio_cert), "%s.crt", name))
		|| !(snprintf(asio_csr, sizeof(asio_csr), "%s.csr", name))
		|| !(snprintf(asio_pkey, sizeof(asio_pkey), "%s.key", name))
		|| !(snprintf(asio_self_touch, sizeof(asio_self_touch), "%s.local", name)))
			RAII_INFO("Invalid certificate %s names: %s, %s, %s\n", name, asio_cert, asio_csr, asio_pkey);
	}
}

void use_ca_certificate(string_t path) {
	if (is_str_empty((string_t)asio_ca_cert)) {
		int r = is_empty((void_t)path)
			? snprintf(asio_ca_cert, sizeof(asio_ca_cert), "%s", X509_get_default_cert_file())
			: snprintf(asio_ca_cert, sizeof(asio_ca_cert), "%s", path);

		if (!r) {
			RAII_LOG("Invalid ca trust certificate");
		}
	}
}

RAII_INLINE string_t ca_cert_file(void) {
	if (is_str_empty((string_t)asio_ca_cert))
		use_ca_certificate(nullptr);

	return (string_t)asio_ca_cert;
}

RAII_INLINE string_t cert_file(void) {
	if (is_str_empty((string_t)asio_cert))
		cert_names_setup();

	return (string_t)asio_cert;
}

static string_t default_cert_file(string path) {
	string name = (string)asio_hostname();
#ifdef _WIN32
	string dir = is_empty(path) ? "..\\" : path;
#else
	string dir = is_empty(path) ? "../" : path;
#endif
	if (is_str_empty((string_t)asio_directory)) {
		if (!(snprintf(asio_directory, sizeof(asio_directory), "%s", dir))
			|| !(snprintf(asio_cert, sizeof(asio_cert), "%s%s.crt", asio_directory, name))
			|| !(snprintf(asio_csr, sizeof(asio_csr), "%s%s.csr", asio_directory, name))
			|| !(snprintf(asio_pkey, sizeof(asio_pkey), "%s%s.key", asio_directory, name)))
			RAII_INFO("Invalid certificate %s names: %s, %s, %s, %s\n",
			name, asio_cert, asio_csr, asio_pkey, asio_directory);
	}

	if (is_empty(path)
		&& (snprintf(asio_self_touch, sizeof(asio_self_touch), "%s.local", name)))
		return (string_t)asio_self_touch;

	return (string_t)asio_cert;
}

RAII_INLINE string_t csr_file(void) {
	if (is_str_empty((string_t)asio_csr))
		cert_names_setup();

	return (string_t)asio_csr;
}

RAII_INLINE string_t pkey_file(void) {
	if (is_str_empty((string_t)asio_pkey))
		cert_names_setup();

	return (string_t)asio_pkey;
}

void use_certificate(string path, u32 ctx_pairs, ...) {
	if (is_empty(path)) {
		if (!file_exists(default_cert_file(path))) {
			if (x509_self_export(nullptr, nullptr, asio_directory))
				fs_touch(asio_self_touch);
		}
	} else {
		default_cert_file(path);
	}
}

void ASIO_ssl_init(void) {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr);

    /* Determine default SSL configuration file */
    string config_filename = getenv("OPENSSL_CONF");
    if (config_filename == nullptr) {
        config_filename = getenv("SSLEAY_CONF");
    }

    /* default to 'openssl.cnf' if no environment variable is set */
    if (config_filename == nullptr) {
        snprintf(default_ssl_conf_filename, sizeof(default_ssl_conf_filename), "%s/%s",
                 X509_get_default_cert_area(),
                 "openssl.cnf");
    } else {
        snprintf(default_ssl_conf_filename, sizeof(default_ssl_conf_filename), "%s", config_filename);
    }
}
