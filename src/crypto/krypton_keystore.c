/*
 * krypton_keystore.c - RSA-2048 identities (OpenSSL 3) and secret files.
 */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L /* open, fdopen, fileno, fstat */
#endif

#include "krypton/krypton_keystore.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

struct kfs_identity {
    EVP_PKEY *pkey;
    bool      has_private;
};

static void set_err(char *err, size_t errlen, const char *fmt, ...) KFS_PRINTF_FMT(3, 4);

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Creates path for writing, failing if it exists. Secrets get mode 0600;
 * public files 0644. */
static FILE *create_exclusive(const char *path, bool secret)
{
#if defined(_WIN32)
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
    FILE *fp;

    (void)secret;
    if (fd < 0)
        return NULL;
    fp = _fdopen(fd, "wb");
    if (fp == NULL)
        _close(fd);
    return fp;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  secret ? 0600 : 0644);
    FILE *fp;

    if (fd < 0)
        return NULL;
    fp = fdopen(fd, "wb");
    if (fp == NULL)
        close(fd);
    return fp;
#endif
}

/* Opens a secret for reading; on POSIX, refuses one that group or others
 * can access, as ssh does for private keys. */
static FILE *open_secret(const char *path, char *err, size_t errlen)
{
    FILE *fp = fopen(path, "rb");

    if (fp == NULL) {
        set_err(err, errlen, "%s: %s", path, strerror(errno));
        return NULL;
    }
#if !defined(_WIN32)
    {
        struct stat st;

        if (fstat(fileno(fp), &st) != 0 || (st.st_mode & 077) != 0) {
            set_err(err, errlen, "%s: accessible by group or others (chmod 600)", path);
            fclose(fp);
            return NULL;
        }
    }
#endif
    return fp;
}

/* Never prompt on the terminal for an encrypted PEM; fail instead. */
static int no_passphrase(char *buf, int size, int rwflag, void *u)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    return -1;
}

static bool is_rsa2048(const EVP_PKEY *pkey)
{
    return EVP_PKEY_is_a(pkey, "RSA") && EVP_PKEY_get_bits(pkey) == KFS_RSA_BITS;
}

static kfs_status wrap(EVP_PKEY *pkey, bool has_private, kfs_identity **out)
{
    kfs_identity *id = OPENSSL_zalloc(sizeof(*id));

    if (id == NULL) {
        EVP_PKEY_free(pkey);
        return KFS_E_NOMEM;
    }
    id->pkey = pkey;
    id->has_private = has_private;
    *out = id;
    return KFS_OK;
}

kfs_status kfs_identity_generate(kfs_identity **out)
{
    EVP_PKEY *pkey = EVP_RSA_gen(KFS_RSA_BITS);

    if (pkey == NULL) {
        ERR_clear_error();
        return KFS_E_CRYPTO;
    }
    return wrap(pkey, true, out);
}

void kfs_identity_free(kfs_identity *id)
{
    if (id == NULL)
        return;
    EVP_PKEY_free(id->pkey);
    OPENSSL_free(id);
}

static kfs_status load(const char *path, bool private_key, kfs_identity **out,
                       char *err, size_t errlen)
{
    FILE *fp = private_key ? open_secret(path, err, errlen) : fopen(path, "rb");
    EVP_PKEY *pkey;

    if (fp == NULL) {
        if (!private_key)
            set_err(err, errlen, "%s: %s", path, strerror(errno));
        return KFS_E_IO;
    }
    pkey = private_key ? PEM_read_PrivateKey(fp, NULL, no_passphrase, NULL)
                       : PEM_read_PUBKEY(fp, NULL, no_passphrase, NULL);
    fclose(fp);
    ERR_clear_error();

    if (pkey == NULL) {
        set_err(err, errlen, "%s: not an unencrypted PEM %s key", path,
                private_key ? "private" : "public");
        return KFS_E_CRYPTO;
    }
    if (!is_rsa2048(pkey)) {
        set_err(err, errlen, "%s: not an RSA-%d key", path, KFS_RSA_BITS);
        EVP_PKEY_free(pkey);
        return KFS_E_CRYPTO;
    }
    return wrap(pkey, private_key, out);
}

kfs_status kfs_identity_load_private(const char *path, kfs_identity **out,
                                     char *err, size_t errlen)
{
    return load(path, true, out, err, errlen);
}

kfs_status kfs_identity_load_public(const char *path, kfs_identity **out,
                                    char *err, size_t errlen)
{
    return load(path, false, out, err, errlen);
}

kfs_status kfs_identity_load_peer(const char *trusted_dir, uint32_t node_id,
                                  kfs_identity **out, char *err, size_t errlen)
{
    char path[KFS_PATH_MAX + 32];
    int n = snprintf(path, sizeof(path), "%s/%u.pub.pem", trusted_dir, node_id);

    if (n < 0 || (size_t)n >= sizeof(path)) {
        set_err(err, errlen, "trusted key path too long");
        return KFS_E_INVAL;
    }
    return load(path, false, out, err, errlen);
}

static kfs_status save(const kfs_identity *id, const char *path, bool private_key)
{
    FILE *fp;
    int ok;

    if (private_key && !id->has_private)
        return KFS_E_INVAL;
    fp = create_exclusive(path, private_key);
    if (fp == NULL)
        return KFS_E_IO;
    ok = private_key ? PEM_write_PrivateKey(fp, id->pkey, NULL, NULL, 0, NULL, NULL)
                     : PEM_write_PUBKEY(fp, id->pkey);
    if (fclose(fp) != 0)
        ok = 0;
    if (ok != 1) {
        ERR_clear_error();
        remove(path);
        return KFS_E_IO;
    }
    return KFS_OK;
}

kfs_status kfs_identity_save_private(const kfs_identity *id, const char *path)
{
    return save(id, path, true);
}

kfs_status kfs_identity_save_public(const kfs_identity *id, const char *path)
{
    return save(id, path, false);
}

/* Sets up RSA-PSS / SHA-256 / digest-length salt on a sign or verify ctx. */
static bool pss_init(EVP_MD_CTX *md, const kfs_identity *id, bool sign)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ok = sign ? EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, id->pkey)
                  : EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), NULL, id->pkey);

    return ok == 1 &&
           EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
           EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1;
}

kfs_status kfs_identity_sign(const kfs_identity *id, const uint8_t *msg,
                             size_t len, uint8_t sig[KFS_RSA_SIG_SIZE])
{
    EVP_MD_CTX *md;
    size_t sig_len = KFS_RSA_SIG_SIZE;
    kfs_status st = KFS_E_CRYPTO;

    if (!id->has_private)
        return KFS_E_INVAL;
    md = EVP_MD_CTX_new();
    if (md != NULL && pss_init(md, id, true) &&
        EVP_DigestSign(md, sig, &sig_len, msg, len) == 1 &&
        sig_len == KFS_RSA_SIG_SIZE)
        st = KFS_OK;
    EVP_MD_CTX_free(md);
    ERR_clear_error();
    return st;
}

kfs_status kfs_identity_verify(const kfs_identity *id, const uint8_t *msg,
                               size_t len, const uint8_t sig[KFS_RSA_SIG_SIZE])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    kfs_status st;

    if (md == NULL)
        return KFS_E_NOMEM;
    if (!pss_init(md, id, false))
        st = KFS_E_CRYPTO;
    else if (EVP_DigestVerify(md, sig, KFS_RSA_SIG_SIZE, msg, len) == 1)
        st = KFS_OK;
    else
        st = KFS_E_AUTH;
    EVP_MD_CTX_free(md);
    ERR_clear_error();
    return st;
}

kfs_status kfs_identity_fingerprint(const kfs_identity *id,
                                    uint8_t out[KFS_FINGERPRINT_SIZE])
{
    unsigned char *der = NULL;
    unsigned int out_len = 0;
    int n = i2d_PUBKEY(id->pkey, &der);
    kfs_status st = KFS_E_CRYPTO;

    if (n > 0 &&
        EVP_Digest(der, (size_t)n, out, &out_len, EVP_sha256(), NULL) == 1 &&
        out_len == KFS_FINGERPRINT_SIZE)
        st = KFS_OK;
    OPENSSL_free(der);
    return st;
}

kfs_status kfs_secret_write(const char *path, const uint8_t *data, size_t len)
{
    FILE *fp = create_exclusive(path, true);
    bool ok;

    if (fp == NULL)
        return KFS_E_IO;
    ok = fwrite(data, 1, len, fp) == len;
    if (fclose(fp) != 0)
        ok = false;
    if (!ok) {
        remove(path);
        return KFS_E_IO;
    }
    return KFS_OK;
}

kfs_status kfs_secret_read(const char *path, uint8_t *data, size_t len,
                           char *err, size_t errlen)
{
    FILE *fp = open_secret(path, err, errlen);
    size_t n;
    int extra;

    if (fp == NULL)
        return KFS_E_IO;
    n = fread(data, 1, len, fp);
    extra = fgetc(fp);
    fclose(fp);
    if (n != len || extra != EOF) {
        OPENSSL_cleanse(data, len);
        set_err(err, errlen, "%s: expected exactly %zu bytes", path, len);
        return KFS_E_CONFIG;
    }
    return KFS_OK;
}
