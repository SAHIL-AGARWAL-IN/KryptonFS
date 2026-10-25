/*
 * krypton_keystore.h - RSA-2048 node identities and secret key files.
 *
 * Every host (client or storage node) owns one RSA-2048 key pair. Peers
 * are trusted only by pinning: [crypto] trusted_keys holds one
 * <node_id>.pub.pem per peer, and a handshake signed by any other key is
 * refused. Signatures are RSA-PSS with SHA-256 and a digest-length salt.
 *
 * Private keys and the cluster key are stored unencrypted; protection is
 * the file mode. Writers create them 0600 and refuse to overwrite; on
 * POSIX, readers refuse files that group or others can access.
 */
#ifndef KRYPTON_KEYSTORE_H
#define KRYPTON_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"

#define KFS_RSA_BITS        2048
#define KFS_RSA_SIG_SIZE    256u
#define KFS_FINGERPRINT_SIZE 32u /* SHA-256 of the DER SubjectPublicKeyInfo */

typedef struct kfs_identity kfs_identity;

kfs_status kfs_identity_generate(kfs_identity **out);
void kfs_identity_free(kfs_identity *id);

/* Loaders accept only RSA keys of exactly KFS_RSA_BITS. */
kfs_status kfs_identity_load_private(const char *path, kfs_identity **out,
                                     char *err, size_t errlen);
kfs_status kfs_identity_load_public(const char *path, kfs_identity **out,
                                    char *err, size_t errlen);

/* Loads <trusted_dir>/<node_id>.pub.pem. */
kfs_status kfs_identity_load_peer(const char *trusted_dir, uint32_t node_id,
                                  kfs_identity **out, char *err, size_t errlen);

/* PEM writers. Fail with KFS_E_IO if path already exists. */
kfs_status kfs_identity_save_private(const kfs_identity *id, const char *path);
kfs_status kfs_identity_save_public(const kfs_identity *id, const char *path);

/* KFS_E_INVAL when signing with a public-only identity. */
kfs_status kfs_identity_sign(const kfs_identity *id, const uint8_t *msg,
                             size_t len, uint8_t sig[KFS_RSA_SIG_SIZE]);

/* KFS_OK for a valid signature, KFS_E_AUTH otherwise. */
kfs_status kfs_identity_verify(const kfs_identity *id, const uint8_t *msg,
                               size_t len, const uint8_t sig[KFS_RSA_SIG_SIZE]);

kfs_status kfs_identity_fingerprint(const kfs_identity *id,
                                    uint8_t out[KFS_FINGERPRINT_SIZE]);

/* Raw secret files such as the 32-byte cluster key. Writes create 0600
 * and never overwrite; reads require exactly len bytes. */
kfs_status kfs_secret_write(const char *path, const uint8_t *data, size_t len);
kfs_status kfs_secret_read(const char *path, uint8_t *data, size_t len,
                           char *err, size_t errlen);

#endif /* KRYPTON_KEYSTORE_H */
