/*
 * krypton_passphrase.h - Reading the volume passphrase.
 *
 * Sources, in order:
 *   1. $KRYPTONFS_PASSPHRASE, for automation. It is read once and removed
 *      from the environment, but it was visible to anything that could
 *      read this process's environment before that; prefer the others.
 *   2. The controlling terminal, with echo disabled.
 *   3. One line on stdin, for piping from a secret manager.
 */
#ifndef KRYPTON_PASSPHRASE_H
#define KRYPTON_PASSPHRASE_H

#include <stdbool.h>
#include <stddef.h>

#include "krypton_common.h"

#define KFS_PASSPHRASE_MAX 1024

/* Stores the passphrase NUL-terminated in buf and its length in *len.
 * With confirm, a terminal prompt asks twice and fails on mismatch. */
kfs_status kfs_read_passphrase(const char *prompt, bool confirm,
                               char *buf, size_t cap, size_t *len);

#endif /* KRYPTON_PASSPHRASE_H */
