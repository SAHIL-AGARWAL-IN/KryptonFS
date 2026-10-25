/*
 * krypton_common.c - Status code descriptions.
 */
#include "krypton/krypton_common.h"

const char *kfs_strerror(kfs_status st)
{
    switch (st) {
    case KFS_OK:            return "success";
    case KFS_E_INVAL:       return "invalid argument";
    case KFS_E_NOMEM:       return "out of memory";
    case KFS_E_IO:          return "I/O error";
    case KFS_E_PROTO:       return "protocol violation";
    case KFS_E_AUTH:        return "authentication failed";
    case KFS_E_CRYPTO:      return "cryptographic failure";
    case KFS_E_MALWARE:     return "rejected by malware scanner";
    case KFS_E_NOT_FOUND:   return "not found";
    case KFS_E_TIMEOUT:     return "timed out";
    case KFS_E_UNAVAILABLE: return "no healthy replica available";
    case KFS_E_CONFIG:      return "configuration error";
    }
    return "unknown status";
}
