/*
 * krypton_net_backend.h - The replicated cluster as a kfs_backend.
 */
#ifndef KRYPTON_NET_BACKEND_H
#define KRYPTON_NET_BACKEND_H

#include "krypton_backend.h"
#include "krypton_cluster.h"
#include "krypton_config.h"

/* Loads this host's identity ([crypto] node_key, authenticating as
 * [node] id), pins every peer's key and starts heartbeats. */
kfs_status kfs_backend_open_cluster(const kfs_config *cfg, kfs_backend **out,
                                    char *err, size_t errlen);

/* The cluster backend's live health table (for telemetry), else NULL. */
kfs_health *kfs_backend_cluster_health(kfs_backend *b);

#endif /* KRYPTON_NET_BACKEND_H */
