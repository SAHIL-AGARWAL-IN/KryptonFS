# Deploying KryptonFS on a server

This sets up KryptonFS on one Linux server (a cloud VM or VPS) for a few
people who share one console password:

- three storage nodes and the client daemon, in one container
- the Krypton Console in production mode: password sign-in, sessions that
  expire after 12 hours, throttled login attempts, no attack lab
- [Caddy](https://caddyserver.com) in front, with an HTTPS certificate it
  obtains and renews by itself

The volume passphrase is never stored on the server. After every start the
volume is locked, and someone who knows the passphrase unlocks it from the
console's **Cluster** page.

## What you need

- A server running Ubuntu 22.04 or 24.04 with at least 2 GB of memory, and
  SSH access to it
- A domain name (for example `vault.example.com`) whose DNS **A** record
  points at the server's public IP address
- [Docker Engine with the Compose plugin](https://docs.docker.com/engine/install/ubuntu/)
  installed on the server

## Setup

All commands run on the server.

**1. Firewall.** Allow only SSH and the web ports.

```sh
sudo ufw allow OpenSSH
sudo ufw allow 80,443/tcp
sudo ufw allow 443/udp
sudo ufw enable
```

Only Caddy publishes ports; the console and the storage nodes are not
reachable from outside the server.

**2. Get the code and configure it.**

```sh
git clone https://github.com/SAHIL-AGARWAL-IN/KryptonFS.git
cd KryptonFS/deploy
cp .env.example .env
chmod 600 .env
nano .env            # set KFS_DOMAIN
docker compose build
```

**3. Choose the console password** that you will share with your team. Use
at least 12 characters.

```sh
docker compose run --rm kryptonfs hash-password
```

Paste the printed line into `.env` as `KFS_WEB_PASSWORD_HASH`, inside
single quotes (the hash contains `$` signs):

```sh
KFS_WEB_PASSWORD_HASH='pbkdf2_sha256$600000$...'
```

The hash cannot be turned back into the password, but keep `.env` private
anyway.

**4. Create the encrypted volume.** This makes the node keys and asks for
the **volume passphrase** twice. Pick a long one and store it in a password
manager: if it is lost, the files cannot be recovered by anyone.

```sh
docker compose run --rm kryptonfs init
```

**5. Start it.**

```sh
docker compose up -d
```

Open `https://<your domain>`, sign in with the console password, go to
**Cluster** and unlock the volume with its passphrase. Everyone who signs
in now sees the same files.

## Day to day

| Task | How |
|------|-----|
| Watch the logs | `docker compose logs -f` |
| After a reboot or restart | The volume is locked again: unlock it from **Cluster**. |
| Lock the volume now | **Cluster → Lock volume** |
| Change the console password | Run `hash-password` again, replace the line in `.env`, then `docker compose up -d`. Everyone has to sign in again. |
| Update KryptonFS | `git pull && docker compose build && docker compose up -d` |
| Stop everything | `docker compose down` (the data stays in its volume) |

### Backups

Everything (node keys, configs and every node's encrypted blocks) lives in
the Docker volume `kryptonfs_kryptonfs-state`. Back it up while the service
is stopped, so no write is half done:

```sh
docker compose stop kryptonfs
docker run --rm -v kryptonfs_kryptonfs-state:/state -v "$PWD":/backup ubuntu:24.04 \
    tar czf /backup/kryptonfs-state-$(date +%F).tgz -C /state .
docker compose start kryptonfs
```

The file contents in a backup stay encrypted under the volume passphrase,
but the backup also holds the node keys, so store it as carefully as the
server itself. Restore by extracting the archive into an empty volume of
the same name.

## What this protects, and what it does not

- **Protected:** files are encrypted before they reach the storage nodes,
  and the key exists only in the sandboxed crypto workers while the volume
  is unlocked. A damaged or tampered copy of a block is detected and another
  copy is used (it also shows in the console's security events). The
  console is reachable only over HTTPS, behind the shared password.
- **Not protected:** all three nodes run on this one server, so the copies
  guard against a corrupted block, not against losing the server or its
  disk. Make backups, or run nodes on other machines (below).
- **Anyone who can sign in** can read, change and delete every file, stop
  storage servers and lock the volume. Share the password only with people
  you would give all of that to. To hide the server controls, set
  `KFS_WEB_ALLOW_NODE_CONTROL=false` in the `environment:` section of
  `docker-compose.yml`.
- **The container is privileged enough to mount filesystems** (FUSE needs
  `SYS_ADMIN`, and AppArmor's default container profile forbids mounts).
  Give the server to KryptonFS alone rather than sharing it with unrelated
  services.

## Storage nodes on other machines

The setup above keeps every copy on one server. To place nodes elsewhere:

1. Connect the machines over a private network (for example WireGuard), and
   allow the node ports (`7410`–`7431` by default) only on that network.
2. On each new machine, build KryptonFS (see the main README), create its
   identity with `kfs-keygen node <id> <dir>`, and copy the cluster key
   `/var/lib/kryptonfs/cluster.key` to it over SSH.
3. Put every node's public key (`<id>.pub.pem`) into every host's
   `trusted/` directory, and list every node as a `peer` line in every
   config, using the private addresses. `config/kryptonfs.conf.example`
   documents each setting.
4. Run `kfs-noded -c <config>` there under a service manager such as
   systemd.

The console shows remote nodes and their health, but marks them as
running elsewhere: start and stop them on their own machines.

## Troubleshooting

- **`fuse: device not found` or `mount: permission denied`.** The host
  needs the `fuse` kernel module (`sudo modprobe fuse`), and the container
  needs the `devices`, `cap_add` and `security_opt` lines from
  `docker-compose.yml`.
- **The browser warns about the certificate, or Caddy's log shows ACME
  errors.** Check that the DNS record points at this server and that ports
  80 and 443 are open in the firewall and at your cloud provider.
- **"Too many attempts" at sign-in.** After five wrong passwords from one
  address, each further try waits longer (up to 15 minutes).
- **Node logs.** `docker compose exec kryptonfs tail -n 50 /var/lib/kryptonfs/node1.log`,
  or open **Cluster** with **Advanced** on.
