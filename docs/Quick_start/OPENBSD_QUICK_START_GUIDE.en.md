# Telemt on OpenBSD (Build, Run, and rc.d)

This guide covers a practical OpenBSD deployment flow for Telemt:
- build from source,
- install binary and config,
- run as an rc.d daemon,
- verify basic runtime behavior.

## 1. Prerequisites

Install required packages:

```sh
doas pkg_add rust git
```

Notes:
- Telemt release installer (`install.sh`) is Linux-only.
- On OpenBSD, use source build with `cargo`.

## 2. Build from source

```sh
git clone https://github.com/telemt/telemt
cd telemt
cargo build --release
./target/release/telemt --version
```

For low-RAM systems, note that this repository currently uses `lto = "fat"` in release profile.  
On constrained builders, a local override to `lto = "thin"` may be more practical.

## 3. Install binary and config

```sh
doas install -d -m 0755 /usr/local/bin
doas install -m 0755 ./target/release/telemt /usr/local/bin/telemt

doas install -d -m 0750 /etc/telemt
doas install -m 0640 ./config.toml /etc/telemt/config.toml
```

## 4. Create runtime user

```sh
doas useradd -L daemon -s /sbin/nologin -d /var/empty _telemt
```

If `_telemt` already exists, continue.

## 5. Install rc.d service

Install the provided script:

```sh
doas install -m 0555 ./contrib/openbsd/telemt.rcd /etc/rc.d/telemt
```

Enable and start:

```sh
doas rcctl enable telemt
# Optional: send daemon output to syslog
#doas rcctl set telemt logger daemon.info

doas rcctl start telemt
```

Service controls:

```sh
doas rcctl check telemt
doas rcctl restart telemt
doas rcctl stop telemt
```

## 6. Resource limits (recommended)

OpenBSD rc.d can apply limits via login class. Add class `telemt` and assign it to `_telemt`.

Example class entry:

```text
telemt:\
    :openfiles-cur=8192:openfiles-max=16384:\
    :datasize-cur=768M:datasize-max=1024M:\
    :coredumpsize=0:\
    :tc=daemon:
```

These values are conservative defaults for small and medium deployments.
Increase `openfiles-*` only if logs show descriptor exhaustion under load.

Then rebuild database and assign class:

```sh
doas cap_mkdb /etc/login.conf
#doas usermod -L telemt _telemt
```

Uncomment `usermod` if you want this class bound to the Telemt user.

## 7. Functional smoke test

1. Validate service state:

```sh
doas rcctl check telemt
```

2. Check listener is present (replace 443 if needed):

```sh
netstat -n -f inet -p tcp | grep LISTEN | grep '\.443'
```

3. Verify process user:

```sh
ps -o user,pid,command -ax | grep telemt | grep -v grep
```

4. If startup fails, debug in foreground:

```sh
RUST_LOG=debug /usr/local/bin/telemt /etc/telemt/config.toml
```

## 8. OpenBSD-specific caveats

- OpenBSD does not support per-socket keepalive retries/interval tuning in the same way as Linux.
- Telemt source already uses target-aware cfg gates for keepalive setup.
- Use rc.d/rcctl, not systemd.
