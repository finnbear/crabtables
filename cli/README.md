# 🦀 nfcrt

[![crates.io](https://img.shields.io/crates/v/nfcrt.svg)](https://crates.io/crates/nfcrt)
[![CI](https://github.com/finnbear/crabtables/actions/workflows/ci.yml/badge.svg)](https://github.com/finnbear/crabtables/actions/workflows/ci.yml)

A pure-Rust nftables command line tool, compatible with `nft`. It has no C
dependencies (no libnftables, libnftnl, or libmnl) and is built on
[crabtables](https://crates.io/crates/crabtables).

It accepts the same commands, rulesets and options as `nft`, and prints the
same output, errors, and JSON:

```sh
nfcrt add table inet filter
nfcrt add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
nfcrt add rule inet filter input tcp dport 22 counter accept
nfcrt list ruleset
nfcrt -f /etc/nftables.conf
nfcrt -j list ruleset
nfcrt monitor
```

The only `nft` option it doesn't support is `-o`/`--optimize`.

## 📦 Installation

Install it system-wide, where `sudo` finds it:

```sh
sudo cargo install --root /usr/local nfcrt
```

Like `nft`, it needs `CAP_NET_ADMIN`. You can instead install it for your
user and grant that capability to the binary, so it runs without `sudo`.
Everyone who can execute the binary then gets the capability, and the binary's
file system must not be mounted `nosuid`:

```sh
cargo install nfcrt
sudo setcap cap_net_admin+ep ~/.cargo/bin/nfcrt
```

## 🏎️ Performance

Medians of three runs: release build, nftables 1.1.3, kernel 6.12.

| operation                 | `nfcrt` | `nft`  |
|---------------------------|--------:|-------:|
| load 200 000 set elements |  608 ms | 917 ms |
| list 200 000 set elements |  1.94 s | 3.33 s |
| load 20 000 rules         |  443 ms | 533 ms |
| list 20 000 rules         |  188 ms | 407 ms |
| single-rule transaction   |  1.7 ms | 3.2 ms |

## 🔬 How it was made

Written by Claude Opus 5.5 from roughly 30 prompts with moderate guidance.
A black-box reimplementation: no libnftnl, libmnl, or nftables source was
used. Interoperability comes from the kernel's UAPI header information
(constants are checked against the headers) and from comparing behavior with
the `nft` tool and the kernel. Tests need root and run in throwaway network
namespaces (`sudo cargo test --workspace --all-features`).

## ⚖️ License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](https://github.com/finnbear/crabtables/blob/main/LICENSE-APACHE)
   or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](https://github.com/finnbear/crabtables/blob/main/LICENSE-MIT)
   or http://opensource.org/licenses/MIT)

at your option.

## 🤝 Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
