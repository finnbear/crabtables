# 🦀 crabtables

[![crates.io](https://img.shields.io/crates/v/crabtables.svg)](https://crates.io/crates/crabtables)
[![docs.rs](https://docs.rs/crabtables/badge.svg)](https://docs.rs/crabtables)
[![CI](https://github.com/finnbear/crabtables/actions/workflows/ci.yml/badge.svg)](https://github.com/finnbear/crabtables/actions/workflows/ci.yml)

A pure-Rust interface to **nf_tables** (the Linux nftables kernel API),
**NFLOG** and **NFQUEUE**, replacing libnftnl/libmnl. No C dependencies.

**Sync and async**: blocking sockets, tokio sockets (feature `tokio`), and
a sans-IO core for any other runtime.

## 📦 Modules

* **crate root**: sockets, atomic `Batch`es with precise per-operation
  errors, typed tables/chains/rules/sets/objects/flowtables, `RuleBuilder`,
  ruleset snapshots, counters with reset.
* **`expr`**: every kernel expression, 1:1 with the kernel ABI.
* **`proto`**: the sans-IO request/response core.
* **`monitor`**: ruleset change notifications and packet traces.
* **`nflog`**: NFLOG on dedicated sockets with overflow (loss) accounting.
* **`nfqueue`**: NFQUEUE packet verdicts.
* **`nl`**, **`sys`**, **`udata`**: netlink encoding, kernel constants, rule
  and set user data.
* **`json`** (feature `json`): lossless serde JSON of all objects.
* **`lang`** (features `lang`, `lang_json`): the nft language — parser,
  compiler to batches (same bytecode as `nft`), printer of `nft list`
  output, and nft's JSON format.

## 🖥️ nfcrt

An `nft`-compatible command line tool built on `lang` (crate
[`nfcrt`](https://crates.io/crates/nfcrt)). Install it system-wide, where
`sudo` finds it:

```sh
sudo cargo install --root /usr/local nfcrt
```

Like `nft`, it needs `CAP_NET_ADMIN`. Granting that capability to the binary
allows a user installation that runs without `sudo` (for everyone who can
execute the binary; its file system must not be mounted `nosuid`):

```sh
cargo install nfcrt
sudo setcap cap_net_admin+ep ~/.cargo/bin/nfcrt
```

## 🏎️ Performance

The same nft-syntax rulesets loaded and listed by crabtables (typed API, and
the in-process `lang` text API), libnftables (the nftables project's
in-process API), and the `nfcrt` and `nft` commands. Medians of three runs,
release build, nftables 1.1.3 (`nft` and libnftables), kernel 6.12,
measured with the
[benchmark harness](https://github.com/finnbear/crabtables/blob/main/examples/bench.rs):

| operation                 | crabtables (typed) | crabtables (`lang`) | libnftables | `nfcrt` | `nft`  |
|---------------------------|-------------------:|--------------------:|------------:|--------:|-------:|
| load 200 000 set elements |             283 ms |              471 ms |      754 ms |  608 ms | 917 ms |
| list 200 000 set elements |             1.52 s |              1.85 s |      1.92 s |  1.94 s | 3.33 s |
| load 20 000 rules         |             308 ms |              361 ms |      560 ms |  443 ms | 533 ms |
| list 20 000 rules         |              97 ms |              143 ms |      181 ms |  188 ms | 407 ms |
| single-rule transaction   |              91 µs |               97 µs |      172 µs |  1.7 ms | 3.2 ms |

## 🔬 How it was made

Written by Claude Opus 5.5 from roughly 30 prompts with moderate guidance.
A black-box reimplementation: no libnftnl, libmnl or nftables source was
used. Interoperability comes from the kernel's UAPI header information
(constants are checked against the headers) and from comparing behavior with
the `nft` tool and the kernel. Tests need root and run in throwaway network
namespaces (`sudo cargo test --workspace --all-features`).

## ⚖️ License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 🤝 Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
