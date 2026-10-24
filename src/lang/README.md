The nftables language (feature `lang`): nft scripts and commands in, kernel
objects out, and back.

* [`parse`]: parser of nft syntax into an [`ast`].
* [`compile`]: compiler of commands to a [`Batch`](crate::Batch), with the
  same bytecode as `nft`.
* [`decompile`] and [`print`](mod@print): rulesets back to the AST and to the text of
  `nft list`; [`list`] runs `list` commands.
* `json` (feature `lang_json`): nft's JSON format (`nft -j`), in both
  directions.
* [`monitor`], [`describe`], [`netdebug`]: the output of `nft monitor` and
  `--echo`, `nft describe`, and `nft --debug=netlink`.

```rust,no_run
use crabtables::lang::{compile::Compiler, list_ruleset, parse};
use crabtables::{Family, Socket};

let cmds = parse::parse("table inet f { chain c { tcp dport 22 accept; }; }")?;
let mut sock = Socket::new()?;
let mut c = Compiler::new();
c.learn(&sock.list_ruleset(Family::Unspec)?); // existing tables, chains, sets
c.compile(&cmds)?;
sock.commit(&c.into_batch().0)?;
print!("{}", list_ruleset(&sock.list_ruleset(Family::Unspec)?, &Default::default()));
# Ok::<(), Box<dyn std::error::Error>>(())
```

# Blocking I/O

Like `nft`, this module reads system files to translate names and values.
The reads block (usually briefly); in async code, call it from a blocking
context (e.g. `tokio::task::spawn_blocking`) if that matters.

* **Once per process** (cached, so later changes are not seen):
  `/etc/services`, `/etc/protocols`, the iproute2 tables `group` and
  `rt_realms`, the time zone, and when needed `/etc/passwd` and
  `/etc/group` (user and group names) and `/etc/hosts`
  ([`Opts::reverse_dns`]).
* **On each use:** files named by `include` statements (and the
  directories searched for them), `/proc/<pid>/comm` for tables owned by a
  process, and interface name/index lookups (`if_nametoindex`,
  `if_indextoname`).

No network lookups are made.
