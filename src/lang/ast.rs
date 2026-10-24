//! Abstract syntax of the nft language.
//!
//! The same types describe parsed input (scripts and commands) and
//! decompiled kernel state, so that listings are printed from, and JSON is
//! generated from, one representation.

use crate::Family;

/// A position in the input, for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Span {
    /// Byte offset of the start.
    pub start: usize,
    /// Byte offset of the end.
    pub end: usize,
}

/// A value literal or a typed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Text as written by the user, interpreted once its type is known
    /// (number, symbol, address, quoted string).
    Raw(String),
    /// Bytes of a known type (from the kernel or after evaluation).
    Typed {
        /// Data type id.
        ty: u32,
        /// Bytes as compared by the kernel.
        bytes: Vec<u8>,
        /// Width of the field in bits.
        bits: u32,
    },
}

/// Binary operators of expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `&`
    And,
    /// `|`
    Or,
    /// `^`
    Xor,
    /// `<<`
    Lshift,
    /// `>>`
    Rshift,
}

impl BinOp {
    /// Operator text.
    pub fn as_str(self) -> &'static str {
        match self {
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::Lshift => "<<",
            BinOp::Rshift => ">>",
        }
    }
}

/// Relational operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelOp {
    /// No operator written (`tcp dport 22`, `ct state new`).
    Implicit,
    /// `==`
    Eq,
    /// `!=`
    Neq,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Lte,
    /// `>=`
    Gte,
    /// Flag test written with a slash: `tcp flags syn / syn,ack`.
    Mask,
}

impl RelOp {
    /// Operator text (empty for implicit).
    pub fn as_str(self) -> &'static str {
        match self {
            RelOp::Implicit => "",
            RelOp::Eq => "==",
            RelOp::Neq => "!=",
            RelOp::Lt => "<",
            RelOp::Gt => ">",
            RelOp::Lte => "<=",
            RelOp::Gte => ">=",
            RelOp::Mask => "/",
        }
    }
}

/// A verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// `accept`
    Accept,
    /// `drop`
    Drop,
    /// `continue`
    Continue,
    /// `return`
    Return,
    /// `jump <chain>`
    Jump(String),
    /// `goto <chain>`
    Goto(String),
    /// Inline anonymous chain `jump { ... }` (binding chain).
    JumpBlock(Vec<Rule>),
    /// Inline anonymous chain `goto { ... }`.
    GotoBlock(Vec<Rule>),
    /// `queue` (as a verdict code).
    Queue,
}

/// An expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A header field (`tcp dport`, `arp saddr ip`).
    Payload {
        /// Protocol name.
        proto: String,
        /// Field name.
        field: String,
    },
    /// Raw payload bits (`@th,16,16`).
    Raw {
        /// Base: `ll`, `nh`, `th` or `ih`.
        base: String,
        /// Offset in bits.
        offset: u32,
        /// Length in bits.
        len: u32,
    },
    /// Extension header / option (`tcp option maxseg size`, `exthdr frag`).
    Exthdr {
        /// Printed description, e.g. `tcp option maxseg` or `exthdr frag`.
        desc: String,
        /// Field (`size`), if any.
        field: Option<String>,
        /// Presence test (`exists`).
        exists: bool,
    },
    /// `meta <key>` (or unqualified, like `iifname`).
    Meta(String),
    /// `ct [original|reply] <key>`.
    Ct {
        /// Direction.
        dir: Option<String>,
        /// Key (`proto-dst`, `ip saddr`).
        key: String,
    },
    /// `rt [ip|ip6] <key>`.
    Rt(String),
    /// `socket <key> [level]`.
    Socket {
        /// Key.
        key: String,
        /// cgroupv2 level.
        level: Option<u32>,
    },
    /// `osf [ttl ...] name|version`.
    Osf {
        /// `ttl loose|skip`.
        ttl: Option<String>,
        /// `version` instead of `name`.
        version: bool,
    },
    /// `fib <flags> <result>`.
    Fib {
        /// Flags (`saddr`, `iif`, ...).
        flags: Vec<String>,
        /// Result (`oif`, `oifname`, `type`).
        result: String,
    },
    /// `numgen inc|random mod N [offset M]`.
    Numgen {
        /// `inc` or `random`.
        mode: String,
        /// Modulus.
        modulus: u32,
        /// Offset.
        offset: u32,
    },
    /// `jhash <expr> mod N [seed S] [offset M]` / `symhash mod N [offset M]`.
    Hash {
        /// Input expression (jhash only).
        input: Option<Box<Expr>>,
        /// Modulus.
        modulus: u32,
        /// Seed.
        seed: Option<u32>,
        /// Offset.
        offset: u32,
    },
    /// `ipsec in|out [spnum N] <key>`.
    Ipsec {
        /// Direction.
        dir: String,
        /// Security path index.
        spnum: u32,
        /// Key (`reqid`, `spi`, `ip saddr`, ...).
        key: String,
    },
    /// Concatenation (`ip saddr . tcp dport`).
    Concat(Vec<Expr>),
    /// Binary operation.
    Binop(BinOp, Box<Expr>, Box<Expr>),
    /// A value.
    Value(Value),
    /// Prefix (`10.0.0.0/8`).
    Prefix(Box<Expr>, u32),
    /// Range (`1-1000`).
    Range(Box<Expr>, Box<Expr>),
    /// Comma separated list (flags: `established,related`).
    List(Vec<Expr>),
    /// Anonymous set `{ ... }`.
    Set(Vec<Elem>),
    /// Named set reference `@name`.
    SetRef(String),
    /// Map lookup `<key> map <set>` (the set is `Set` or `SetRef`).
    Map(Box<Expr>, Box<Expr>),
    /// Verdict (inside maps).
    Verdict(Verdict),
    /// Catch-all `*`.
    Wildcard,
    /// A variable reference (`$var`), resolved while parsing scripts.
    Variable(String),
}

impl Expr {
    /// A raw value literal.
    pub fn raw(s: impl Into<String>) -> Expr {
        Expr::Value(Value::Raw(s.into()))
    }
}

/// A set element (in sets, maps and anonymous sets).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Elem {
    /// Key (value, range, prefix, concatenation or wildcard).
    pub key: Option<Expr>,
    /// Map data.
    pub data: Option<Expr>,
    /// Element timeout in ms.
    pub timeout: Option<u64>,
    /// Remaining time in ms.
    pub expires: Option<u64>,
    /// Comment.
    pub comment: Option<String>,
    /// Stateful statements (`counter`, `limit`, ...).
    pub stmts: Vec<Stmt>,
    /// Location of the key in the input (parsed elements).
    pub span: Span,
}

impl Elem {
    /// An element with just a key.
    pub fn key(e: Expr) -> Elem {
        Elem {
            key: Some(e),
            ..Default::default()
        }
    }
}

/// Limit statement / object parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Limit {
    /// `over`.
    pub over: bool,
    /// Rate.
    pub rate: u64,
    /// Rate unit for byte limits (`bytes`, `kbytes`, `mbytes`).
    pub rate_unit: Option<String>,
    /// Time unit (`second`, `minute`, `hour`, `day`, `week`).
    pub per: String,
    /// Burst.
    pub burst: Option<u64>,
    /// Burst unit (`packets`, `bytes`, `kbytes`, `mbytes`).
    pub burst_unit: Option<String>,
}

/// Quota parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Quota {
    /// `over` (otherwise `until`).
    pub over: bool,
    /// Bytes.
    pub bytes: u64,
    /// Bytes used.
    pub used: u64,
}

/// Log statement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Log {
    /// Prefix.
    pub prefix: Option<String>,
    /// NFLOG group.
    pub group: Option<u16>,
    /// Snap length.
    pub snaplen: Option<u32>,
    /// Queue threshold.
    pub qthreshold: Option<u16>,
    /// Level name.
    pub level: Option<String>,
    /// Flags (`all`, `tcp sequence,options`, ...), as printed.
    pub flags: Option<String>,
}

/// NAT statement kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatKind {
    /// `snat`
    Snat,
    /// `dnat`
    Dnat,
    /// `masquerade`
    Masquerade,
    /// `redirect`
    Redirect,
}

/// A statement of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    /// Relational match.
    Match {
        /// Left side.
        left: Expr,
        /// Operator.
        op: RelOp,
        /// Right side.
        right: Expr,
    },
    /// Verdict.
    Verdict(Verdict),
    /// Verdict map (`<expr> vmap <set>`).
    Vmap {
        /// Key.
        key: Expr,
        /// Map (`Set` or `SetRef`).
        map: Expr,
    },
    /// `counter [packets N bytes M]`.
    Counter {
        /// Packets.
        packets: Option<u64>,
        /// Bytes.
        bytes: Option<u64>,
    },
    /// `limit rate ...`.
    Limit(Limit),
    /// `quota ...`.
    Quota(Quota),
    /// `log ...`.
    Log(Log),
    /// `ct count [over] N`.
    Connlimit {
        /// Count.
        count: u32,
        /// `over`.
        over: bool,
    },
    /// `last [used <time>|never]`.
    Last {
        /// Milliseconds since last use.
        used: Option<u64>,
    },
    /// Named object reference (`counter name "x"`, `ct helper set "x"`,
    /// `counter name ip saddr map @m`).
    Objref {
        /// Object kind as written (`counter`, `quota`, `limit`, `ct helper`,
        /// `ct timeout`, `ct expectation`, `synproxy`, `secmark`).
        kind: String,
        /// Name (a string value) or map lookup.
        name: Expr,
    },
    /// `meta <key> set <expr>` (also unqualified forms).
    MetaSet {
        /// Key.
        key: String,
        /// Value.
        value: Expr,
    },
    /// `ct [dir] <key> set <expr>`.
    CtSet {
        /// Key.
        key: String,
        /// Direction.
        dir: Option<String>,
        /// Value.
        value: Expr,
    },
    /// `<payload|exthdr> set <expr>`.
    PayloadSet {
        /// Destination.
        target: Expr,
        /// Value.
        value: Expr,
    },
    /// NAT.
    Nat {
        /// Kind.
        kind: NatKind,
        /// `ip` / `ip6` qualifier (`dnat ip to`).
        family: Option<String>,
        /// Address (value, range, map, ...).
        addr: Option<Expr>,
        /// Port (value, range, map).
        port: Option<Expr>,
        /// Flags (`random`, `persistent`, `fully-random`, `netmap`).
        flags: Vec<String>,
    },
    /// `reject [with <type> <code>]`.
    Reject {
        /// `icmp`, `icmpv6`, `icmpx` or `tcp reset`.
        with: Option<String>,
        /// Code.
        code: Option<String>,
    },
    /// `queue [flags ...] [to N[-M] | to <expr>]`.
    Queue {
        /// Flags.
        flags: Vec<String>,
        /// Queue number(s) or expression.
        num: Option<Expr>,
    },
    /// `dup to <addr> [device <dev>]`.
    Dup {
        /// Address.
        addr: Option<Expr>,
        /// Device.
        dev: Option<Expr>,
    },
    /// `fwd [ip|ip6] to <dev|addr device dev>`.
    Fwd {
        /// Family for neighbour forwarding.
        family: Option<String>,
        /// Next hop.
        addr: Option<Expr>,
        /// Device.
        dev: Expr,
    },
    /// `notrack`.
    Notrack,
    /// `flow add @ft`.
    Flow(String),
    /// `tproxy [ip|ip6] to [addr][:port]`.
    Tproxy {
        /// Family.
        family: Option<String>,
        /// Address.
        addr: Option<Expr>,
        /// Port.
        port: Option<Expr>,
    },
    /// `synproxy [mss N] [wscale N] [timestamp] [sack-perm]`.
    Synproxy {
        /// MSS.
        mss: Option<u16>,
        /// Window scale.
        wscale: Option<u8>,
        /// Flags.
        flags: Vec<String>,
    },
    /// `add|update|delete @set { key [stmts] }`, with map data for maps.
    SetUpdate {
        /// `add`, `update`, `delete`.
        op: String,
        /// Set name.
        set: String,
        /// Key.
        key: Expr,
        /// Map data.
        data: Option<Expr>,
        /// Timeout in ms.
        timeout: Option<u64>,
        /// Stateful statements.
        stmts: Vec<Stmt>,
    },
    /// `meter NAME [size N] { key [timeout T] stmts }`: an update of a
    /// dynamic set that is created if it does not exist.
    Meter {
        /// Set name.
        name: String,
        /// Maximum number of elements.
        size: Option<u32>,
        /// Key.
        key: Expr,
        /// Timeout in ms.
        timeout: Option<u64>,
        /// Stateful statements.
        stmts: Vec<Stmt>,
    },
    /// Something only printable (e.g. iptables-nft `xt` extensions).
    Opaque(String),
}

/// A rule.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    /// Statements.
    pub stmts: Vec<Stmt>,
    /// Comment.
    pub comment: Option<String>,
    /// Kernel handle.
    pub handle: Option<u64>,
    /// Location in the input (parsed rules).
    pub span: Span,
    /// Locations of the statements (parsed rules).
    pub stmt_spans: Vec<Span>,
}

/// Base chain parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BaseChain {
    /// `filter`, `nat`, `route`.
    pub ty: String,
    /// Hook name.
    pub hook: String,
    /// Devices (netdev / ingress).
    pub devices: Vec<String>,
    /// Priority as written (`filter + 10`, `-100`).
    pub priority: Priority,
    /// `accept` / `drop`.
    pub policy: Option<String>,
}

/// A chain priority.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Priority {
    /// Standard priority name, if any.
    pub name: Option<String>,
    /// Offset from the named priority, or the absolute value.
    pub offset: i32,
}

/// A chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Chain {
    /// Name.
    pub name: String,
    /// Location of the base chain declaration (`type ... ;`) in the input.
    pub base_span: Span,
    /// Location of the declaration in the input (parsed objects).
    pub span: Span,
    /// Location of the name in the input (parsed objects).
    pub name_span: Span,
    /// Handle.
    pub handle: Option<u64>,
    /// Base chain parameters.
    pub base: Option<BaseChain>,
    /// Comment.
    pub comment: Option<String>,
    /// Rules.
    pub rules: Vec<Rule>,
}

/// Key or data type of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSpec {
    /// `type a . b` (type names).
    Type(Vec<String>),
    /// `typeof <expr> . <expr>`.
    Typeof(Vec<Expr>),
}

/// A set or map declaration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Set {
    /// Name.
    pub name: String,
    /// Location of the declaration in the input (parsed objects).
    pub span: Span,
    /// Location of the name in the input (parsed objects).
    pub name_span: Span,
    /// Handle.
    pub handle: Option<u64>,
    /// Whether this is a map.
    pub is_map: bool,
    /// Key type.
    pub key: Option<TypeSpec>,
    /// Data type (maps), e.g. `verdict`, `counter`.
    pub data: Option<TypeSpec>,
    /// Data is an interval (`: interval ipv4_addr`).
    pub data_interval: bool,
    /// Flags (`constant`, `interval`, `timeout`, `dynamic`).
    pub flags: Vec<String>,
    /// Default timeout in ms.
    pub timeout: Option<u64>,
    /// GC interval in ms.
    pub gc_interval: Option<u64>,
    /// Maximum size.
    pub size: Option<u32>,
    /// `performance` / `memory`.
    pub policy: Option<String>,
    /// `auto-merge`.
    pub auto_merge: bool,
    /// Comment.
    pub comment: Option<String>,
    /// Stateful statements for every element (`counter`).
    pub stmts: Vec<Stmt>,
    /// Elements (`None` when not given / omitted).
    pub elements: Option<Vec<Elem>>,
}

/// A stateful object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjBody {
    /// `counter { packets N bytes M }`.
    Counter {
        /// Packets.
        packets: u64,
        /// Bytes.
        bytes: u64,
    },
    /// `quota { [over] N bytes [used M bytes] }`.
    Quota(Quota),
    /// `limit { rate ... }`.
    Limit(Limit),
    /// `ct helper { type "ftp" protocol tcp; l3proto ip }`.
    CtHelper {
        /// Helper name.
        helper: String,
        /// Layer 4 protocol name.
        protocol: String,
        /// Layer 3 protocol name.
        l3proto: Option<String>,
    },
    /// `ct timeout { protocol tcp; l3proto ip; policy = { ... } }`.
    CtTimeout {
        /// Layer 4 protocol name.
        protocol: String,
        /// Layer 3 protocol name.
        l3proto: Option<String>,
        /// `(state, seconds)` overrides.
        policy: Vec<(String, u32)>,
    },
    /// `ct expectation { ... }`.
    CtExpect {
        /// Layer 4 protocol name.
        protocol: String,
        /// Destination port.
        dport: u16,
        /// Timeout in ms.
        timeout: u64,
        /// Maximum expectations.
        size: u8,
        /// Layer 3 protocol name.
        l3proto: Option<String>,
    },
    /// `synproxy { mss N; wscale N; flags }`.
    Synproxy {
        /// MSS.
        mss: u16,
        /// Window scale.
        wscale: u8,
        /// Flags (`timestamp`, `sack-perm`).
        flags: Vec<String>,
    },
    /// `secmark { "ctx" }`.
    Secmark(String),
}

impl ObjBody {
    /// Keyword of the object kind (`counter`, `ct helper`, ...).
    pub fn kind(&self) -> &'static str {
        match self {
            ObjBody::Counter { .. } => "counter",
            ObjBody::Quota(_) => "quota",
            ObjBody::Limit(_) => "limit",
            ObjBody::CtHelper { .. } => "ct helper",
            ObjBody::CtTimeout { .. } => "ct timeout",
            ObjBody::CtExpect { .. } => "ct expectation",
            ObjBody::Synproxy { .. } => "synproxy",
            ObjBody::Secmark(_) => "secmark",
        }
    }
}

/// A named stateful object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obj {
    /// Name.
    pub name: String,
    /// Location of the declaration in the input (parsed objects).
    pub span: Span,
    /// Location of the name in the input (parsed objects).
    pub name_span: Span,
    /// Handle.
    pub handle: Option<u64>,
    /// Comment.
    pub comment: Option<String>,
    /// Body.
    pub body: ObjBody,
}

/// A flowtable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Flowtable {
    /// Name.
    pub name: String,
    /// Location of the declaration in the input (parsed objects).
    pub span: Span,
    /// Location of the name in the input (parsed objects).
    pub name_span: Span,
    /// Handle.
    pub handle: Option<u64>,
    /// Hook name (`ingress`).
    pub hook: String,
    /// Priority.
    pub priority: Priority,
    /// Devices.
    pub devices: Vec<String>,
    /// `counter` flag.
    pub counter: bool,
    /// `offload` flag.
    pub offload: bool,
}

/// An item inside a table block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableItem {
    /// Chain.
    Chain(Chain),
    /// Set or map.
    Set(Set),
    /// Stateful object.
    Obj(Obj),
    /// Flowtable.
    Flowtable(Flowtable),
}

/// A table with its contents.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Table {
    /// Family.
    pub family: Family,
    /// Name.
    pub name: String,
    /// Location of the declaration in the input (parsed objects).
    pub span: Span,
    /// Location of the name in the input (parsed objects).
    pub name_span: Span,
    /// Handle.
    pub handle: Option<u64>,
    /// Flags (`dormant`, `owner`, `persist`).
    pub flags: Vec<String>,
    /// Comment.
    pub comment: Option<String>,
    /// Contents.
    pub items: Vec<TableItem>,
    /// For owned tables: name of the owning process (printed as a comment).
    pub owner: Option<String>,
}

/// Kinds of objects addressed by commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjKind {
    /// `table`
    Table,
    /// `chain`
    Chain,
    /// `rule`
    Rule,
    /// `set`
    Set,
    /// `map`
    Map,
    /// `element`
    Element,
    /// `counter`
    Counter,
    /// `quota`
    Quota,
    /// `limit`
    Limit,
    /// `ct helper`
    CtHelper,
    /// `ct timeout`
    CtTimeout,
    /// `ct expectation`
    CtExpect,
    /// `synproxy`
    Synproxy,
    /// `secmark`
    Secmark,
    /// `flowtable`
    Flowtable,
    /// A meter (a dynamic set or map).
    Meter,
}

/// What a command addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Target {
    /// Family (default `ip`).
    pub family: Option<Family>,
    /// Table name.
    pub table: Option<String>,
    /// Chain / set / object name.
    pub name: Option<String>,
    /// Handle.
    pub handle: Option<u64>,
    /// Location of the table name in the input.
    pub table_span: Span,
    /// Location of the name in the input.
    pub name_span: Span,
    /// Location of the handle in the input.
    pub handle_span: Span,
}

/// Where a rule is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulePos {
    /// `position <handle>`
    Position(u64),
    /// `handle <handle>` (replace)
    Handle(u64),
    /// `index <n>`
    Index(u32),
}

/// A command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    /// `add|create table ...` (also `table ... { }` blocks).
    Table {
        /// `create` (fail if exists).
        create: bool,
        /// Table and contents.
        table: Table,
    },
    /// `add|create chain`.
    Chain {
        /// `create`.
        create: bool,
        /// Family.
        family: Family,
        /// Table.
        table: String,
        /// Location of the table name.
        table_span: Span,
        /// Chain.
        chain: Chain,
    },
    /// `add|insert|replace rule`.
    Rule {
        /// `add`, `insert` or `replace`.
        op: RuleOp,
        /// Family.
        family: Family,
        /// Table.
        table: String,
        /// Location of the table name.
        table_span: Span,
        /// Chain.
        chain: String,
        /// Location of the chain name.
        chain_span: Span,
        /// Position.
        pos: Option<RulePos>,
        /// Location of the position / handle number.
        pos_span: Span,
        /// Rule.
        rule: Rule,
        /// Span of the rule text (for error messages).
        span: Span,
        /// Spans of the statements.
        stmt_spans: Vec<Span>,
    },
    /// `add|create set|map`.
    Set {
        /// `create`.
        create: bool,
        /// Family.
        family: Family,
        /// Table.
        table: String,
        /// Location of the table name.
        table_span: Span,
        /// Set.
        set: Set,
    },
    /// `add|create|delete|destroy|get|reset element`.
    Element {
        /// `add`, `create`, `delete`, `destroy`, `get`, `reset`.
        op: String,
        /// Family.
        family: Family,
        /// Table.
        table: String,
        /// Location of the table name.
        table_span: Span,
        /// Set.
        set: String,
        /// Location of the set name.
        set_span: Span,
        /// Elements.
        elems: Vec<Elem>,
    },
    /// `add|create <object>`.
    Obj {
        /// `create`.
        create: bool,
        /// Family.
        family: Family,
        /// Table.
        table: String,
        /// Location of the table name.
        table_span: Span,
        /// Object.
        obj: Obj,
    },
    /// `add|create flowtable`.
    Flowtable {
        /// `create`.
        create: bool,
        /// Family.
        family: Family,
        /// Table.
        table: String,
        /// Location of the table name.
        table_span: Span,
        /// Flowtable.
        ft: Flowtable,
    },
    /// `delete|destroy <kind> ...`.
    Delete {
        /// `destroy` (no error if missing).
        destroy: bool,
        /// Kind.
        kind: ObjKind,
        /// Target.
        target: Target,
    },
    /// `list ...`.
    List {
        /// Kind (`None` for `list ruleset`); plural forms list all.
        kind: Option<ObjKind>,
        /// Plural (`list tables`, `list sets`, ...).
        all: bool,
        /// Target.
        target: Target,
    },
    /// `flush ruleset|table|chain|set|map`.
    Flush {
        /// Kind (`None` for the ruleset).
        kind: Option<ObjKind>,
        /// Target.
        target: Target,
    },
    /// `reset counters|quotas|rules|...`.
    Reset {
        /// Kind.
        kind: ObjKind,
        /// Plural.
        all: bool,
        /// Target.
        target: Target,
    },
    /// `describe <expr>`.
    Describe(Expr),
    /// `monitor [new|destroy] [object] [format]`.
    Monitor {
        /// `new` or `destroy` events only.
        event: Option<String>,
        /// `tables`, `chains`, `sets`, `rules`, `elements`, `ruleset` or
        /// `trace`.
        object: Option<String>,
        /// JSON output (`json` / `vm json` format).
        json: bool,
    },
    /// `rename chain <family> <table> <chain> <new>`.
    Rename {
        /// Target chain.
        target: Target,
        /// New name.
        new_name: String,
    },
}

/// Rule addition operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOp {
    /// `add rule` (append).
    Add,
    /// `insert rule` (prepend).
    Insert,
    /// `replace rule`.
    Replace,
}
