//! Human readable descriptions of nf_tables messages, used to explain
//! batch errors.

use crate::error::ErrorLocation;
use crate::expr::Expr;
use crate::nl::{Attrs, Messages, align};
use crate::objects::SetElem;
use crate::sys::*;
use crate::types::Family;
use crate::types::{Data, Verdict};

const TABLE_ATTRS: &[&str] = &[
    "",
    "NFTA_TABLE_NAME",
    "NFTA_TABLE_FLAGS",
    "NFTA_TABLE_USE",
    "NFTA_TABLE_HANDLE",
    "NFTA_TABLE_PAD",
    "NFTA_TABLE_USERDATA",
    "NFTA_TABLE_OWNER",
];
const CHAIN_ATTRS: &[&str] = &[
    "",
    "NFTA_CHAIN_TABLE",
    "NFTA_CHAIN_HANDLE",
    "NFTA_CHAIN_NAME",
    "NFTA_CHAIN_HOOK",
    "NFTA_CHAIN_POLICY",
    "NFTA_CHAIN_USE",
    "NFTA_CHAIN_TYPE",
    "NFTA_CHAIN_COUNTERS",
    "NFTA_CHAIN_PAD",
    "NFTA_CHAIN_FLAGS",
    "NFTA_CHAIN_ID",
    "NFTA_CHAIN_USERDATA",
];
const HOOK_ATTRS: &[&str] = &[
    "",
    "NFTA_HOOK_HOOKNUM",
    "NFTA_HOOK_PRIORITY",
    "NFTA_HOOK_DEV",
    "NFTA_HOOK_DEVS",
];
const RULE_ATTRS: &[&str] = &[
    "",
    "NFTA_RULE_TABLE",
    "NFTA_RULE_CHAIN",
    "NFTA_RULE_HANDLE",
    "NFTA_RULE_EXPRESSIONS",
    "NFTA_RULE_COMPAT",
    "NFTA_RULE_POSITION",
    "NFTA_RULE_USERDATA",
    "NFTA_RULE_PAD",
    "NFTA_RULE_ID",
    "NFTA_RULE_POSITION_ID",
    "NFTA_RULE_CHAIN_ID",
];
const SET_ATTRS: &[&str] = &[
    "",
    "NFTA_SET_TABLE",
    "NFTA_SET_NAME",
    "NFTA_SET_FLAGS",
    "NFTA_SET_KEY_TYPE",
    "NFTA_SET_KEY_LEN",
    "NFTA_SET_DATA_TYPE",
    "NFTA_SET_DATA_LEN",
    "NFTA_SET_POLICY",
    "NFTA_SET_DESC",
    "NFTA_SET_ID",
    "NFTA_SET_TIMEOUT",
    "NFTA_SET_GC_INTERVAL",
    "NFTA_SET_USERDATA",
    "NFTA_SET_PAD",
    "NFTA_SET_OBJ_TYPE",
    "NFTA_SET_HANDLE",
    "NFTA_SET_EXPR",
    "NFTA_SET_EXPRESSIONS",
];
const ELEM_LIST_ATTRS: &[&str] = &[
    "",
    "NFTA_SET_ELEM_LIST_TABLE",
    "NFTA_SET_ELEM_LIST_SET",
    "NFTA_SET_ELEM_LIST_ELEMENTS",
    "NFTA_SET_ELEM_LIST_SET_ID",
];
const ELEM_ATTRS: &[&str] = &[
    "",
    "NFTA_SET_ELEM_KEY",
    "NFTA_SET_ELEM_DATA",
    "NFTA_SET_ELEM_FLAGS",
    "NFTA_SET_ELEM_TIMEOUT",
    "NFTA_SET_ELEM_EXPIRATION",
    "NFTA_SET_ELEM_USERDATA",
    "NFTA_SET_ELEM_EXPR",
    "NFTA_SET_ELEM_PAD",
    "NFTA_SET_ELEM_OBJREF",
    "NFTA_SET_ELEM_KEY_END",
    "NFTA_SET_ELEM_EXPRESSIONS",
];
const OBJ_ATTRS: &[&str] = &[
    "",
    "NFTA_OBJ_TABLE",
    "NFTA_OBJ_NAME",
    "NFTA_OBJ_TYPE",
    "NFTA_OBJ_DATA",
    "NFTA_OBJ_USE",
    "NFTA_OBJ_HANDLE",
    "NFTA_OBJ_PAD",
    "NFTA_OBJ_USERDATA",
];
const FLOWTABLE_ATTRS: &[&str] = &[
    "",
    "NFTA_FLOWTABLE_TABLE",
    "NFTA_FLOWTABLE_NAME",
    "NFTA_FLOWTABLE_HOOK",
    "NFTA_FLOWTABLE_USE",
    "NFTA_FLOWTABLE_HANDLE",
    "NFTA_FLOWTABLE_PAD",
    "NFTA_FLOWTABLE_FLAGS",
];
const EXPR_ATTRS: &[&str] = &["", "NFTA_EXPR_NAME", "NFTA_EXPR_DATA"];
const DATA_ATTRS: &[&str] = &["", "NFTA_DATA_VALUE", "NFTA_DATA_VERDICT"];
const VERDICT_ATTRS: &[&str] = &[
    "",
    "NFTA_VERDICT_CODE",
    "NFTA_VERDICT_CHAIN",
    "NFTA_VERDICT_CHAIN_ID",
];

/// Attribute names of the private data of common expressions.
fn expr_attrs(name: &str) -> &'static [&'static str] {
    match name {
        "immediate" => &["", "NFTA_IMMEDIATE_DREG", "NFTA_IMMEDIATE_DATA"],
        "cmp" => &["", "NFTA_CMP_SREG", "NFTA_CMP_OP", "NFTA_CMP_DATA"],
        "lookup" => &[
            "",
            "NFTA_LOOKUP_SET",
            "NFTA_LOOKUP_SREG",
            "NFTA_LOOKUP_DREG",
            "NFTA_LOOKUP_SET_ID",
            "NFTA_LOOKUP_FLAGS",
        ],
        "dynset" => &[
            "",
            "NFTA_DYNSET_SET_NAME",
            "NFTA_DYNSET_SET_ID",
            "NFTA_DYNSET_OP",
            "NFTA_DYNSET_SREG_KEY",
            "NFTA_DYNSET_SREG_DATA",
            "NFTA_DYNSET_TIMEOUT",
            "NFTA_DYNSET_EXPR",
            "NFTA_DYNSET_PAD",
            "NFTA_DYNSET_FLAGS",
            "NFTA_DYNSET_EXPRESSIONS",
        ],
        "payload" => &[
            "",
            "NFTA_PAYLOAD_DREG",
            "NFTA_PAYLOAD_BASE",
            "NFTA_PAYLOAD_OFFSET",
            "NFTA_PAYLOAD_LEN",
            "NFTA_PAYLOAD_SREG",
            "NFTA_PAYLOAD_CSUM_TYPE",
            "NFTA_PAYLOAD_CSUM_OFFSET",
            "NFTA_PAYLOAD_CSUM_FLAGS",
        ],
        "meta" => &["", "NFTA_META_DREG", "NFTA_META_KEY", "NFTA_META_SREG"],
        "ct" => &[
            "",
            "NFTA_CT_DREG",
            "NFTA_CT_KEY",
            "NFTA_CT_DIRECTION",
            "NFTA_CT_SREG",
        ],
        "bitwise" => &[
            "",
            "NFTA_BITWISE_SREG",
            "NFTA_BITWISE_DREG",
            "NFTA_BITWISE_LEN",
            "NFTA_BITWISE_MASK",
            "NFTA_BITWISE_XOR",
            "NFTA_BITWISE_OP",
            "NFTA_BITWISE_DATA",
        ],
        "limit" => &[
            "",
            "NFTA_LIMIT_RATE",
            "NFTA_LIMIT_UNIT",
            "NFTA_LIMIT_BURST",
            "NFTA_LIMIT_TYPE",
            "NFTA_LIMIT_FLAGS",
        ],
        "log" => &[
            "",
            "NFTA_LOG_GROUP",
            "NFTA_LOG_PREFIX",
            "NFTA_LOG_SNAPLEN",
            "NFTA_LOG_QTHRESHOLD",
            "NFTA_LOG_LEVEL",
            "NFTA_LOG_FLAGS",
        ],
        "numgen" => &[
            "",
            "NFTA_NG_DREG",
            "NFTA_NG_MODULUS",
            "NFTA_NG_TYPE",
            "NFTA_NG_OFFSET",
        ],
        "connlimit" => &["", "NFTA_CONNLIMIT_COUNT", "NFTA_CONNLIMIT_FLAGS"],
        "counter" => &["", "NFTA_COUNTER_BYTES", "NFTA_COUNTER_PACKETS"],
        "objref" => &[
            "",
            "NFTA_OBJREF_IMM_TYPE",
            "NFTA_OBJREF_IMM_NAME",
            "NFTA_OBJREF_SET_SREG",
            "NFTA_OBJREF_SET_NAME",
            "NFTA_OBJREF_SET_ID",
        ],
        "range" => &[
            "",
            "NFTA_RANGE_SREG",
            "NFTA_RANGE_OP",
            "NFTA_RANGE_FROM_DATA",
            "NFTA_RANGE_TO_DATA",
        ],
        "nat" => &[
            "",
            "NFTA_NAT_TYPE",
            "NFTA_NAT_FAMILY",
            "NFTA_NAT_REG_ADDR_MIN",
            "NFTA_NAT_REG_ADDR_MAX",
            "NFTA_NAT_REG_PROTO_MIN",
            "NFTA_NAT_REG_PROTO_MAX",
            "NFTA_NAT_FLAGS",
        ],
        "quota" => &[
            "",
            "NFTA_QUOTA_BYTES",
            "NFTA_QUOTA_FLAGS",
            "NFTA_QUOTA_PAD",
            "NFTA_QUOTA_CONSUMED",
        ],
        "reject" => &["", "NFTA_REJECT_TYPE", "NFTA_REJECT_ICMP_CODE"],
        "queue" => &[
            "",
            "NFTA_QUEUE_NUM",
            "NFTA_QUEUE_TOTAL",
            "NFTA_QUEUE_FLAGS",
            "NFTA_QUEUE_SREG_QNUM",
        ],
        "exthdr" => &[
            "",
            "NFTA_EXTHDR_DREG",
            "NFTA_EXTHDR_TYPE",
            "NFTA_EXTHDR_OFFSET",
            "NFTA_EXTHDR_LEN",
            "NFTA_EXTHDR_FLAGS",
            "NFTA_EXTHDR_OP",
            "NFTA_EXTHDR_SREG",
        ],
        "fib" => &["", "NFTA_FIB_DREG", "NFTA_FIB_RESULT", "NFTA_FIB_FLAGS"],
        "hash" => &[
            "",
            "NFTA_HASH_SREG",
            "NFTA_HASH_DREG",
            "NFTA_HASH_LEN",
            "NFTA_HASH_MODULUS",
            "NFTA_HASH_SEED",
            "NFTA_HASH_OFFSET",
            "NFTA_HASH_TYPE",
        ],
        _ => &[],
    }
}

fn name_of(table: &[&str], ty: u16) -> String {
    match table.get(ty as usize) {
        Some(n) if !n.is_empty() => (*n).to_owned(),
        _ => format!("attr#{ty}"),
    }
}

/// What a sequence of attributes represents.
#[derive(Clone, Copy)]
enum Ctx<'a> {
    Top(u8),
    Hook,
    ExprList,
    Expr,
    ExprData(&'a str),
    ElemList,
    Elem,
    Data,
    Verdict,
    Opaque,
}

impl<'a> Ctx<'a> {
    fn names(self) -> &'static [&'static str] {
        match self {
            Ctx::Top(t) => top_attrs(t),
            Ctx::Hook => HOOK_ATTRS,
            Ctx::Expr => EXPR_ATTRS,
            Ctx::ExprData(n) => expr_attrs(n),
            Ctx::Elem => ELEM_ATTRS,
            Ctx::Data => DATA_ATTRS,
            Ctx::Verdict => VERDICT_ATTRS,
            Ctx::ExprList | Ctx::ElemList | Ctx::Opaque => &[],
        }
    }

    /// Context of the children of attribute `ty`. `expr_name` is the name of
    /// the enclosing expression, if this is an expression nest.
    fn child(self, ty: u16, expr_name: Option<&'a str>) -> Ctx<'a> {
        match (self, ty) {
            (Ctx::Top(NFT_MSG_NEWCHAIN), NFTA_CHAIN_HOOK) => Ctx::Hook,
            (Ctx::Top(NFT_MSG_NEWFLOWTABLE), NFTA_FLOWTABLE_HOOK) => Ctx::Hook,
            (Ctx::Top(NFT_MSG_NEWRULE), NFTA_RULE_EXPRESSIONS) => Ctx::ExprList,
            (Ctx::Top(NFT_MSG_NEWSET), NFTA_SET_EXPR) => Ctx::Expr,
            (Ctx::Top(NFT_MSG_NEWSET), NFTA_SET_EXPRESSIONS) => Ctx::ExprList,
            (
                Ctx::Top(NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM | NFT_MSG_DESTROYSETELEM),
                NFTA_SET_ELEM_LIST_ELEMENTS,
            ) => Ctx::ElemList,
            (Ctx::ExprList, _) => Ctx::Expr,
            (Ctx::ElemList, _) => Ctx::Elem,
            (Ctx::Expr, NFTA_EXPR_DATA) => Ctx::ExprData(expr_name.unwrap_or("")),
            (Ctx::Elem, NFTA_SET_ELEM_KEY | NFTA_SET_ELEM_KEY_END | NFTA_SET_ELEM_DATA) => {
                Ctx::Data
            }
            (Ctx::Elem, NFTA_SET_ELEM_EXPR) => Ctx::Expr,
            (Ctx::Elem, NFTA_SET_ELEM_EXPRESSIONS) => Ctx::ExprList,
            (Ctx::ExprData("immediate"), NFTA_IMMEDIATE_DATA) => Ctx::Data,
            (Ctx::ExprData("cmp"), NFTA_CMP_DATA) => Ctx::Data,
            (Ctx::ExprData("dynset"), NFTA_DYNSET_EXPR) => Ctx::Expr,
            (Ctx::ExprData("dynset"), NFTA_DYNSET_EXPRESSIONS) => Ctx::ExprList,
            (Ctx::Data, NFTA_DATA_VERDICT) => Ctx::Verdict,
            _ => Ctx::Opaque,
        }
    }
}

fn top_attrs(subtype: u8) -> &'static [&'static str] {
    match subtype {
        NFT_MSG_NEWTABLE | NFT_MSG_DELTABLE | NFT_MSG_DESTROYTABLE => TABLE_ATTRS,
        NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN | NFT_MSG_DESTROYCHAIN => CHAIN_ATTRS,
        NFT_MSG_NEWRULE | NFT_MSG_DELRULE | NFT_MSG_DESTROYRULE => RULE_ATTRS,
        NFT_MSG_NEWSET | NFT_MSG_DELSET | NFT_MSG_DESTROYSET => SET_ATTRS,
        NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM | NFT_MSG_DESTROYSETELEM => ELEM_LIST_ATTRS,
        NFT_MSG_NEWOBJ | NFT_MSG_DELOBJ | NFT_MSG_DESTROYOBJ => OBJ_ATTRS,
        NFT_MSG_NEWFLOWTABLE | NFT_MSG_DELFLOWTABLE | NFT_MSG_DESTROYFLOWTABLE => FLOWTABLE_ATTRS,
        _ => &[],
    }
}

/// Find the name of an expression nest (the content of an `NFTA_LIST_ELEM`).
fn expr_name(data: &[u8]) -> Option<&str> {
    Attrs::new(data)
        .flatten()
        .find(|a| a.ty == NFTA_EXPR_NAME)
        .and_then(|a| a.str().ok())
}

/// Walk `buf` (located at absolute offset `base`) towards `target`.
/// Byte spans of the innermost blamed expression and element.
#[derive(Default)]
struct Spans {
    expr: Option<(usize, usize)>,
    elem: Option<(usize, usize)>,
}

#[allow(clippy::too_many_arguments)]
fn walk<'a>(
    buf: &'a [u8],
    base: usize,
    target: usize,
    ctx: Ctx<'a>,
    loc: &mut ErrorLocation,
    spans: &mut Spans,
    elem_base: usize,
    depth: u32,
) {
    if depth > 16 {
        return;
    }
    let mut pos = 0usize;
    let mut index = 0usize;
    while pos + NLA_HDRLEN <= buf.len() {
        let len = u16::from_ne_bytes([buf[pos], buf[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([buf[pos + 2], buf[pos + 3]]) & NLA_TYPE_MASK;
        if len < NLA_HDRLEN || pos + len > buf.len() {
            return;
        }
        let abs = base + pos;
        if target >= abs && target < abs + len.max(1) {
            let data = &buf[pos + NLA_HDRLEN..pos + len];
            let mut name_inner = None;
            match ctx {
                Ctx::ExprList => {
                    spans.expr = Some((abs + NLA_HDRLEN, abs + len));
                    loc.attr_path.push(format!("elem[{index}]"));
                    // The innermost expression wins (dynset nests expressions).
                    loc.expr_index = Some(index);
                    name_inner = expr_name(data);
                    loc.expr_name = name_inner.map(str::to_owned);
                }
                Ctx::Expr => {
                    loc.attr_path.push(name_of(ctx.names(), ty));
                }
                Ctx::ElemList => {
                    spans.elem = Some((abs + NLA_HDRLEN, abs + len));
                    loc.attr_path.push(format!("elem[{}]", elem_base + index));
                    loc.elem_index = Some(elem_base + index);
                }
                _ => loc.attr_path.push(name_of(ctx.names(), ty)),
            }
            if abs == target {
                return;
            }
            // In an expression nest, find the expression's name so that its
            // data attributes can be named.
            let inner_name = match ctx {
                Ctx::Expr => {
                    // `buf` is the expression nest; its name is a sibling.
                    expr_name(buf)
                }
                _ => name_inner,
            };
            let child = ctx.child(ty, inner_name);
            if let (Ctx::Expr, false) = (ctx.child(ty, inner_name), matches!(ctx, Ctx::ExprList)) {
                // A single expression nest (e.g. NFTA_SET_EXPR, NFTA_DYNSET_EXPR).
                loc.expr_name = expr_name(data).map(str::to_owned);
                spans.expr = Some((abs + NLA_HDRLEN, abs + len));
            }
            walk(
                data,
                abs + NLA_HDRLEN,
                target,
                child,
                loc,
                spans,
                elem_base,
                depth + 1,
            );
            return;
        }
        pos += align(len);
        index += 1;
    }
}

/// Map an extended ack offset (relative to the start of the netlink header
/// of `msg`) to a location description.
pub(crate) fn locate(
    msg: &[u8],
    offset: usize,
    elem_base: usize,
    missing: bool,
    miss_type: Option<u32>,
) -> ErrorLocation {
    let mut loc = ErrorLocation {
        missing,
        ..Default::default()
    };
    let start = NLMSG_HDRLEN + NFGENMSG_LEN;
    if msg.len() < start {
        return loc;
    }
    let subtype = (u16::from_ne_bytes([msg[4], msg[5]]) & 0xff) as u8;
    let top = match subtype {
        // Delete messages share attribute layouts with their NEW variants.
        NFT_MSG_DELTABLE | NFT_MSG_DESTROYTABLE => NFT_MSG_NEWTABLE,
        NFT_MSG_DELCHAIN | NFT_MSG_DESTROYCHAIN => NFT_MSG_NEWCHAIN,
        NFT_MSG_DELRULE | NFT_MSG_DESTROYRULE => NFT_MSG_NEWRULE,
        NFT_MSG_DELSET | NFT_MSG_DESTROYSET => NFT_MSG_NEWSET,
        NFT_MSG_DELOBJ | NFT_MSG_DESTROYOBJ => NFT_MSG_NEWOBJ,
        NFT_MSG_DELFLOWTABLE | NFT_MSG_DESTROYFLOWTABLE => NFT_MSG_NEWFLOWTABLE,
        s => s,
    };
    let mut spans = Spans::default();
    if offset >= start {
        walk(
            &msg[start..],
            start,
            offset,
            Ctx::Top(top),
            &mut loc,
            &mut spans,
            elem_base,
            0,
        );
    }
    if let Some((a, b)) = spans.expr {
        if let Ok(e) = Expr::decode(Attrs::new(&msg[a..b])) {
            loc.detail = expr_detail(&e);
        }
    } else if let Some((a, b)) = spans.elem {
        if let Ok(e) = SetElem::decode(Attrs::new(&msg[a..b])) {
            loc.detail = elem_detail(&e);
        }
    }
    if let Some(t) = miss_type {
        // Name the missing attribute relative to the innermost known nest.
        loc.attr_path.push(format!("type {t}"));
    }
    loc
}

/// Describe the operation encoded in `msg`, e.g. `add rule inet filter input`.
pub(crate) fn operation(msg: &[u8]) -> String {
    let Some(Ok(m)) = Messages::new(msg).next() else {
        return "unknown operation".into();
    };
    let Ok((h, attrs)) = m.nfgen() else {
        return "unknown operation".into();
    };
    let fam = Family::from_raw(h.family).map(|f| f.name()).unwrap_or("?");
    let sub = m.subtype();
    let flags = m.flags;

    let mut table = None;
    let mut name = None;
    let mut chain = None;
    let mut handle = None;
    let mut has_elems = false;
    let mut elem_count = 0usize;
    for a in attrs.flatten() {
        match (
            top_attrs(sub).get(a.ty as usize).copied().unwrap_or(""),
            a.ty,
        ) {
            ("NFTA_TABLE_NAME", _) => name = a.str().ok(),
            ("NFTA_TABLE_HANDLE", _)
            | ("NFTA_CHAIN_HANDLE", _)
            | ("NFTA_RULE_HANDLE", _)
            | ("NFTA_OBJ_HANDLE", _) => handle = a.be64().ok(),
            (
                "NFTA_CHAIN_TABLE"
                | "NFTA_RULE_TABLE"
                | "NFTA_SET_TABLE"
                | "NFTA_SET_ELEM_LIST_TABLE"
                | "NFTA_OBJ_TABLE"
                | "NFTA_FLOWTABLE_TABLE",
                _,
            ) => table = a.str().ok(),
            (
                "NFTA_CHAIN_NAME"
                | "NFTA_SET_NAME"
                | "NFTA_SET_ELEM_LIST_SET"
                | "NFTA_OBJ_NAME"
                | "NFTA_FLOWTABLE_NAME",
                _,
            ) => name = a.str().ok(),
            ("NFTA_RULE_CHAIN", _) => chain = a.str().ok(),
            ("NFTA_SET_ELEM_LIST_ELEMENTS", _) => {
                has_elems = true;
                elem_count = a.nested().count();
            }
            _ => {}
        }
    }

    let verb = |what: &str| -> String {
        let v = match sub {
            NFT_MSG_NEWTABLE | NFT_MSG_NEWCHAIN | NFT_MSG_NEWRULE | NFT_MSG_NEWSET
            | NFT_MSG_NEWSETELEM | NFT_MSG_NEWOBJ | NFT_MSG_NEWFLOWTABLE => {
                if flags & NLM_F_REPLACE != 0 && sub == NFT_MSG_NEWRULE {
                    "replace"
                } else if flags & NLM_F_EXCL != 0 {
                    "create"
                } else if sub == NFT_MSG_NEWRULE && flags & NLM_F_APPEND == 0 {
                    "insert"
                } else if sub == NFT_MSG_NEWCHAIN && flags & NLM_F_CREATE == 0 {
                    "rename"
                } else {
                    "add"
                }
            }
            NFT_MSG_DESTROYTABLE
            | NFT_MSG_DESTROYCHAIN
            | NFT_MSG_DESTROYRULE
            | NFT_MSG_DESTROYSET
            | NFT_MSG_DESTROYSETELEM
            | NFT_MSG_DESTROYOBJ
            | NFT_MSG_DESTROYFLOWTABLE => "destroy",
            _ => "delete",
        };
        format!("{v} {what}")
    };
    let id = |parts: &[Option<&str>]| -> String {
        let mut s = String::from(fam);
        for p in parts.iter().flatten() {
            s.push(' ');
            s.push_str(p);
        }
        if let Some(h) = handle {
            s.push_str(&format!(" handle {h}"));
        }
        s
    };
    match sub {
        NFT_MSG_DELTABLE if name.is_none() && handle.is_none() => format!("flush ruleset {fam}"),
        NFT_MSG_NEWTABLE | NFT_MSG_DELTABLE | NFT_MSG_DESTROYTABLE => {
            format!("{} {}", verb("table"), id(&[name]))
        }
        NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN | NFT_MSG_DESTROYCHAIN => {
            format!("{} {}", verb("chain"), id(&[table, name]))
        }
        NFT_MSG_DELRULE if handle.is_none() && chain.is_none() => {
            format!("flush table {}", id(&[table]))
        }
        NFT_MSG_DELRULE if handle.is_none() => format!("flush chain {}", id(&[table, chain])),
        NFT_MSG_NEWRULE | NFT_MSG_DELRULE | NFT_MSG_DESTROYRULE => {
            format!("{} {}", verb("rule"), id(&[table, chain]))
        }
        NFT_MSG_NEWSET | NFT_MSG_DELSET | NFT_MSG_DESTROYSET => {
            format!("{} {}", verb("set"), id(&[table, name]))
        }
        NFT_MSG_DELSETELEM if !has_elems => format!("flush set {}", id(&[table, name])),
        NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM | NFT_MSG_DESTROYSETELEM => {
            format!(
                "{} ({elem_count} in message) in set {}",
                verb("elements"),
                id(&[table, name])
            )
        }
        NFT_MSG_NEWOBJ | NFT_MSG_DELOBJ | NFT_MSG_DESTROYOBJ => {
            format!("{} {}", verb("object"), id(&[table, name]))
        }
        NFT_MSG_NEWFLOWTABLE | NFT_MSG_DELFLOWTABLE | NFT_MSG_DESTROYFLOWTABLE => {
            format!("{} {}", verb("flowtable"), id(&[table, name]))
        }
        s => format!("nf_tables message {s} {fam}"),
    }
}

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

fn verdict_detail(v: &Verdict) -> String {
    match v {
        Verdict::Jump(c) => format!("jump {c}"),
        Verdict::Goto(c) => format!("goto {c}"),
        Verdict::JumpId(i) => format!("jump chain id {i}"),
        Verdict::GotoId(i) => format!("goto chain id {i}"),
        v => format!("{v:?}").to_lowercase(),
    }
}

/// A short description of the interesting part of an expression.
fn expr_detail(e: &Expr) -> Option<String> {
    Some(match e {
        Expr::Immediate(i) => match &i.data {
            Data::Verdict(v) => verdict_detail(v),
            Data::Value(v) => format!("value {}", hex(v)),
        },
        Expr::Lookup(l) => format!("set {}", l.set),
        Expr::Dynset(d) => format!("set {}", d.set_name),
        Expr::Objref(o) => match (&o.imm_name, &o.set_name) {
            (Some(n), _) => format!("object {n}"),
            (_, Some(s)) => format!("map {s}"),
            _ => return None,
        },
        Expr::Meta(m) => format!("key {:?}", m.key),
        Expr::Ct(c) => format!("key {:?}", c.key),
        Expr::Payload(p) => format!("{:?} header offset {} length {}", p.base, p.offset, p.len),
        Expr::FlowOffload(f) => format!("flowtable {}", f.table_name),
        Expr::Unknown(u) => format!("unknown expression {}", u.name),
        _ => return None,
    })
}

fn elem_detail(e: &SetElem) -> Option<String> {
    let mut s = match (&e.key, &e.key_end) {
        (Some(k), Some(end)) => format!("key {}-{}", hex(k), hex(end)),
        (Some(k), None) => format!("key {}", hex(k)),
        (None, _) if e.is_catchall() => "catch-all".to_owned(),
        _ => return None,
    };
    if let Some(Data::Verdict(v)) = &e.data {
        s.push_str(&format!(" : {}", verdict_detail(v)));
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::Batch;
    use crate::builder::{Field, RuleBuilder};
    use crate::objects::{Chain, SetElemList};
    use crate::types::Family;

    #[test]
    fn locate_every_offset() {
        let mut b = Batch::new();
        b.add_chain(&Chain::new(Family::Inet, "t", "c").with_hook(
            crate::ChainType::Filter,
            crate::Hook::INPUT,
            0,
        ));
        b.add_rule(
            &RuleBuilder::new(Family::Inet, "t", "c")
                .match_eq(Field::TcpDport, 22u16)
                .dynset(
                    crate::DynsetOp::Update,
                    "m",
                    &[Field::IpSaddr],
                    None,
                    vec![crate::expr::Counter::default().into()],
                )
                .jump("x")
                .build(),
        );
        b.add_elems(
            &SetElemList::new(Family::Inet, "t", "s")
                .with(SetElem::new(vec![1, 2, 3, 4]).with_verdict(Verdict::Drop)),
        );
        let body = b.body();
        for m in Messages::new(body) {
            let m = m.unwrap();
            let len = NLMSG_HDRLEN + m.payload.len();
            let start = m.payload.as_ptr() as usize - NLMSG_HDRLEN - body.as_ptr() as usize;
            let bytes = &body[start..start + len];
            assert!(!operation(bytes).is_empty());
            for off in 0..len + 8 {
                let _ = locate(bytes, off, 0, false, None);
                let _ = locate(bytes, off, 3, true, Some(7));
            }
            // Truncated messages must not panic either.
            for cut in 0..len {
                let _ = operation(&bytes[..cut]);
                let _ = locate(&bytes[..cut], cut / 2, 0, false, None);
            }
        }
        // The dynset's inner counter is located as the innermost expression.
        let rule = Messages::new(body).nth(1).unwrap().unwrap();
        let start = rule.payload.as_ptr() as usize - NLMSG_HDRLEN - body.as_ptr() as usize;
        let bytes = &body[start..start + NLMSG_HDRLEN + rule.payload.len()];
        let pos = bytes.windows(8).position(|w| w == b"counter\0").unwrap();
        let loc = locate(bytes, pos - 4, 0, false, None);
        assert_eq!(loc.expr_name.as_deref(), Some("counter"), "{loc:?}");
    }
}
