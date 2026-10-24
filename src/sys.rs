//! Raw constants of the netlink / nfnetlink / nf_tables / nfnetlink_log
//! userspace ABI.
//!
//! These mirror the values of the Linux UAPI headers (`linux/netlink.h`,
//! `linux/netfilter/nfnetlink.h`, `linux/netfilter/nf_tables.h`,
//! `linux/netfilter/nfnetlink_log.h`). They are provided so that users can
//! build or inspect messages that the typed API does not cover.
#![allow(missing_docs)]

// ---------------------------------------------------------------- netlink
pub const NETLINK_NETFILTER: isize = 12;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;
pub const NLM_F_NONREC: u16 = 0x100;
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_ACK_TLVS: u16 = 0x200;

pub const NLMSG_NOOP: u16 = 0x1;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_OVERRUN: u16 = 0x4;
pub const NLMSG_MIN_TYPE: u16 = 0x10;

pub const NLMSGERR_ATTR_UNUSED: u16 = 0;
pub const NLMSGERR_ATTR_MSG: u16 = 1;
pub const NLMSGERR_ATTR_OFFS: u16 = 2;
pub const NLMSGERR_ATTR_COOKIE: u16 = 3;
pub const NLMSGERR_ATTR_POLICY: u16 = 4;
pub const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;
pub const NLMSGERR_ATTR_MISS_NEST: u16 = 6;

pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: i32 = 2;
pub const NETLINK_NO_ENOBUFS: i32 = 5;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;

pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

/// Size of `struct nlmsghdr`.
pub const NLMSG_HDRLEN: usize = 16;
/// Size of `struct nfgenmsg`.
pub const NFGENMSG_LEN: usize = 4;
/// Size of `struct nlattr`.
pub const NLA_HDRLEN: usize = 4;

// ---------------------------------------------------------------- nfnetlink
pub const NFNETLINK_V0: u8 = 0;

pub const NFNL_SUBSYS_NONE: u8 = 0;
pub const NFNL_SUBSYS_CTNETLINK: u8 = 1;
pub const NFNL_SUBSYS_CTNETLINK_EXP: u8 = 2;
pub const NFNL_SUBSYS_QUEUE: u8 = 3;
pub const NFNL_SUBSYS_ULOG: u8 = 4;
pub const NFNL_SUBSYS_OSF: u8 = 5;
pub const NFNL_SUBSYS_IPSET: u8 = 6;
pub const NFNL_SUBSYS_ACCT: u8 = 7;
pub const NFNL_SUBSYS_CTNETLINK_TIMEOUT: u8 = 8;
pub const NFNL_SUBSYS_CTHELPER: u8 = 9;
pub const NFNL_SUBSYS_NFTABLES: u8 = 10;
pub const NFNL_SUBSYS_NFT_COMPAT: u8 = 11;
pub const NFNL_SUBSYS_HOOK: u8 = 12;

pub const NFNL_MSG_BATCH_BEGIN: u16 = NLMSG_MIN_TYPE;
pub const NFNL_MSG_BATCH_END: u16 = NLMSG_MIN_TYPE + 1;
pub const NFNL_BATCH_GENID: u16 = 1;

/// Multicast group for nf_tables ruleset change notifications.
pub const NFNLGRP_NFTABLES: u32 = 7;
/// Multicast group for nf_tables trace events.
pub const NFNLGRP_NFTRACE: u32 = 9;

// ---------------------------------------------------------------- families
pub const NFPROTO_UNSPEC: u8 = 0;
pub const NFPROTO_INET: u8 = 1;
pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_ARP: u8 = 3;
pub const NFPROTO_NETDEV: u8 = 5;
pub const NFPROTO_BRIDGE: u8 = 7;
pub const NFPROTO_IPV6: u8 = 10;

// ---------------------------------------------------------------- hooks
pub const NF_INET_PRE_ROUTING: u32 = 0;
pub const NF_INET_LOCAL_IN: u32 = 1;
pub const NF_INET_FORWARD: u32 = 2;
pub const NF_INET_LOCAL_OUT: u32 = 3;
pub const NF_INET_POST_ROUTING: u32 = 4;
pub const NF_INET_INGRESS: u32 = 5;
pub const NF_NETDEV_INGRESS: u32 = 0;
pub const NF_NETDEV_EGRESS: u32 = 1;
pub const NF_ARP_IN: u32 = 0;
pub const NF_ARP_OUT: u32 = 1;
pub const NF_ARP_FORWARD: u32 = 2;

// ---------------------------------------------------------------- verdicts
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NF_STOLEN: i32 = 2;
pub const NF_QUEUE: i32 = 3;
pub const NF_REPEAT: i32 = 4;
pub const NF_STOP: i32 = 5;

pub const NFT_CONTINUE: i32 = -1;
pub const NFT_BREAK: i32 = -2;
pub const NFT_JUMP: i32 = -3;
pub const NFT_GOTO: i32 = -4;
pub const NFT_RETURN: i32 = -5;

// ---------------------------------------------------------------- nf_tables
pub const NFT_NAME_MAXLEN: usize = 256;
pub const NFT_USERDATA_MAXLEN: usize = 256;
pub const NFT_DATA_VALUE_MAXLEN: usize = 64;
pub const NFT_REG_SIZE: usize = 16;
pub const NFT_REG32_SIZE: usize = 4;

pub const NFT_REG_VERDICT: u32 = 0;
pub const NFT_REG_1: u32 = 1;
pub const NFT_REG_2: u32 = 2;
pub const NFT_REG_3: u32 = 3;
pub const NFT_REG_4: u32 = 4;
pub const NFT_REG32_00: u32 = 8;
pub const NFT_REG32_15: u32 = 23;

pub const NFT_MSG_NEWTABLE: u8 = 0;
pub const NFT_MSG_GETTABLE: u8 = 1;
pub const NFT_MSG_DELTABLE: u8 = 2;
pub const NFT_MSG_NEWCHAIN: u8 = 3;
pub const NFT_MSG_GETCHAIN: u8 = 4;
pub const NFT_MSG_DELCHAIN: u8 = 5;
pub const NFT_MSG_NEWRULE: u8 = 6;
pub const NFT_MSG_GETRULE: u8 = 7;
pub const NFT_MSG_DELRULE: u8 = 8;
pub const NFT_MSG_NEWSET: u8 = 9;
pub const NFT_MSG_GETSET: u8 = 10;
pub const NFT_MSG_DELSET: u8 = 11;
pub const NFT_MSG_NEWSETELEM: u8 = 12;
pub const NFT_MSG_GETSETELEM: u8 = 13;
pub const NFT_MSG_DELSETELEM: u8 = 14;
pub const NFT_MSG_NEWGEN: u8 = 15;
pub const NFT_MSG_GETGEN: u8 = 16;
pub const NFT_MSG_TRACE: u8 = 17;
pub const NFT_MSG_NEWOBJ: u8 = 18;
pub const NFT_MSG_GETOBJ: u8 = 19;
pub const NFT_MSG_DELOBJ: u8 = 20;
pub const NFT_MSG_GETOBJ_RESET: u8 = 21;
pub const NFT_MSG_NEWFLOWTABLE: u8 = 22;
pub const NFT_MSG_GETFLOWTABLE: u8 = 23;
pub const NFT_MSG_DELFLOWTABLE: u8 = 24;
pub const NFT_MSG_GETRULE_RESET: u8 = 25;
pub const NFT_MSG_DESTROYTABLE: u8 = 26;
pub const NFT_MSG_DESTROYCHAIN: u8 = 27;
pub const NFT_MSG_DESTROYRULE: u8 = 28;
pub const NFT_MSG_DESTROYSET: u8 = 29;
pub const NFT_MSG_DESTROYSETELEM: u8 = 30;
pub const NFT_MSG_DESTROYOBJ: u8 = 31;
pub const NFT_MSG_DESTROYFLOWTABLE: u8 = 32;
pub const NFT_MSG_GETSETELEM_RESET: u8 = 33;

pub const NFTA_LIST_ELEM: u16 = 1;

pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;
pub const NFTA_HOOK_DEV: u16 = 3;
pub const NFTA_HOOK_DEVS: u16 = 4;

pub const NFT_TABLE_F_DORMANT: u32 = 0x1;
pub const NFT_TABLE_F_OWNER: u32 = 0x2;
pub const NFT_TABLE_F_PERSIST: u32 = 0x4;

pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_TABLE_FLAGS: u16 = 2;
pub const NFTA_TABLE_USE: u16 = 3;
pub const NFTA_TABLE_HANDLE: u16 = 4;
pub const NFTA_TABLE_PAD: u16 = 5;
pub const NFTA_TABLE_USERDATA: u16 = 6;
pub const NFTA_TABLE_OWNER: u16 = 7;

pub const NFT_CHAIN_BASE: u32 = 1 << 0;
pub const NFT_CHAIN_HW_OFFLOAD: u32 = 1 << 1;
pub const NFT_CHAIN_BINDING: u32 = 1 << 2;

pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_HANDLE: u16 = 2;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_USE: u16 = 6;
pub const NFTA_CHAIN_TYPE: u16 = 7;
pub const NFTA_CHAIN_COUNTERS: u16 = 8;
pub const NFTA_CHAIN_PAD: u16 = 9;
pub const NFTA_CHAIN_FLAGS: u16 = 10;
pub const NFTA_CHAIN_ID: u16 = 11;
pub const NFTA_CHAIN_USERDATA: u16 = 12;

pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_HANDLE: u16 = 3;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_RULE_COMPAT: u16 = 5;
pub const NFTA_RULE_POSITION: u16 = 6;
pub const NFTA_RULE_USERDATA: u16 = 7;
pub const NFTA_RULE_PAD: u16 = 8;
pub const NFTA_RULE_ID: u16 = 9;
pub const NFTA_RULE_POSITION_ID: u16 = 10;
pub const NFTA_RULE_CHAIN_ID: u16 = 11;

pub const NFTA_RULE_COMPAT_PROTO: u16 = 1;
pub const NFTA_RULE_COMPAT_FLAGS: u16 = 2;

pub const NFT_SET_ANONYMOUS: u32 = 0x1;
pub const NFT_SET_CONSTANT: u32 = 0x2;
pub const NFT_SET_INTERVAL: u32 = 0x4;
pub const NFT_SET_MAP: u32 = 0x8;
pub const NFT_SET_TIMEOUT: u32 = 0x10;
pub const NFT_SET_EVAL: u32 = 0x20;
pub const NFT_SET_OBJECT: u32 = 0x40;
pub const NFT_SET_CONCAT: u32 = 0x80;
pub const NFT_SET_EXPR: u32 = 0x100;

pub const NFT_SET_POL_PERFORMANCE: u32 = 0;
pub const NFT_SET_POL_MEMORY: u32 = 1;

pub const NFTA_SET_DESC_SIZE: u16 = 1;
pub const NFTA_SET_DESC_CONCAT: u16 = 2;
pub const NFTA_SET_FIELD_LEN: u16 = 1;

pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
pub const NFTA_SET_DATA_TYPE: u16 = 6;
pub const NFTA_SET_DATA_LEN: u16 = 7;
pub const NFTA_SET_POLICY: u16 = 8;
pub const NFTA_SET_DESC: u16 = 9;
pub const NFTA_SET_ID: u16 = 10;
pub const NFTA_SET_TIMEOUT: u16 = 11;
pub const NFTA_SET_GC_INTERVAL: u16 = 12;
pub const NFTA_SET_USERDATA: u16 = 13;
pub const NFTA_SET_PAD: u16 = 14;
pub const NFTA_SET_OBJ_TYPE: u16 = 15;
pub const NFTA_SET_HANDLE: u16 = 16;
pub const NFTA_SET_EXPR: u16 = 17;
pub const NFTA_SET_EXPRESSIONS: u16 = 18;

pub const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;
pub const NFT_SET_ELEM_CATCHALL: u32 = 0x2;

pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_DATA: u16 = 2;
pub const NFTA_SET_ELEM_FLAGS: u16 = 3;
pub const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
pub const NFTA_SET_ELEM_EXPIRATION: u16 = 5;
pub const NFTA_SET_ELEM_USERDATA: u16 = 6;
pub const NFTA_SET_ELEM_EXPR: u16 = 7;
pub const NFTA_SET_ELEM_PAD: u16 = 8;
pub const NFTA_SET_ELEM_OBJREF: u16 = 9;
pub const NFTA_SET_ELEM_KEY_END: u16 = 10;
pub const NFTA_SET_ELEM_EXPRESSIONS: u16 = 11;

pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
pub const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;

pub const NFT_DATA_VALUE: u32 = 0;
pub const NFT_DATA_VERDICT: u32 = 0xffff_ff00;

pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;

pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;
pub const NFTA_VERDICT_CHAIN_ID: u16 = 3;

pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

pub const NFT_BITWISE_MASK_XOR: u32 = 0;
pub const NFT_BITWISE_LSHIFT: u32 = 1;
pub const NFT_BITWISE_RSHIFT: u32 = 2;

pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN: u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR: u16 = 5;
pub const NFTA_BITWISE_OP: u16 = 6;
pub const NFTA_BITWISE_DATA: u16 = 7;

pub const NFT_BYTEORDER_NTOH: u32 = 0;
pub const NFT_BYTEORDER_HTON: u32 = 1;

pub const NFTA_BYTEORDER_SREG: u16 = 1;
pub const NFTA_BYTEORDER_DREG: u16 = 2;
pub const NFTA_BYTEORDER_OP: u16 = 3;
pub const NFTA_BYTEORDER_LEN: u16 = 4;
pub const NFTA_BYTEORDER_SIZE: u16 = 5;

pub const NFT_CMP_EQ: u32 = 0;
pub const NFT_CMP_NEQ: u32 = 1;
pub const NFT_CMP_LT: u32 = 2;
pub const NFT_CMP_LTE: u32 = 3;
pub const NFT_CMP_GT: u32 = 4;
pub const NFT_CMP_GTE: u32 = 5;

pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;

pub const NFT_RANGE_EQ: u32 = 0;
pub const NFT_RANGE_NEQ: u32 = 1;

pub const NFTA_RANGE_SREG: u16 = 1;
pub const NFTA_RANGE_OP: u16 = 2;
pub const NFTA_RANGE_FROM_DATA: u16 = 3;
pub const NFTA_RANGE_TO_DATA: u16 = 4;

pub const NFT_LOOKUP_F_INV: u32 = 1 << 0;

pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;
pub const NFTA_LOOKUP_DREG: u16 = 3;
pub const NFTA_LOOKUP_SET_ID: u16 = 4;
pub const NFTA_LOOKUP_FLAGS: u16 = 5;

pub const NFT_DYNSET_OP_ADD: u32 = 0;
pub const NFT_DYNSET_OP_UPDATE: u32 = 1;
pub const NFT_DYNSET_OP_DELETE: u32 = 2;

pub const NFT_DYNSET_F_INV: u32 = 1 << 0;
pub const NFT_DYNSET_F_EXPR: u32 = 1 << 1;

pub const NFTA_DYNSET_SET_NAME: u16 = 1;
pub const NFTA_DYNSET_SET_ID: u16 = 2;
pub const NFTA_DYNSET_OP: u16 = 3;
pub const NFTA_DYNSET_SREG_KEY: u16 = 4;
pub const NFTA_DYNSET_SREG_DATA: u16 = 5;
pub const NFTA_DYNSET_TIMEOUT: u16 = 6;
pub const NFTA_DYNSET_EXPR: u16 = 7;
pub const NFTA_DYNSET_PAD: u16 = 8;
pub const NFTA_DYNSET_FLAGS: u16 = 9;
pub const NFTA_DYNSET_EXPRESSIONS: u16 = 10;

pub const NFT_PAYLOAD_LL_HEADER: u32 = 0;
pub const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub const NFT_PAYLOAD_INNER_HEADER: u32 = 3;
pub const NFT_PAYLOAD_TUN_HEADER: u32 = 4;

pub const NFT_PAYLOAD_CSUM_NONE: u32 = 0;
pub const NFT_PAYLOAD_CSUM_INET: u32 = 1;
pub const NFT_PAYLOAD_CSUM_SCTP: u32 = 2;
pub const NFT_PAYLOAD_L4CSUM_PSEUDOHDR: u32 = 1 << 0;

pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;
pub const NFTA_PAYLOAD_SREG: u16 = 5;
pub const NFTA_PAYLOAD_CSUM_TYPE: u16 = 6;
pub const NFTA_PAYLOAD_CSUM_OFFSET: u16 = 7;
pub const NFTA_PAYLOAD_CSUM_FLAGS: u16 = 8;

pub const NFTA_INNER_NUM: u16 = 1;
pub const NFTA_INNER_TYPE: u16 = 2;
pub const NFTA_INNER_FLAGS: u16 = 3;
pub const NFTA_INNER_HDRSIZE: u16 = 4;
pub const NFTA_INNER_EXPR: u16 = 5;

pub const NFT_EXTHDR_F_PRESENT: u32 = 1 << 0;
pub const NFT_EXTHDR_OP_IPV6: u32 = 0;
pub const NFT_EXTHDR_OP_TCPOPT: u32 = 1;
pub const NFT_EXTHDR_OP_IPV4: u32 = 2;
pub const NFT_EXTHDR_OP_SCTP: u32 = 3;
pub const NFT_EXTHDR_OP_DCCP: u32 = 4;

pub const NFTA_EXTHDR_DREG: u16 = 1;
pub const NFTA_EXTHDR_TYPE: u16 = 2;
pub const NFTA_EXTHDR_OFFSET: u16 = 3;
pub const NFTA_EXTHDR_LEN: u16 = 4;
pub const NFTA_EXTHDR_FLAGS: u16 = 5;
pub const NFTA_EXTHDR_OP: u16 = 6;
pub const NFTA_EXTHDR_SREG: u16 = 7;

pub const NFT_META_LEN: u32 = 0;
pub const NFT_META_PROTOCOL: u32 = 1;
pub const NFT_META_PRIORITY: u32 = 2;
pub const NFT_META_MARK: u32 = 3;
pub const NFT_META_IIF: u32 = 4;
pub const NFT_META_OIF: u32 = 5;
pub const NFT_META_IIFNAME: u32 = 6;
pub const NFT_META_OIFNAME: u32 = 7;
pub const NFT_META_IIFTYPE: u32 = 8;
pub const NFT_META_OIFTYPE: u32 = 9;
pub const NFT_META_SKUID: u32 = 10;
pub const NFT_META_SKGID: u32 = 11;
pub const NFT_META_NFTRACE: u32 = 12;
pub const NFT_META_RTCLASSID: u32 = 13;
pub const NFT_META_SECMARK: u32 = 14;
pub const NFT_META_NFPROTO: u32 = 15;
pub const NFT_META_L4PROTO: u32 = 16;
pub const NFT_META_BRI_IIFNAME: u32 = 17;
pub const NFT_META_BRI_OIFNAME: u32 = 18;
pub const NFT_META_PKTTYPE: u32 = 19;
pub const NFT_META_CPU: u32 = 20;
pub const NFT_META_IIFGROUP: u32 = 21;
pub const NFT_META_OIFGROUP: u32 = 22;
pub const NFT_META_CGROUP: u32 = 23;
pub const NFT_META_PRANDOM: u32 = 24;
pub const NFT_META_SECPATH: u32 = 25;
pub const NFT_META_IIFKIND: u32 = 26;
pub const NFT_META_OIFKIND: u32 = 27;
pub const NFT_META_BRI_IIFPVID: u32 = 28;
pub const NFT_META_BRI_IIFVPROTO: u32 = 29;
pub const NFT_META_TIME_NS: u32 = 30;
pub const NFT_META_TIME_DAY: u32 = 31;
pub const NFT_META_TIME_HOUR: u32 = 32;
pub const NFT_META_SDIF: u32 = 33;
pub const NFT_META_SDIFNAME: u32 = 34;
pub const NFT_META_BRI_BROUTE: u32 = 35;

pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;
pub const NFTA_META_SREG: u16 = 3;

pub const NFT_RT_CLASSID: u32 = 0;
pub const NFT_RT_NEXTHOP4: u32 = 1;
pub const NFT_RT_NEXTHOP6: u32 = 2;
pub const NFT_RT_TCPMSS: u32 = 3;
pub const NFT_RT_XFRM: u32 = 4;

pub const NFTA_RT_DREG: u16 = 1;
pub const NFTA_RT_KEY: u16 = 2;

pub const NFT_HASH_JENKINS: u32 = 0;
pub const NFT_HASH_SYM: u32 = 1;

pub const NFTA_HASH_SREG: u16 = 1;
pub const NFTA_HASH_DREG: u16 = 2;
pub const NFTA_HASH_LEN: u16 = 3;
pub const NFTA_HASH_MODULUS: u16 = 4;
pub const NFTA_HASH_SEED: u16 = 5;
pub const NFTA_HASH_OFFSET: u16 = 6;
pub const NFTA_HASH_TYPE: u16 = 7;

pub const NFTA_SOCKET_KEY: u16 = 1;
pub const NFTA_SOCKET_DREG: u16 = 2;
pub const NFTA_SOCKET_LEVEL: u16 = 3;

pub const NFT_SOCKET_TRANSPARENT: u32 = 0;
pub const NFT_SOCKET_MARK: u32 = 1;
pub const NFT_SOCKET_WILDCARD: u32 = 2;
pub const NFT_SOCKET_CGROUPV2: u32 = 3;

pub const NFT_CT_STATE: u32 = 0;
pub const NFT_CT_DIRECTION: u32 = 1;
pub const NFT_CT_STATUS: u32 = 2;
pub const NFT_CT_MARK: u32 = 3;
pub const NFT_CT_SECMARK: u32 = 4;
pub const NFT_CT_EXPIRATION: u32 = 5;
pub const NFT_CT_HELPER: u32 = 6;
pub const NFT_CT_L3PROTOCOL: u32 = 7;
pub const NFT_CT_SRC: u32 = 8;
pub const NFT_CT_DST: u32 = 9;
pub const NFT_CT_PROTOCOL: u32 = 10;
pub const NFT_CT_PROTO_SRC: u32 = 11;
pub const NFT_CT_PROTO_DST: u32 = 12;
pub const NFT_CT_LABELS: u32 = 13;
pub const NFT_CT_PKTS: u32 = 14;
pub const NFT_CT_BYTES: u32 = 15;
pub const NFT_CT_AVGPKT: u32 = 16;
pub const NFT_CT_ZONE: u32 = 17;
pub const NFT_CT_EVENTMASK: u32 = 18;
pub const NFT_CT_SRC_IP: u32 = 19;
pub const NFT_CT_DST_IP: u32 = 20;
pub const NFT_CT_SRC_IP6: u32 = 21;
pub const NFT_CT_DST_IP6: u32 = 22;
pub const NFT_CT_ID: u32 = 23;

pub const NFTA_CT_DREG: u16 = 1;
pub const NFTA_CT_KEY: u16 = 2;
pub const NFTA_CT_DIRECTION: u16 = 3;
pub const NFTA_CT_SREG: u16 = 4;

/// Conntrack state bits as matched by `ct state`.
pub const NF_CT_STATE_INVALID_BIT: u32 = 1 << 0;
pub const NF_CT_STATE_ESTABLISHED_BIT: u32 = 1 << 1;
pub const NF_CT_STATE_RELATED_BIT: u32 = 1 << 2;
pub const NF_CT_STATE_NEW_BIT: u32 = 1 << 3;
pub const NF_CT_STATE_UNTRACKED_BIT: u32 = 1 << 6;

pub const NFTA_FLOW_TABLE_NAME: u16 = 1;

pub const NFT_LIMIT_PKTS: u32 = 0;
pub const NFT_LIMIT_PKT_BYTES: u32 = 1;
pub const NFT_LIMIT_F_INV: u32 = 1 << 0;

pub const NFTA_LIMIT_RATE: u16 = 1;
pub const NFTA_LIMIT_UNIT: u16 = 2;
pub const NFTA_LIMIT_BURST: u16 = 3;
pub const NFTA_LIMIT_TYPE: u16 = 4;
pub const NFTA_LIMIT_FLAGS: u16 = 5;
pub const NFTA_LIMIT_PAD: u16 = 6;

pub const NFT_CONNLIMIT_F_INV: u32 = 1 << 0;
pub const NFTA_CONNLIMIT_COUNT: u16 = 1;
pub const NFTA_CONNLIMIT_FLAGS: u16 = 2;

pub const NFTA_COUNTER_BYTES: u16 = 1;
pub const NFTA_COUNTER_PACKETS: u16 = 2;
pub const NFTA_COUNTER_PAD: u16 = 3;

pub const NFTA_LAST_SET: u16 = 1;
pub const NFTA_LAST_MSECS: u16 = 2;
pub const NFTA_LAST_PAD: u16 = 3;

pub const NFTA_LOG_GROUP: u16 = 1;
pub const NFTA_LOG_PREFIX: u16 = 2;
pub const NFTA_LOG_SNAPLEN: u16 = 3;
pub const NFTA_LOG_QTHRESHOLD: u16 = 4;
pub const NFTA_LOG_LEVEL: u16 = 5;
pub const NFTA_LOG_FLAGS: u16 = 6;

pub const NFT_LOGLEVEL_EMERG: u32 = 0;
pub const NFT_LOGLEVEL_ALERT: u32 = 1;
pub const NFT_LOGLEVEL_CRIT: u32 = 2;
pub const NFT_LOGLEVEL_ERR: u32 = 3;
pub const NFT_LOGLEVEL_WARNING: u32 = 4;
pub const NFT_LOGLEVEL_NOTICE: u32 = 5;
pub const NFT_LOGLEVEL_INFO: u32 = 6;
pub const NFT_LOGLEVEL_DEBUG: u32 = 7;
pub const NFT_LOGLEVEL_AUDIT: u32 = 8;

pub const NF_LOG_TCPSEQ: u32 = 0x01;
pub const NF_LOG_TCPOPT: u32 = 0x02;
pub const NF_LOG_IPOPT: u32 = 0x04;
pub const NF_LOG_UID: u32 = 0x08;
pub const NF_LOG_MACDECODE: u32 = 0x20;
pub const NF_LOG_MASK: u32 = 0x2f;
pub const NF_LOG_PREFIXLEN: usize = 128;

pub const NFTA_QUEUE_NUM: u16 = 1;
pub const NFTA_QUEUE_TOTAL: u16 = 2;
pub const NFTA_QUEUE_FLAGS: u16 = 3;
pub const NFTA_QUEUE_SREG_QNUM: u16 = 4;
pub const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;
pub const NFT_QUEUE_FLAG_CPU_FANOUT: u16 = 0x02;

pub const NFT_QUOTA_F_INV: u32 = 1 << 0;
pub const NFT_QUOTA_F_DEPLETED: u32 = 1 << 1;
pub const NFTA_QUOTA_BYTES: u16 = 1;
pub const NFTA_QUOTA_FLAGS: u16 = 2;
pub const NFTA_QUOTA_PAD: u16 = 3;
pub const NFTA_QUOTA_CONSUMED: u16 = 4;

pub const NFTA_SECMARK_CTX: u16 = 1;

pub const NFT_REJECT_ICMP_UNREACH: u32 = 0;
pub const NFT_REJECT_TCP_RST: u32 = 1;
pub const NFT_REJECT_ICMPX_UNREACH: u32 = 2;
pub const NFT_REJECT_ICMPX_NO_ROUTE: u8 = 0;
pub const NFT_REJECT_ICMPX_PORT_UNREACH: u8 = 1;
pub const NFT_REJECT_ICMPX_HOST_UNREACH: u8 = 2;
pub const NFT_REJECT_ICMPX_ADMIN_PROHIBITED: u8 = 3;
pub const NFTA_REJECT_TYPE: u16 = 1;
pub const NFTA_REJECT_ICMP_CODE: u16 = 2;

pub const NFT_NAT_SNAT: u32 = 0;
pub const NFT_NAT_DNAT: u32 = 1;
pub const NFTA_NAT_TYPE: u16 = 1;
pub const NFTA_NAT_FAMILY: u16 = 2;
pub const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
pub const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
pub const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
pub const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
pub const NFTA_NAT_FLAGS: u16 = 7;

pub const NF_NAT_RANGE_MAP_IPS: u32 = 1 << 0;
pub const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 1;
pub const NF_NAT_RANGE_PROTO_RANDOM: u32 = 1 << 2;
pub const NF_NAT_RANGE_PERSISTENT: u32 = 1 << 3;
pub const NF_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 4;
pub const NF_NAT_RANGE_PROTO_OFFSET: u32 = 1 << 5;
pub const NF_NAT_RANGE_NETMAP: u32 = 1 << 6;

pub const NFTA_TPROXY_FAMILY: u16 = 1;
pub const NFTA_TPROXY_REG_ADDR: u16 = 2;
pub const NFTA_TPROXY_REG_PORT: u16 = 3;

pub const NFTA_MASQ_FLAGS: u16 = 1;
pub const NFTA_MASQ_REG_PROTO_MIN: u16 = 2;
pub const NFTA_MASQ_REG_PROTO_MAX: u16 = 3;

pub const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
pub const NFTA_REDIR_REG_PROTO_MAX: u16 = 2;
pub const NFTA_REDIR_FLAGS: u16 = 3;

pub const NFTA_DUP_SREG_ADDR: u16 = 1;
pub const NFTA_DUP_SREG_DEV: u16 = 2;

pub const NFTA_FWD_SREG_DEV: u16 = 1;
pub const NFTA_FWD_SREG_ADDR: u16 = 2;
pub const NFTA_FWD_NFPROTO: u16 = 3;

pub const NFTA_OBJREF_IMM_TYPE: u16 = 1;
pub const NFTA_OBJREF_IMM_NAME: u16 = 2;
pub const NFTA_OBJREF_SET_SREG: u16 = 3;
pub const NFTA_OBJREF_SET_NAME: u16 = 4;
pub const NFTA_OBJREF_SET_ID: u16 = 5;

pub const NFTA_GEN_ID: u16 = 1;
pub const NFTA_GEN_PROC_PID: u16 = 2;
pub const NFTA_GEN_PROC_NAME: u16 = 3;

pub const NFTA_FIB_DREG: u16 = 1;
pub const NFTA_FIB_RESULT: u16 = 2;
pub const NFTA_FIB_FLAGS: u16 = 3;
pub const NFT_FIB_RESULT_OIF: u32 = 1;
pub const NFT_FIB_RESULT_OIFNAME: u32 = 2;
pub const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;
pub const NFTA_FIB_F_SADDR: u32 = 1 << 0;
pub const NFTA_FIB_F_DADDR: u32 = 1 << 1;
pub const NFTA_FIB_F_MARK: u32 = 1 << 2;
pub const NFTA_FIB_F_IIF: u32 = 1 << 3;
pub const NFTA_FIB_F_OIF: u32 = 1 << 4;
pub const NFTA_FIB_F_PRESENT: u32 = 1 << 5;

pub const NFTA_CT_HELPER_NAME: u16 = 1;
pub const NFTA_CT_HELPER_L3PROTO: u16 = 2;
pub const NFTA_CT_HELPER_L4PROTO: u16 = 3;

pub const NFTA_CT_TIMEOUT_L3PROTO: u16 = 1;
pub const NFTA_CT_TIMEOUT_L4PROTO: u16 = 2;
pub const NFTA_CT_TIMEOUT_DATA: u16 = 3;

pub const NFTA_CT_EXPECT_L3PROTO: u16 = 1;
pub const NFTA_CT_EXPECT_L4PROTO: u16 = 2;
pub const NFTA_CT_EXPECT_DPORT: u16 = 3;
pub const NFTA_CT_EXPECT_TIMEOUT: u16 = 4;
pub const NFTA_CT_EXPECT_SIZE: u16 = 5;

pub const NFT_OBJECT_UNSPEC: u32 = 0;
pub const NFT_OBJECT_COUNTER: u32 = 1;
pub const NFT_OBJECT_QUOTA: u32 = 2;
pub const NFT_OBJECT_CT_HELPER: u32 = 3;
pub const NFT_OBJECT_LIMIT: u32 = 4;
pub const NFT_OBJECT_CONNLIMIT: u32 = 5;
pub const NFT_OBJECT_TUNNEL: u32 = 6;
pub const NFT_OBJECT_CT_TIMEOUT: u32 = 7;
pub const NFT_OBJECT_SECMARK: u32 = 8;
pub const NFT_OBJECT_CT_EXPECT: u32 = 9;
pub const NFT_OBJECT_SYNPROXY: u32 = 10;

pub const NFTA_OBJ_TABLE: u16 = 1;
pub const NFTA_OBJ_NAME: u16 = 2;
pub const NFTA_OBJ_TYPE: u16 = 3;
pub const NFTA_OBJ_DATA: u16 = 4;
pub const NFTA_OBJ_USE: u16 = 5;
pub const NFTA_OBJ_HANDLE: u16 = 6;
pub const NFTA_OBJ_PAD: u16 = 7;
pub const NFTA_OBJ_USERDATA: u16 = 8;

pub const NFT_FLOWTABLE_HW_OFFLOAD: u32 = 0x1;
pub const NFT_FLOWTABLE_COUNTER: u32 = 0x2;

pub const NFTA_FLOWTABLE_TABLE: u16 = 1;
pub const NFTA_FLOWTABLE_NAME: u16 = 2;
pub const NFTA_FLOWTABLE_HOOK: u16 = 3;
pub const NFTA_FLOWTABLE_USE: u16 = 4;
pub const NFTA_FLOWTABLE_HANDLE: u16 = 5;
pub const NFTA_FLOWTABLE_PAD: u16 = 6;
pub const NFTA_FLOWTABLE_FLAGS: u16 = 7;

pub const NFTA_FLOWTABLE_HOOK_NUM: u16 = 1;
pub const NFTA_FLOWTABLE_HOOK_PRIORITY: u16 = 2;
pub const NFTA_FLOWTABLE_HOOK_DEVS: u16 = 3;

pub const NFTA_OSF_DREG: u16 = 1;
pub const NFTA_OSF_TTL: u16 = 2;
pub const NFTA_OSF_FLAGS: u16 = 3;
pub const NFT_OSF_F_VERSION: u32 = 1 << 0;

pub const NFTA_SYNPROXY_MSS: u16 = 1;
pub const NFTA_SYNPROXY_WSCALE: u16 = 2;
pub const NFTA_SYNPROXY_FLAGS: u16 = 3;

pub const NFTA_DEVICE_NAME: u16 = 1;

pub const NFTA_XFRM_DREG: u16 = 1;
pub const NFTA_XFRM_KEY: u16 = 2;
pub const NFTA_XFRM_DIR: u16 = 3;
pub const NFTA_XFRM_SPNUM: u16 = 4;

pub const NFTA_TRACE_TABLE: u16 = 1;
pub const NFTA_TRACE_CHAIN: u16 = 2;
pub const NFTA_TRACE_RULE_HANDLE: u16 = 3;
pub const NFTA_TRACE_TYPE: u16 = 4;
pub const NFTA_TRACE_VERDICT: u16 = 5;
pub const NFTA_TRACE_ID: u16 = 6;
pub const NFTA_TRACE_LL_HEADER: u16 = 7;
pub const NFTA_TRACE_NETWORK_HEADER: u16 = 8;
pub const NFTA_TRACE_TRANSPORT_HEADER: u16 = 9;
pub const NFTA_TRACE_IIF: u16 = 10;
pub const NFTA_TRACE_IIFTYPE: u16 = 11;
pub const NFTA_TRACE_OIF: u16 = 12;
pub const NFTA_TRACE_OIFTYPE: u16 = 13;
pub const NFTA_TRACE_MARK: u16 = 14;
pub const NFTA_TRACE_NFPROTO: u16 = 15;
pub const NFTA_TRACE_POLICY: u16 = 16;

pub const NFTA_NG_DREG: u16 = 1;
pub const NFTA_NG_MODULUS: u16 = 2;
pub const NFTA_NG_TYPE: u16 = 3;
pub const NFTA_NG_OFFSET: u16 = 4;
pub const NFT_NG_INCREMENTAL: u32 = 0;
pub const NFT_NG_RANDOM: u32 = 1;

pub const NFTA_TUNNEL_KEY: u16 = 1;
pub const NFTA_TUNNEL_DREG: u16 = 2;
pub const NFTA_TUNNEL_MODE: u16 = 3;

// ---------------------------------------------------------------- nfnetlink_log
pub const NFULNL_MSG_PACKET: u8 = 0;
pub const NFULNL_MSG_CONFIG: u8 = 1;

pub const NFULA_VLAN_PROTO: u16 = 1;
pub const NFULA_VLAN_TCI: u16 = 2;

pub const NFULA_PACKET_HDR: u16 = 1;
pub const NFULA_MARK: u16 = 2;
pub const NFULA_TIMESTAMP: u16 = 3;
pub const NFULA_IFINDEX_INDEV: u16 = 4;
pub const NFULA_IFINDEX_OUTDEV: u16 = 5;
pub const NFULA_IFINDEX_PHYSINDEV: u16 = 6;
pub const NFULA_IFINDEX_PHYSOUTDEV: u16 = 7;
pub const NFULA_HWADDR: u16 = 8;
pub const NFULA_PAYLOAD: u16 = 9;
pub const NFULA_PREFIX: u16 = 10;
pub const NFULA_UID: u16 = 11;
pub const NFULA_SEQ: u16 = 12;
pub const NFULA_SEQ_GLOBAL: u16 = 13;
pub const NFULA_GID: u16 = 14;
pub const NFULA_HWTYPE: u16 = 15;
pub const NFULA_HWHEADER: u16 = 16;
pub const NFULA_HWLEN: u16 = 17;
pub const NFULA_CT: u16 = 18;
pub const NFULA_CT_INFO: u16 = 19;
pub const NFULA_VLAN: u16 = 20;
pub const NFULA_L2HDR: u16 = 21;

pub const NFULNL_CFG_CMD_NONE: u8 = 0;
pub const NFULNL_CFG_CMD_BIND: u8 = 1;
pub const NFULNL_CFG_CMD_UNBIND: u8 = 2;
pub const NFULNL_CFG_CMD_PF_BIND: u8 = 3;
pub const NFULNL_CFG_CMD_PF_UNBIND: u8 = 4;

pub const NFULA_CFG_CMD: u16 = 1;
pub const NFULA_CFG_MODE: u16 = 2;
pub const NFULA_CFG_NLBUFSIZ: u16 = 3;
pub const NFULA_CFG_TIMEOUT: u16 = 4;
pub const NFULA_CFG_QTHRESH: u16 = 5;
pub const NFULA_CFG_FLAGS: u16 = 6;

pub const NFULNL_COPY_NONE: u8 = 0x00;
pub const NFULNL_COPY_META: u8 = 0x01;
pub const NFULNL_COPY_PACKET: u8 = 0x02;

pub const NFULNL_CFG_F_SEQ: u16 = 0x0001;
pub const NFULNL_CFG_F_SEQ_GLOBAL: u16 = 0x0002;
pub const NFULNL_CFG_F_CONNTRACK: u16 = 0x0004;

// ---------------------------------------------------------------- cttimeout
// Attribute types of per-state timeouts (seconds, be32) in
// `NFTA_CT_TIMEOUT_DATA`.
pub const CTA_TIMEOUT_TCP_SYN_SENT: u16 = 1;
pub const CTA_TIMEOUT_TCP_SYN_RECV: u16 = 2;
pub const CTA_TIMEOUT_TCP_ESTABLISHED: u16 = 3;
pub const CTA_TIMEOUT_TCP_FIN_WAIT: u16 = 4;
pub const CTA_TIMEOUT_TCP_CLOSE_WAIT: u16 = 5;
pub const CTA_TIMEOUT_TCP_LAST_ACK: u16 = 6;
pub const CTA_TIMEOUT_TCP_TIME_WAIT: u16 = 7;
pub const CTA_TIMEOUT_TCP_CLOSE: u16 = 8;
pub const CTA_TIMEOUT_TCP_SYN_SENT2: u16 = 9;
pub const CTA_TIMEOUT_TCP_RETRANS: u16 = 10;
pub const CTA_TIMEOUT_TCP_UNACK: u16 = 11;
pub const CTA_TIMEOUT_UDP_UNREPLIED: u16 = 1;
pub const CTA_TIMEOUT_UDP_REPLIED: u16 = 2;
pub const CTA_TIMEOUT_ICMP_TIMEOUT: u16 = 1;
pub const CTA_TIMEOUT_GENERIC_TIMEOUT: u16 = 1;

// ---------------------------------------------------------------- nfnetlink_queue
pub const NFQNL_MSG_PACKET: u8 = 0;
pub const NFQNL_MSG_VERDICT: u8 = 1;
pub const NFQNL_MSG_CONFIG: u8 = 2;
pub const NFQNL_MSG_VERDICT_BATCH: u8 = 3;

pub const NFQA_VLAN_PROTO: u16 = 1;
pub const NFQA_VLAN_TCI: u16 = 2;

pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_VERDICT_HDR: u16 = 2;
pub const NFQA_MARK: u16 = 3;
pub const NFQA_TIMESTAMP: u16 = 4;
pub const NFQA_IFINDEX_INDEV: u16 = 5;
pub const NFQA_IFINDEX_OUTDEV: u16 = 6;
pub const NFQA_IFINDEX_PHYSINDEV: u16 = 7;
pub const NFQA_IFINDEX_PHYSOUTDEV: u16 = 8;
pub const NFQA_HWADDR: u16 = 9;
pub const NFQA_PAYLOAD: u16 = 10;
pub const NFQA_CT: u16 = 11;
pub const NFQA_CT_INFO: u16 = 12;
pub const NFQA_CAP_LEN: u16 = 13;
pub const NFQA_SKB_INFO: u16 = 14;
pub const NFQA_EXP: u16 = 15;
pub const NFQA_UID: u16 = 16;
pub const NFQA_GID: u16 = 17;
pub const NFQA_SECCTX: u16 = 18;
pub const NFQA_VLAN: u16 = 19;
pub const NFQA_L2HDR: u16 = 20;
pub const NFQA_PRIORITY: u16 = 21;
pub const NFQA_CGROUP_CLASSID: u16 = 22;

pub const NFQNL_CFG_CMD_NONE: u8 = 0;
pub const NFQNL_CFG_CMD_BIND: u8 = 1;
pub const NFQNL_CFG_CMD_UNBIND: u8 = 2;
pub const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
pub const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;

pub const NFQNL_COPY_NONE: u8 = 0;
pub const NFQNL_COPY_META: u8 = 1;
pub const NFQNL_COPY_PACKET: u8 = 2;

pub const NFQA_CFG_CMD: u16 = 1;
pub const NFQA_CFG_PARAMS: u16 = 2;
pub const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
pub const NFQA_CFG_MASK: u16 = 4;
pub const NFQA_CFG_FLAGS: u16 = 5;

pub const NFQA_CFG_F_FAIL_OPEN: u32 = 1 << 0;
pub const NFQA_CFG_F_CONNTRACK: u32 = 1 << 1;
pub const NFQA_CFG_F_GSO: u32 = 1 << 2;
pub const NFQA_CFG_F_UID_GID: u32 = 1 << 3;
pub const NFQA_CFG_F_SECCTX: u32 = 1 << 4;

pub const NFQA_SKB_CSUMNOTREADY: u32 = 1 << 0;
pub const NFQA_SKB_GSO: u32 = 1 << 1;
pub const NFQA_SKB_CSUM_NOTVERIFIED: u32 = 1 << 2;

/// Conntrack attribute: connection mark (be32), usable in `NFQA_CT` of a verdict.
pub const CTA_MARK: u16 = 8;
