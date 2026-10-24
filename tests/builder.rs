//! Rules built with `RuleBuilder` must be listed by `nft` exactly like the
//! equivalent rules written in nft syntax.
mod common;
use std::net::Ipv4Addr;
use std::time::Duration;

use common::*;
use crabtables::expr::*;
use crabtables::sys::*;
use crabtables::*;

fn chain_body(table: &str, chain: &str) -> String {
    let out = nft(&["list", "chain", "inet", table, chain]);
    normalize(&out)
        .lines()
        .filter(|l| !l.starts_with("table") && !l.starts_with("chain") && *l != "}")
        .collect::<Vec<_>>()
        .join("\n")
}

/// For each case, add the nft text to chain nN and our rule to chain bN,
/// then compare the listings.
fn check_equiv(setup: &str, cases: Vec<(&str, Rule)>) {
    netns();
    nft_script(setup);
    let mut s = Socket::new().unwrap();
    for (i, (text, mut rule)) in cases.into_iter().enumerate() {
        nft(&["add", "chain", "inet", "t", &format!("n{i}")]);
        nft(&["add", "chain", "inet", "t", &format!("b{i}")]);
        let (ok, _, err) = nft_try(&["add", "rule", "inet", "t", &format!("n{i}"), text]);
        assert!(ok, "nft rejected case {i} `{text}`: {err}");
        rule.chain = format!("b{i}");
        let mut b = Batch::new();
        b.add_rule(&rule);
        if let Err(e) = s.commit(&b) {
            panic!("case {i} `{text}`: {e}");
        }
        let want = chain_body("t", &format!("n{i}"));
        let got = chain_body("t", &format!("b{i}"));
        assert_eq!(want, got, "case {i}: `{text}`");
        // And the kernel's view decodes to the same expressions.
        let ours = s
            .list_rules(Family::Inet, Some("t"), Some(&format!("b{i}")))
            .unwrap();
        let theirs = s
            .list_rules(Family::Inet, Some("t"), Some(&format!("n{i}")))
            .unwrap();
        assert_eq!(
            ours[0].exprs, theirs[0].exprs,
            "case {i}: `{text}` decoded differently"
        );
    }
}

fn rb() -> RuleBuilder {
    RuleBuilder::new(Family::Inet, "t", "")
}

const SETUP: &str = "
table inet t {
    set s4 { type ipv4_addr; }
    set svc { type ipv4_addr . inet_service; }
    set mtr { type ipv4_addr; flags dynamic,timeout; timeout 1m; }
    map vm { type inet_service : verdict; }
    map ng { typeof numgen inc mod 2 : verdict; }
    counter cnt { }
    chain target { }
}
";

#[test]
fn builder_matches_nft() {
    let ten = Ipv4Addr::new(10, 0, 0, 0);
    check_equiv(
        SETUP,
        vec![
            (
                "tcp dport 22 counter accept",
                rb().match_eq(Field::TcpDport, 22u16)
                    .counter()
                    .accept()
                    .build(),
            ),
            (
                "udp sport 53 drop",
                rb().match_eq(Field::UdpSport, 53u16).drop().build(),
            ),
            (
                "ip saddr 10.0.0.0/8 drop",
                rb().match_prefix(Field::IpSaddr, ten, 8).drop().build(),
            ),
            (
                "ip saddr 10.16.0.0/12 drop",
                rb().match_prefix(Field::IpSaddr, Ipv4Addr::new(10, 16, 0, 0), 12)
                    .drop()
                    .build(),
            ),
            (
                "ip daddr 1.2.3.4 accept",
                rb().match_eq(Field::IpDaddr, Ipv4Addr::new(1, 2, 3, 4))
                    .accept()
                    .build(),
            ),
            (
                "ip daddr != 1.2.3.4 accept",
                rb().match_neq(Field::IpDaddr, Ipv4Addr::new(1, 2, 3, 4))
                    .accept()
                    .build(),
            ),
            (
                "ip6 saddr ::1 accept",
                rb().match_eq(Field::Ip6Saddr, std::net::Ipv6Addr::LOCALHOST)
                    .accept()
                    .build(),
            ),
            (
                "tcp dport 1000-2000 drop",
                rb().match_range(Field::TcpDport, 1000u16, 2000u16)
                    .drop()
                    .build(),
            ),
            (
                "meta mark 0x00000007 accept",
                rb().match_eq(Field::Mark, 7u32).accept().build(),
            ),
            (
                "iifname \"lo\" accept",
                rb().match_eq(Field::IifName, "lo").accept().build(),
            ),
            (
                "iifname \"eth*\" accept",
                rb().match_eq(Field::IifName, b"eth".to_vec())
                    .accept()
                    .build(),
            ),
            (
                "ct state established,related accept",
                rb().ct_state(NF_CT_STATE_ESTABLISHED_BIT | NF_CT_STATE_RELATED_BIT)
                    .accept()
                    .build(),
            ),
            (
                "@th,16,16 0x1234 counter",
                rb().match_bits(PayloadBase::Transport, 16, 16, 0x1234)
                    .counter()
                    .build(),
            ),
            (
                "@th,0,4 3 counter",
                rb().match_bits(PayloadBase::Transport, 0, 4, 3)
                    .counter()
                    .build(),
            ),
            (
                "@nh,64,8 64 drop",
                rb().match_bits(PayloadBase::Network, 64, 8, 64)
                    .drop()
                    .build(),
            ),
            (
                "@th,100,12 0x5a5 drop",
                rb().match_bits(PayloadBase::Transport, 100, 12, 0x5a5)
                    .drop()
                    .build(),
            ),
            (
                "ip saddr @s4 drop",
                rb().in_set("s4", &[Field::IpSaddr]).drop().build(),
            ),
            (
                "ip saddr != @s4 drop",
                rb().not_in_set("s4", &[Field::IpSaddr]).drop().build(),
            ),
            (
                "ip saddr . tcp dport @svc accept",
                rb().in_set("svc", &[Field::IpSaddr, Field::TcpDport])
                    .accept()
                    .build(),
            ),
            (
                "tcp dport vmap @vm",
                rb().vmap("vm", &[Field::TcpDport]).build(),
            ),
            (
                "numgen inc mod 2 offset 5 vmap @ng",
                rb().numgen_vmap(NumgenType::Incremental, 2, 5, "ng")
                    .build(),
            ),
            (
                "numgen random mod 4 vmap @ng",
                rb().numgen_vmap(NumgenType::Random, 4, 0, "ng").build(),
            ),
            (
                "limit rate 10/second burst 5 packets accept",
                rb().limit(10, Duration::from_secs(1), 5).accept().build(),
            ),
            (
                "limit rate over 3/minute burst 1 packets drop",
                rb().limit_over(3, Duration::from_secs(60), 1)
                    .drop()
                    .build(),
            ),
            (
                "limit rate 1 mbytes/second accept",
                rb().limit_bytes(1024 * 1024, Duration::from_secs(1), 0)
                    .accept()
                    .build(),
            ),
            (
                "ct count 5 accept",
                rb().connlimit(5, false).accept().build(),
            ),
            (
                "ct count over 5 drop",
                rb().connlimit(5, true).drop().build(),
            ),
            (
                "log prefix \"hi \" group 3",
                rb().log_group(3, Some("hi ")).build(),
            ),
            (
                "log group 4 snaplen 100 queue-threshold 7",
                rb().log(Log {
                    group: Some(4),
                    snaplen: Some(100),
                    qthreshold: Some(7),
                    ..Default::default()
                })
                .build(),
            ),
            (
                "update @mtr { ip saddr limit rate over 10/second burst 5 packets } drop",
                rb().dynset(
                    DynsetOp::Update,
                    "mtr",
                    &[Field::IpSaddr],
                    None,
                    vec![
                        limit_expr(10, Duration::from_secs(1), 5, LimitType::Packets, true).into(),
                    ],
                )
                .drop()
                .build(),
            ),
            (
                "add @mtr { ip saddr timeout 10s }",
                rb().dynset(
                    DynsetOp::Add,
                    "mtr",
                    &[Field::IpSaddr],
                    Some(Duration::from_secs(10)),
                    vec![],
                )
                .build(),
            ),
            (
                "update @mtr { ip saddr counter }",
                rb().dynset(
                    DynsetOp::Update,
                    "mtr",
                    &[Field::IpSaddr],
                    None,
                    vec![Counter::default().into()],
                )
                .build(),
            ),
            (
                "delete @mtr { ip saddr }",
                rb().dynset(DynsetOp::Delete, "mtr", &[Field::IpSaddr], None, vec![])
                    .build(),
            ),
            ("counter name \"cnt\"", rb().counter_named("cnt").build()),
            ("meta mark set 0x00000010", rb().set_mark(0x10).build()),
            ("jump target", rb().jump("target").build()),
            ("goto target", rb().goto("target").build()),
            ("return", rb().ret().build()),
            (
                "tcp dport 25 reject with tcp reset",
                rb().match_eq(Field::TcpDport, 25u16)
                    .reject_tcp_reset()
                    .build(),
            ),
            (
                "reject with icmpx admin-prohibited",
                rb().reject_icmpx(NFT_REJECT_ICMPX_ADMIN_PROHIBITED).build(),
            ),
            (
                "meta skuid 0 accept",
                rb().match_eq(Field::SkUid, 0u32).accept().build(),
            ),
            (
                "ip ttl < 10 drop",
                rb().match_cmp(Field::IpTtl, CmpOp::Lt, 10u8).drop().build(),
            ),
            (
                "counter comment \"hello world\"",
                rb().counter().comment("hello world").build(),
            ),
        ],
    );
}

/// Sets built with `Set::keyed` are displayed by nft like sets it created.
#[test]
fn keyed_sets_match_nft() {
    netns();
    nft_script("table inet t { }");
    let mut s = Socket::new().unwrap();
    let ne = |v: u32| v.to_ne_bytes().to_vec();
    let cases: Vec<(&str, Set, Vec<SetElem>)> = vec![
        (
            "type mark; elements = { 10 }",
            Set::keyed(Family::Inet, "t", "", &[Field::Mark]),
            vec![SetElem::new(ne(10))],
        ),
        (
            "type ipv4_addr . inet_service . mark; elements = { 1.2.3.4 . 22 . 5 }",
            Set::keyed(
                Family::Inet,
                "t",
                "",
                &[Field::IpSaddr, Field::TcpDport, Field::Mark],
            ),
            vec![SetElem::new(concat_key(&[
                (&Field::IpSaddr, vec![1, 2, 3, 4]),
                (&Field::TcpDport, vec![0, 22]),
                (&Field::Mark, ne(5)),
            ]))],
        ),
        (
            "type ifname; elements = { \"eth0\", \"lo\" }",
            Set::keyed(Family::Inet, "t", "", &[Field::IifName]),
            vec![
                SetElem::new("eth0".into_value(&Field::IifName)),
                SetElem::new("lo".into_value(&Field::IifName)),
            ],
        ),
        (
            "type ipv6_addr; elements = { ::1, 2001:db8::1 }",
            Set::keyed(Family::Inet, "t", "", &[Field::Ip6Saddr]),
            vec![
                SetElem::new(std::net::Ipv6Addr::LOCALHOST.octets().to_vec()),
                SetElem::new(
                    "2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                ),
            ],
        ),
        (
            "type ether_addr; elements = { 00:11:22:33:44:55 }",
            Set::keyed(Family::Inet, "t", "", &[Field::EtherSaddr]),
            vec![SetElem::new(vec![0, 0x11, 0x22, 0x33, 0x44, 0x55])],
        ),
        (
            "type inet_service; flags interval; elements = { 10-20, 30 }",
            Set::keyed(Family::Inet, "t", "", &[Field::TcpDport]).with_flags(NFT_SET_INTERVAL),
            [
                SetElem::range(&[0, 10], &[0, 20], None).unwrap(),
                SetElem::range(&[0, 30], &[0, 30], None).unwrap(),
            ]
            .concat(),
        ),
        (
            "type ipv4_addr . inet_service; flags interval; elements = { 10.0.0.0/8 . 1-1000 }",
            Set::keyed(Family::Inet, "t", "", &[Field::IpSaddr, Field::TcpDport])
                .with_flags(NFT_SET_INTERVAL),
            vec![
                SetElem::new(concat_key(&[
                    (&Field::IpSaddr, vec![10, 0, 0, 0]),
                    (&Field::TcpDport, vec![0, 1]),
                ]))
                .with_key_end(concat_key(&[
                    (&Field::IpSaddr, vec![10, 255, 255, 255]),
                    (&Field::TcpDport, 1000u16.to_be_bytes().to_vec()),
                ])),
            ],
        ),
        (
            "type ipv4_addr : mark; elements = { 1.2.3.4 : 7 }",
            Set::keyed(Family::Inet, "t", "", &[Field::IpSaddr]).with_map_data(Field::Mark),
            vec![SetElem::new(vec![1, 2, 3, 4]).with_data(ne(7))],
        ),
        (
            "type ipv4_addr : ipv4_addr; elements = { 1.2.3.4 : 5.6.7.8 }",
            Set::keyed(Family::Inet, "t", "", &[Field::IpSaddr]).with_map_data(Field::IpDaddr),
            vec![SetElem::new(vec![1, 2, 3, 4]).with_data(vec![5, 6, 7, 8])],
        ),
        (
            "type inet_service : verdict; elements = { 22 : accept }",
            Set::keyed(Family::Inet, "t", "", &[Field::TcpDport]).vmap(),
            vec![SetElem::new(vec![0, 22]).with_verdict(Verdict::Accept)],
        ),
        (
            "type ipv4_addr; flags timeout; timeout 1h; elements = { 1.1.1.1 timeout 1d comment \"x\" }",
            Set::keyed(Family::Inet, "t", "", &[Field::IpSaddr])
                .with_timeout(Duration::from_secs(3600)),
            vec![
                SetElem::new(vec![1, 1, 1, 1])
                    .with_timeout(Duration::from_secs(86400))
                    .with_comment("x"),
            ],
        ),
    ];
    let strip = |s: String| -> String {
        normalize(&s)
            .lines()
            .filter(|l| {
                !l.starts_with("table")
                    && !l.starts_with("set ")
                    && !l.starts_with("map ")
                    && !l.starts_with('}')
            })
            .map(|l| match l.find("expires") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    for (i, (decl, mut set, elems)) in cases.into_iter().enumerate() {
        let kind = if set.is_map() { "map" } else { "set" };
        nft(&[
            "add",
            kind,
            "inet",
            "t",
            &format!("n{i}"),
            &format!("{{ {decl}; }}"),
        ]);
        set.name = format!("b{i}");
        let mut b = Batch::new();
        b.add_set(&set);
        let mut l = SetElemList::new(Family::Inet, "t", set.name.clone());
        l.elems = elems;
        b.add_elems(&l);
        s.commit(&b)
            .unwrap_or_else(|e| panic!("case {i} `{decl}`: {e}"));
        let want = strip(nft(&["list", kind, "inet", "t", &format!("n{i}")]));
        let got = strip(nft(&["list", kind, "inet", "t", &format!("b{i}")]));
        assert_eq!(want, got, "case {i}: `{decl}`");
    }
}

const CT_SETUP: &str = "
table inet t {
    ct helper ftp { type \"ftp\" protocol tcp; l3proto ip; }
    ct timeout tmo { protocol tcp; l3proto ip; policy = { established: 100 }; }
    ct expectation exp { protocol tcp; dport 5000; timeout 1m; size 10; l3proto ip; }
    quota q { 1000 bytes; }
    limit l { rate 5/second; }
}
";

#[test]
fn conntrack_and_nat_builders_match_nft() {
    use std::net::IpAddr;
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    let ct = |k| Field::Ct(k, None);
    let orig = |k| Field::Ct(k, Some(CtDir::Original));
    let reply = |k| Field::Ct(k, Some(CtDir::Reply));
    check_equiv(
        CT_SETUP,
        vec![
            (
                "ct state new counter",
                rb().ct_state(NF_CT_STATE_NEW_BIT).counter().build(),
            ),
            (
                "ct state invalid drop",
                rb().ct_state(NF_CT_STATE_INVALID_BIT).drop().build(),
            ),
            (
                "ct state untracked accept",
                rb().ct_state(NF_CT_STATE_UNTRACKED_BIT).accept().build(),
            ),
            (
                "ct status assured accept",
                rb().ct_status(1 << 2).accept().build(),
            ),
            (
                "ct status dnat accept",
                rb().ct_status(1 << 5).accept().build(),
            ),
            (
                "ct direction reply accept",
                rb().match_eq(ct(CtKey::Direction), 1u8).accept().build(),
            ),
            (
                "ct mark 0x00000010 accept",
                rb().match_eq(Field::CtMark, 0x10u32).accept().build(),
            ),
            (
                "ct mark and 0xff == 0x1 accept",
                rb().match_masked(Field::CtMark, 0xffu32, 1u32)
                    .accept()
                    .build(),
            ),
            (
                "ct mark set 0x10",
                rb().ct_set(CtKey::Mark, 0x10u32).build(),
            ),
            (
                "ct mark set meta mark",
                rb().ct_set_from(CtKey::Mark, Field::Mark).build(),
            ),
            (
                "meta mark set ct mark",
                rb().meta_set_from(MetaKey::Mark, Field::CtMark).build(),
            ),
            ("ct zone set 3", rb().ct_set(CtKey::Zone, 3u16).build()),
            (
                "ct zone 3 accept",
                rb().match_eq(ct(CtKey::Zone), 3u16).accept().build(),
            ),
            ("ct label set 5", rb().ct_label_set(5).build()),
            (
                "ct event set new,destroy",
                rb().ct_set(CtKey::EventMask, 5u32).build(),
            ),
            ("notrack", rb().notrack().build()),
            ("ct helper set \"ftp\"", rb().ct_helper("ftp").build()),
            ("ct timeout set \"tmo\"", rb().ct_timeout("tmo").build()),
            (
                "ct expectation set \"exp\"",
                rb().ct_expectation("exp").build(),
            ),
            (
                "quota name \"q\" drop",
                rb().quota_named("q").drop().build(),
            ),
            (
                "limit name \"l\" accept",
                rb().limit_named("l").accept().build(),
            ),
            (
                "ct original ip saddr 1.2.3.4 accept",
                rb().match_eq(orig(CtKey::SrcIp), ip("1.2.3.4"))
                    .accept()
                    .build(),
            ),
            (
                "ct reply ip daddr 1.2.3.4 accept",
                rb().match_eq(reply(CtKey::DstIp), ip("1.2.3.4"))
                    .accept()
                    .build(),
            ),
            (
                "ct original ip6 saddr ::1 accept",
                rb().match_eq(orig(CtKey::SrcIp6), ip("::1"))
                    .accept()
                    .build(),
            ),
            (
                "ct original proto-dst 80 accept",
                rb().match_eq(orig(CtKey::ProtoDst), 80u16).accept().build(),
            ),
            (
                "ct reply proto-src 80 accept",
                rb().match_eq(reply(CtKey::ProtoSrc), 80u16)
                    .accept()
                    .build(),
            ),
            (
                "ct bytes > 100 accept",
                rb().match_cmp(ct(CtKey::Bytes), CmpOp::Gt, 100u64)
                    .accept()
                    .build(),
            ),
            (
                "ct packets < 5 accept",
                rb().match_cmp(ct(CtKey::Pkts), CmpOp::Lt, 5u64)
                    .accept()
                    .build(),
            ),
            (
                "ct original packets >= 5 accept",
                rb().match_cmp(orig(CtKey::Pkts), CmpOp::Gte, 5u64)
                    .accept()
                    .build(),
            ),
            (
                "ct expiration < 10s accept",
                rb().match_cmp(ct(CtKey::Expiration), CmpOp::Lt, 10_000u32)
                    .accept()
                    .build(),
            ),
            (
                "ct protocol tcp accept",
                rb().match_eq(ct(CtKey::Protocol), 6u8).accept().build(),
            ),
            (
                "ct l3proto ipv4 accept",
                rb().match_eq(ct(CtKey::L3Protocol), 2u8).accept().build(),
            ),
            (
                "ct count over 3 drop",
                rb().connlimit(3, true).drop().build(),
            ),
            ("queue to 5", rb().queue(5, 1, 0).build()),
            (
                "queue flags bypass to 5",
                rb().queue(5, 1, NFT_QUEUE_FLAG_BYPASS).build(),
            ),
            (
                "queue flags bypass,fanout to 3-4",
                rb().queue(3, 2, NFT_QUEUE_FLAG_BYPASS | NFT_QUEUE_FLAG_CPU_FANOUT)
                    .build(),
            ),
            (
                "tcp dport 8000 redirect to :8001",
                rb().match_eq(Field::TcpDport, 8000u16)
                    .redirect(Some(8001))
                    .build(),
            ),
            (
                "meta l4proto tcp redirect",
                rb().match_eq(Field::L4Proto, 6u8).redirect(None).build(),
            ),
            (
                "ip daddr 127.0.0.5 tcp dport 80 dnat ip to 127.0.0.1:8080",
                rb().match_eq(Field::IpDaddr, ip("127.0.0.5"))
                    .match_eq(Field::TcpDport, 80u16)
                    .dnat(ip("127.0.0.1"), Some(8080))
                    .build(),
            ),
            (
                "ip saddr 127.0.0.1 snat ip to 127.0.0.2",
                rb().match_eq(Field::IpSaddr, ip("127.0.0.1"))
                    .snat(ip("127.0.0.2"), None)
                    .build(),
            ),
            (
                "ip saddr 10.0.0.0/8 tcp dport 80 snat ip to 1.2.3.4-1.2.3.10:1000-2000 random,persistent",
                rb().match_prefix(Field::IpSaddr, ip("10.0.0.0"), 8)
                    .match_eq(Field::TcpDport, 80u16)
                    .nat(
                        NatType::Snat,
                        Some((ip("1.2.3.4"), ip("1.2.3.10"))),
                        Some((1000, 2000)),
                        NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PERSISTENT,
                    )
                    .build(),
            ),
            (
                "ip6 daddr ::1 meta l4proto tcp dnat ip6 to [::2]:80",
                rb().match_eq(Field::Ip6Daddr, ip("::1"))
                    .match_eq(Field::L4Proto, 6u8)
                    .dnat(ip("::2"), Some(80))
                    .build(),
            ),
            (
                "oifname \"lo\" masquerade",
                rb().match_eq(Field::OifName, "lo").masquerade(0).build(),
            ),
            (
                "ip daddr 1.1.1.1 masquerade random",
                rb().match_eq(Field::IpDaddr, ip("1.1.1.1"))
                    .masquerade(NF_NAT_RANGE_PROTO_RANDOM)
                    .build(),
            ),
        ],
    );
}

/// In the bridge and netdev families, IP fields depend on `meta protocol`
/// (as nft), not `meta nfproto` (which is the family there).
#[test]
fn l2_family_dependencies() {
    netns();
    let mut s = Socket::new().unwrap();
    for (fam, name) in [(Family::Bridge, "bridge"), (Family::Netdev, "netdev")] {
        nft_script(&format!(
            "table {name} t {{ chain n {{ }}; chain b {{ }}; }}"
        ));
        let cases = [
            (
                "ip saddr 1.2.3.4 tcp dport 22 accept",
                RuleBuilder::new(fam, "t", "b")
                    .match_eq(Field::IpSaddr, Ipv4Addr::new(1, 2, 3, 4))
                    .match_eq(Field::TcpDport, 22u16)
                    .accept(),
            ),
            (
                "ip6 daddr ::1 accept",
                RuleBuilder::new(fam, "t", "b")
                    .match_eq(
                        Field::Ip6Daddr,
                        "::1".parse::<std::net::Ipv6Addr>().unwrap(),
                    )
                    .accept(),
            ),
        ];
        for (text, rule) in cases {
            nft(&["flush", "table", name, "t"]);
            let (ok, _, err) = nft_try(&["add", "rule", name, "t", "n", text]);
            assert!(ok, "{err}");
            let mut b = Batch::new();
            b.add_rule(&rule.build());
            s.commit(&b).unwrap();
            let body = |c: &str| {
                let out = nft(&["list", "chain", name, "t", c]);
                normalize(&out)
                    .lines()
                    .nth(2)
                    .unwrap_or_default()
                    .to_owned()
            };
            assert_eq!(body("n"), body("b"), "{name}");
        }
    }
}
