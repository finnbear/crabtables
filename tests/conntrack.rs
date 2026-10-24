//! Conntrack and NAT, with real traffic. Results are checked with rule
//! counters and with the `conntrack` tool (conntrack-tools).
mod common;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::time::Duration;

use common::*;
use crabtables::expr::*;
use crabtables::nflog::{GroupConfig, NflogSocket};
use crabtables::sys::*;
use crabtables::*;

const F: Family = Family::Inet;

/// Table `t` with filter chains `out`/`in`, raw chains `rawout`/`rawpre`
/// and nat chains `natout`/`natpost`.
fn setup() -> Socket {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    for (name, ty, hook, prio) in [
        ("rawout", ChainType::Filter, Hook::OUTPUT, -300),
        ("rawpre", ChainType::Filter, Hook::PREROUTING, -300),
        ("natout", ChainType::Nat, Hook::OUTPUT, -100),
        ("natpost", ChainType::Nat, Hook::POSTROUTING, 100),
        ("out", ChainType::Filter, Hook::OUTPUT, 0),
        ("in", ChainType::Filter, Hook::INPUT, 0),
    ] {
        b.add_chain(&Chain::new(F, "t", name).with_hook(ty, hook, prio));
    }
    s.commit(&b).unwrap();
    s
}

fn rule(chain: &str) -> RuleBuilder {
    RuleBuilder::new(F, "t", chain)
}

fn add(s: &mut Socket, rules: Vec<Rule>) {
    let mut b = Batch::new();
    for r in &rules {
        b.add_rule(r);
    }
    s.commit(&b).unwrap();
}

fn counter(s: &mut Socket, chain: &str, comment: &str) -> u64 {
    s.list_rules(F, Some("t"), Some(chain))
        .unwrap()
        .iter()
        .find(|r| r.comment() == Some(comment))
        .unwrap_or_else(|| panic!("no rule {comment}"))
        .counters()
        .map(|c| c.packets)
        .sum()
}

fn conntrack(args: &[&str]) -> String {
    let out = Command::new("conntrack")
        .args(args)
        .output()
        .expect("conntrack tool");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sysctl(path: &str, v: &str) {
    std::fs::write(format!("/proc/sys/net/netfilter/{path}"), v).unwrap();
}

/// An echo server on 127.0.0.1:port (thread, inherits the namespace).
/// Returns the address of each accepted peer through the channel.
fn echo_server(port: u16) -> std::sync::mpsc::Receiver<SocketAddr> {
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { break };
            let _ = tx.send(c.peer_addr().unwrap());
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    rx
}

/// Connect, send `msg`, expect it echoed back.
fn talk(addr: (IpAddr, u16), msg: &[u8]) -> TcpStream {
    let mut c = TcpStream::connect_timeout(&SocketAddr::from(addr), Duration::from_secs(3))
        .expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(msg).unwrap();
    let mut buf = vec![0u8; msg.len()];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(buf, msg);
    c
}

fn lo() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[test]
fn connection_states() {
    let mut s = setup();
    sysctl("nf_conntrack_tcp_loose", "0");
    add(
        &mut s,
        vec![
            rule("in")
                .match_eq(Field::TcpDport, 7001u16)
                .ct_state(NF_CT_STATE_NEW_BIT)
                .counter()
                .comment("new")
                .build(),
            rule("in")
                .match_eq(Field::TcpSport, 7001u16)
                .ct_state(NF_CT_STATE_ESTABLISHED_BIT)
                .counter()
                .comment("est")
                .build(),
            rule("in")
                .match_eq(Field::L4Proto, libc::IPPROTO_ICMP as u8)
                .ct_state(NF_CT_STATE_RELATED_BIT)
                .counter()
                .comment("rel")
                .build(),
            rule("out")
                .match_eq(Field::TcpDport, 7009u16)
                .ct_state(NF_CT_STATE_INVALID_BIT)
                .counter()
                .comment("inv")
                .build(),
            rule("rawout")
                .match_eq(Field::UdpDport, 7010u16)
                .notrack()
                .build(),
            rule("out")
                .match_eq(Field::UdpDport, 7010u16)
                .ct_state(NF_CT_STATE_UNTRACKED_BIT)
                .counter()
                .comment("untracked")
                .build(),
            rule("in")
                .match_eq(Field::TcpSport, 7001u16)
                .ct_status(1 << 2)
                .counter()
                .comment("assured")
                .build(),
        ],
    );
    let _srv = echo_server(7001);
    let c = talk((lo(), 7001), b"hello");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(counter(&mut s, "in", "new"), 1, "only the SYN is new");
    assert!(
        counter(&mut s, "in", "est") >= 2,
        "SYN-ACK and data from the server are established"
    );
    assert!(counter(&mut s, "in", "assured") >= 1);
    drop(c);

    // UDP to a closed port: the ICMP port unreachable error is RELATED.
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"x", "127.0.0.1:7002")
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(counter(&mut s, "in", "rel"), 1);

    // A TCP ACK without a connection is INVALID (with tcp_loose = 0).
    send_raw_tcp_ack(7009);
    assert_eq!(counter(&mut s, "out", "inv"), 1);

    // notrack in a raw chain makes packets untracked.
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"x", "127.0.0.1:7010")
        .unwrap();
    assert_eq!(counter(&mut s, "out", "untracked"), 1);
    assert!(
        !conntrack(&["-L"]).contains("dport=7010"),
        "untracked flows have no conntrack entry"
    );
}

/// Send a bare TCP ACK to 127.0.0.1:port through a raw socket.
fn send_raw_tcp_ack(port: u16) {
    // SAFETY: plain socket syscalls on locally owned buffers.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        assert!(fd >= 0);
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&port.to_be_bytes());
        tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x10; // ACK
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
        // Checksum over the pseudo header and segment.
        let mut sum: u32 = 0;
        let mut add16 = |b: &[u8]| {
            for c in b.chunks(2) {
                sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
            }
        };
        add16(&[127, 0, 0, 1, 127, 0, 0, 1, 0, 6, 0, 20]);
        add16(&tcp);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        tcp[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        let n = libc::sendto(
            fd,
            tcp.as_ptr() as *const libc::c_void,
            tcp.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        assert_eq!(n, 20, "{}", std::io::Error::last_os_error());
        libc::close(fd);
    }
}

#[test]
fn marks_zones_labels() {
    let mut s = setup();
    add(
        &mut s,
        vec![
            // Mark the connection on the way out ...
            rule("out")
                .match_eq(Field::TcpDport, 7003u16)
                .ct_state(NF_CT_STATE_NEW_BIT)
                .ct_set(CtKey::Mark, 0x42u32)
                .build(),
            rule("out")
                .match_eq(Field::TcpDport, 7003u16)
                .ct_label_set(5)
                .build(),
            // ... and restore it onto reply packets.
            rule("in")
                .match_eq(Field::TcpSport, 7003u16)
                .meta_set_from(MetaKey::Mark, Field::CtMark)
                .build(),
            rule("in")
                .match_eq(Field::TcpSport, 7003u16)
                .match_eq(Field::Mark, 0x42u32)
                .counter()
                .comment("restored")
                .build(),
            rule("in")
                .match_eq(Field::TcpSport, 7003u16)
                .match_flags(Field::Ct(CtKey::Labels, None), {
                    let mut v = vec![0u8; 16];
                    v[0] = 1 << 5;
                    v
                })
                .counter()
                .comment("label")
                .build(),
            rule("in")
                .match_eq(Field::TcpSport, 7003u16)
                .match_masked(Field::CtMark, 0xf0u32, 0x40u32)
                .counter()
                .comment("masked")
                .build(),
            // Copy the packet mark into the connection for UDP.
            rule("out")
                .match_eq(Field::UdpDport, 7004u16)
                .set_mark(0x77)
                .ct_set_from(CtKey::Mark, Field::Mark)
                .build(),
            // Zones must be set before conntrack (raw priority), in both directions.
            rule("rawout")
                .match_eq(Field::UdpDport, 7005u16)
                .ct_set(CtKey::Zone, 9u16)
                .build(),
            rule("in")
                .match_eq(Field::UdpDport, 7005u16)
                .match_eq(Field::Ct(CtKey::Zone, None), 9u16)
                .counter()
                .comment("zone")
                .build(),
        ],
    );
    let _srv = echo_server(7003);
    let _c = talk((lo(), 7003), b"mark me");
    let ct = conntrack(&["-L", "-p", "tcp", "--dport", "7003"]);
    assert!(ct.contains("mark=66"), "{ct}");
    assert!(counter(&mut s, "in", "restored") >= 2);
    assert!(counter(&mut s, "in", "label") >= 2);
    assert!(counter(&mut s, "in", "masked") >= 2);

    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"x", "127.0.0.1:7004")
        .unwrap();
    let ct = conntrack(&["-L", "-p", "udp", "--dport", "7004"]);
    assert!(ct.contains("mark=119"), "{ct}");

    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"x", "127.0.0.1:7005")
        .unwrap();
    let ct = conntrack(&["-L", "-p", "udp", "--dport", "7005"]);
    assert!(ct.contains("zone=9"), "{ct}");
    assert_eq!(counter(&mut s, "in", "zone"), 1);
}

#[test]
fn helpers_timeouts_expectations() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_obj(&Obj::new(
        F,
        "t",
        "ftp",
        ObjKind::CtHelper(CtHelper {
            name: "ftp".into(),
            l3proto: Some(NFPROTO_IPV4.into()),
            l4proto: libc::IPPROTO_TCP as u8,
        }),
    ));
    let tmo = CtTimeout::new(
        Some(NFPROTO_IPV4.into()),
        libc::IPPROTO_TCP as u8,
        &[
            (CTA_TIMEOUT_TCP_ESTABLISHED, 100),
            (CTA_TIMEOUT_TCP_CLOSE, 4),
        ],
    );
    b.add_obj(&Obj::new(F, "t", "short", ObjKind::CtTimeout(tmo.clone())));
    b.add_obj(&Obj::new(
        F,
        "t",
        "exp",
        ObjKind::CtExpect(CtExpect {
            l3proto: Some(NFPROTO_IPV4.into()),
            l4proto: libc::IPPROTO_TCP as u8,
            dport: 5555,
            timeout: 60_000,
            size: 5,
        }),
    ));
    s.commit(&b).unwrap();
    let rs = ruleset();
    assert_contains_lines(
        &rs,
        "ct timeout short {\nprotocol tcp\nl3proto ip\npolicy = { established : 1m40s, close : 4s }",
    );
    assert_contains_lines(
        &rs,
        "ct expectation exp {\nprotocol tcp\ndport 5555\ntimeout 1m\nsize 5\nl3proto ip",
    );
    match s.get_obj(F, "t", "short", ObjType::CtTimeout).unwrap().kind {
        // The kernel fills in defaults for the other states.
        ObjKind::CtTimeout(t) => {
            let p = t.policy();
            assert!(
                p.contains(&(CTA_TIMEOUT_TCP_ESTABLISHED, 100))
                    && p.contains(&(CTA_TIMEOUT_TCP_CLOSE, 4)),
                "{p:?}"
            );
        }
        k => panic!("{k:?}"),
    }
    match s.get_obj(F, "t", "exp", ObjType::CtExpect).unwrap().kind {
        ObjKind::CtExpect(e) => assert_eq!(e.timeout, 60_000),
        k => panic!("{k:?}"),
    }
    add(
        &mut s,
        vec![
            rule("out")
                .match_eq(Field::TcpDport, 7006u16)
                .ct_helper("ftp")
                .build(),
            // Timeout policies attach to new, unconfirmed connections: use
            // a chain after conntrack (priority > -200), not a raw chain.
            rule("out")
                .match_eq(Field::TcpDport, 7007u16)
                .ct_timeout("short")
                .build(),
            // Like timeouts, expectations are created for new connections.
            rule("out")
                .match_eq(Field::TcpDport, 7008u16)
                .ct_state(NF_CT_STATE_NEW_BIT)
                .ct_expectation("exp")
                .build(),
        ],
    );
    let _a = echo_server(7006);
    let _b = echo_server(7007);
    let _c = echo_server(7008);
    let _c1 = talk((lo(), 7006), b"USER x\r\n");
    let _c2 = talk((lo(), 7007), b"x");
    let _c3 = talk((lo(), 7008), b"x");
    let ct = conntrack(&["-L", "-p", "tcp", "--dport", "7006"]);
    assert!(ct.contains("helper=ftp"), "{ct}");
    let ct = conntrack(&["-L", "-p", "tcp", "--dport", "7007"]);
    let timeout: u64 = ct.split_whitespace().nth(2).unwrap().parse().unwrap();
    assert!(ct.contains("ESTABLISHED") && timeout <= 100, "{ct}");
    let exp = conntrack(&["-L", "expect"]);
    assert!(exp.contains("dport=5555"), "{exp}");
}

#[test]
fn nat_redirect_dnat_snat_masquerade() {
    let mut s = setup();
    let ip = |a: [u8; 4]| IpAddr::V4(Ipv4Addr::from(a));
    add(
        &mut s,
        vec![
            rule("natout")
                .match_eq(Field::TcpDport, 8000u16)
                .redirect(Some(8001))
                .build(),
            rule("natout")
                .match_eq(Field::IpDaddr, ip([127, 0, 0, 5]))
                .match_eq(Field::TcpDport, 80u16)
                .dnat(lo(), Some(8002))
                .build(),
            rule("natpost")
                .match_eq(Field::TcpDport, 8003u16)
                .snat(ip([127, 0, 0, 2]), None)
                .build(),
            rule("natpost")
                .match_eq(Field::TcpDport, 8005u16)
                .nat(
                    NatType::Snat,
                    Some((ip([127, 0, 0, 3]), ip([127, 0, 0, 3]))),
                    Some((9000, 9010)),
                    0,
                )
                .build(),
            rule("in")
                .match_eq(Field::TcpDport, 8002u16)
                .ct_status(1 << 5)
                .counter()
                .comment("dnat")
                .build(),
        ],
    );
    let _r = echo_server(8001);
    let _d = echo_server(8002);
    let peers3 = echo_server(8003);
    let peers5 = echo_server(8005);
    let _c = talk((lo(), 8000), b"redirected");
    let _c = talk((ip([127, 0, 0, 5]), 80), b"dnatted");
    assert!(counter(&mut s, "in", "dnat") >= 1);
    let ct = conntrack(&["-L", "-p", "tcp", "--orig-port-dst", "8000"]);
    assert!(
        ct.contains("sport=8001"),
        "reply tuple comes from the redirect target: {ct}"
    );
    let _c = talk((lo(), 8003), b"snatted");
    assert_eq!(
        peers3.recv_timeout(Duration::from_secs(1)).unwrap().ip(),
        ip([127, 0, 0, 2])
    );
    let _c = talk((lo(), 8005), b"range");
    let p = peers5.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(p.ip(), ip([127, 0, 0, 3]));
    assert!((9000..=9010).contains(&p.port()), "{p}");
}

/// Masquerade does not work on loopback (the kernel finds no usable
/// address), so use a dummy interface with two addresses: packets from the
/// secondary address are masqueraded to the primary one.
#[test]
fn masquerade() {
    let mut s = setup();
    for cmd in [
        "link add d0 type dummy",
        "link set d0 up",
        "addr add 10.99.0.1/24 dev d0",
        "addr add 10.99.0.5/24 dev d0",
    ] {
        assert!(
            Command::new("ip")
                .args(cmd.split(' '))
                .status()
                .unwrap()
                .success(),
            "ip {cmd}"
        );
    }
    add(
        &mut s,
        vec![
            rule("natpost")
                .match_eq(Field::OifName, "d0")
                .match_eq(Field::UdpDport, 7020u16)
                .counter()
                .comment("masq")
                .masquerade(0)
                .build(),
            rule("natpost")
                .match_eq(Field::OifName, "d0")
                .match_eq(Field::UdpDport, 7021u16)
                .match_eq(Field::L4Proto, libc::IPPROTO_UDP as u8)
                .expr(Immediate {
                    dreg: Reg::R1,
                    data: Data::Value(30000u16.to_be_bytes().to_vec()),
                })
                .expr(Masq {
                    flags: Some(NF_NAT_RANGE_PROTO_SPECIFIED),
                    reg_proto_min: Some(Reg::R1),
                    reg_proto_max: Some(Reg::R1),
                })
                .build(),
        ],
    );
    let tx = UdpSocket::bind("10.99.0.5:0").unwrap();
    tx.send_to(b"x", "10.99.0.2:7020").unwrap();
    tx.send_to(b"x", "10.99.0.2:7021").unwrap();
    assert_eq!(counter(&mut s, "natpost", "masq"), 1);
    let ct = conntrack(&["-L", "-p", "udp", "--dport", "7020"]);
    assert!(
        ct.contains("src=10.99.0.5 dst=10.99.0.2") && ct.contains("src=10.99.0.2 dst=10.99.0.1"),
        "{ct}"
    );
    let ct = conntrack(&["-L", "-p", "udp", "--dport", "7021"]);
    assert!(ct.contains("dst=10.99.0.1 sport=7021 dport=30000"), "{ct}");
}

#[test]
fn accounting_and_directions() {
    let mut s = setup();
    sysctl("nf_conntrack_acct", "1");
    let ct = |k, d| Field::Ct(k, d);
    add(
        &mut s,
        vec![
            rule("out")
                .match_eq(Field::UdpDport, 7011u16)
                .match_cmp(ct(CtKey::Pkts, Some(CtDir::Original)), CmpOp::Gt, 5u64)
                .counter()
                .comment("after5")
                .build(),
            rule("out")
                .match_eq(Field::UdpDport, 7011u16)
                .match_cmp(ct(CtKey::Bytes, None), CmpOp::Gte, 10 * 28 + 10 * 100u64)
                .counter()
                .comment("bytes")
                .build(),
            rule("in")
                .match_eq(Field::UdpSport, 7012u16)
                .match_eq(ct(CtKey::Direction, None), 1u8)
                .match_eq(ct(CtKey::SrcIp, Some(CtDir::Original)), lo())
                .match_eq(ct(CtKey::ProtoDst, Some(CtDir::Original)), 7012u16)
                .counter()
                .comment("reply")
                .build(),
            rule("out")
                .match_eq(Field::UdpDport, 7011u16)
                .match_cmp(ct(CtKey::Pkts, Some(CtDir::Original)), CmpOp::Gt, 1u64)
                .match_cmp(ct(CtKey::Expiration, None), CmpOp::Gt, 1000u32)
                .counter()
                .comment("expiring")
                .build(),
        ],
    );
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let _rx = UdpSocket::bind("127.0.0.1:7011").unwrap();
    for _ in 0..10 {
        tx.send_to(&[0u8; 100], "127.0.0.1:7011").unwrap();
    }
    // Conntrack accounts a packet before the filter hook sees it: packet n
    // sees n packets, so packets 6..=10 match.
    assert_eq!(counter(&mut s, "out", "after5"), 5);
    // 128 bytes per packet (headers included): only the 10th sees 1280.
    assert_eq!(counter(&mut s, "out", "bytes"), 1);
    // The first packet's connection is not confirmed yet, so its timeout is
    // still relative and the kernel's expiration is garbage: 0, or a large
    // value within ~5 min of boot (before jiffies wrap). Skip it.
    assert_eq!(counter(&mut s, "out", "expiring"), 9);
    let ct = conntrack(&["-L", "-p", "udp", "--dport", "7011"]);
    assert!(ct.contains("packets=10 bytes=1280"), "{ct}");

    // Reply direction: a UDP echo.
    let srv = UdpSocket::bind("127.0.0.1:7012").unwrap();
    tx.send_to(b"ping", "127.0.0.1:7012").unwrap();
    let mut buf = [0u8; 16];
    let (n, from) = srv.recv_from(&mut buf).unwrap();
    srv.send_to(&buf[..n], from).unwrap();
    assert_eq!(counter(&mut s, "in", "reply"), 1);
}

#[test]
fn per_source_connlimit() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_set(&Set::keyed(F, "t", "perip", &[Field::IpDaddr]).with_flags(NFT_SET_EVAL));
    b.add_rule(
        &rule("out")
            .match_eq(Field::TcpDport, 7013u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .dynset(
                DynsetOp::Add,
                "perip",
                &[Field::IpDaddr],
                None,
                vec![
                    Connlimit {
                        count: 2,
                        flags: NFT_CONNLIMIT_F_INV,
                    }
                    .into(),
                ],
            )
            .counter()
            .comment("over")
            .reject_tcp_reset()
            .build(),
    );
    s.commit(&b).unwrap();
    let _srv = echo_server(7013);
    let _l = TcpListener::bind("127.0.0.2:7013").unwrap();
    let a = talk((lo(), 7013), b"1");
    let b2 = talk((lo(), 7013), b"2");
    assert!(
        TcpStream::connect_timeout(&"127.0.0.1:7013".parse().unwrap(), Duration::from_secs(2))
            .is_err(),
        "third connection to 127.0.0.1 rejected"
    );
    // Another destination has its own budget.
    let _other = TcpStream::connect("127.0.0.2:7013").unwrap();
    assert_eq!(counter(&mut s, "out", "over"), 1);
    let elems = s.list_elems(F, "t", "perip").unwrap();
    assert_eq!(elems.len(), 2);
    assert!(
        elems
            .iter()
            .all(|e| matches!(e.exprs.first(), Some(Expr::Connlimit(_))))
    );
    // Closing connections frees the budget (the count is garbage collected
    // when the next connection is checked).
    drop((a, b2));
    std::thread::sleep(Duration::from_millis(200));
    talk((lo(), 7013), b"3");
}

#[test]
fn ct_keyed_sets_and_maps() {
    let mut s = setup();
    let mut b = Batch::new();
    // ct state vmap
    b.add_chain(&Chain::new(F, "t", "newc"));
    b.add_rule(&rule("newc").counter().comment("newc").build());
    b.add_set(&Set::keyed(F, "t", "states", &[Field::CtState]).vmap());
    b.add_elems(
        &SetElemList::new(F, "t", "states").with(
            SetElem::new(NF_CT_STATE_NEW_BIT.to_ne_bytes().to_vec())
                .with_verdict(Verdict::Jump("newc".into())),
        ),
    );
    b.add_rule(
        &rule("out")
            .match_eq(Field::UdpDport, 7014u16)
            .vmap("states", &[Field::CtState])
            .build(),
    );
    // ct mark set ip daddr map { ... }
    b.add_set(&Set::keyed(F, "t", "marks", &[Field::IpDaddr]).with_map_data(Field::CtMark));
    b.add_elems(
        &SetElemList::new(F, "t", "marks")
            .with(SetElem::new(vec![127, 0, 0, 1]).with_data(0x99u32.to_ne_bytes().to_vec())),
    );
    b.add_rule(
        &rule("out")
            .match_eq(Field::UdpDport, 7015u16)
            .map_lookup("marks", &[Field::IpDaddr], Reg::R1)
            .expr(Ct {
                dreg: None,
                key: CtKey::Mark,
                direction: None,
                sreg: Some(Reg::R1),
            })
            .build(),
    );
    // A dynamic set of original destination ports.
    b.add_set(
        &Set::keyed(
            F,
            "t",
            "ports",
            &[Field::Ct(CtKey::ProtoDst, Some(CtDir::Original))],
        )
        .with_flags(NFT_SET_EVAL),
    );
    b.add_rule(
        &rule("out")
            .match_eq(Field::L4Proto, libc::IPPROTO_UDP as u8)
            .dynset(
                DynsetOp::Add,
                "ports",
                &[Field::Ct(CtKey::ProtoDst, Some(CtDir::Original))],
                None,
                vec![],
            )
            .build(),
    );
    s.commit(&b).unwrap();
    let rs = ruleset();
    assert!(rs.contains("ct state vmap @states"), "{rs}");
    assert!(rs.contains("ct mark set ip daddr map @marks"), "{rs}");
    assert!(rs.contains("add @ports { ct original proto-dst }"), "{rs}");
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv = UdpSocket::bind("127.0.0.1:7014").unwrap();
    tx.send_to(b"a", "127.0.0.1:7014").unwrap();
    tx.send_to(b"b", "127.0.0.1:7014").unwrap();
    assert_eq!(
        counter(&mut s, "newc", "newc"),
        2,
        "an unreplied UDP flow stays new"
    );
    let mut buf = [0u8; 4];
    let (_, from) = srv.recv_from(&mut buf).unwrap();
    srv.send_to(b"r", from).unwrap();
    tx.send_to(b"c", "127.0.0.1:7014").unwrap();
    assert_eq!(
        counter(&mut s, "newc", "newc"),
        2,
        "established after the reply"
    );
    tx.send_to(b"c", "127.0.0.1:7015").unwrap();
    assert!(conntrack(&["-L", "-p", "udp", "--dport", "7015"]).contains("mark=153"));
    let mut ports: Vec<_> = s
        .list_elems(F, "t", "ports")
        .unwrap()
        .into_iter()
        .map(|e| e.key.unwrap())
        .collect();
    ports.sort();
    assert_eq!(
        ports,
        vec![
            7014u16.to_be_bytes().to_vec(),
            7015u16.to_be_bytes().to_vec()
        ]
    );
}

#[test]
fn nflog_with_conntrack_info() {
    let mut s = setup();
    add(
        &mut s,
        vec![
            // Conntrack is only active in a namespace when a rule needs it.
            rule("out")
                .match_eq(Field::UdpDport, 7016u16)
                .ct_state(NF_CT_STATE_NEW_BIT)
                .counter()
                .build(),
            rule("out")
                .match_eq(Field::UdpDport, 7016u16)
                .log_group(4, None)
                .build(),
        ],
    );
    // Conntrack attributes need the ctnetlink module; the conntrack tool
    // loads it on first use.
    conntrack(&["-L"]);
    let mut log = NflogSocket::new().unwrap();
    log.bind(&GroupConfig::new(4).conntrack(true)).unwrap();
    log.set_recv_timeout(Some(Duration::from_secs(3))).unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(b"1", "127.0.0.1:7016").unwrap();
    tx.send_to(b"2", "127.0.0.1:7016").unwrap();
    let mut infos = Vec::new();
    while infos.len() < 2 {
        for p in log.recv().unwrap() {
            let p = p.unwrap();
            assert!(
                p.ct.is_some_and(|c| !c.is_empty()),
                "conntrack attributes present"
            );
            infos.push(p.ct_info.unwrap());
        }
    }
    // IP_CT_NEW = 2 for the first packet, IP_CT_NEW again since unreplied.
    assert_eq!(infos, [2, 2]);
}

#[test]
fn ct_event_mask() {
    let mut s = setup();
    // Only report destroy events for this flow.
    add(
        &mut s,
        vec![
            rule("out")
                .match_eq(Field::UdpDport, 7017u16)
                .ct_state(NF_CT_STATE_NEW_BIT)
                .ct_set(CtKey::EventMask, 1u32 << 2)
                .build(),
        ],
    );
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"x", "127.0.0.1:7017")
        .unwrap();
    let ct = conntrack(&["-L", "-p", "udp", "--dport", "7017"]);
    assert!(ct.contains("dport=7017"), "{ct}");
}
