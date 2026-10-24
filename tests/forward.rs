//! Forwarding through the test namespace between two other namespaces:
//! flowtable offload, NAT across interfaces, netdev ingress chains.
mod common;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

use common::*;
use crabtables::sys::*;
use crabtables::*;

const F: Family = Family::Inet;

fn counter(s: &mut Socket, family: Family, table: &str, chain: &str, comment: &str) -> u64 {
    s.list_rules(family, Some(table), Some(chain))
        .unwrap()
        .iter()
        .find(|r| r.comment() == Some(comment))
        .unwrap_or_else(|| panic!("no rule {comment}"))
        .counters()
        .map(|c| c.packets)
        .sum()
}

/// Start an echo server in `ns` on 0.0.0.0:port; peers are reported.
fn echo_server(ns: &NetnsThread, port: u16) -> std::sync::mpsc::Receiver<SocketAddr> {
    let (tx, rx) = std::sync::mpsc::channel();
    let l = ns.run(move || TcpListener::bind(("0.0.0.0", port)).unwrap());
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { break };
            let _ = tx.send(c.peer_addr().unwrap());
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
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

/// From `ns`, connect to `addr` and exchange `rounds` messages.
fn exchange(ns: &NetnsThread, addr: &str, rounds: usize) -> Result<(), String> {
    exchange_open(ns, addr, rounds).map(drop)
}

/// Like [`exchange`], but return the still open connection.
fn exchange_open(ns: &NetnsThread, addr: &str, rounds: usize) -> Result<TcpStream, String> {
    let addr: SocketAddr = addr.parse().unwrap();
    ns.run(move || {
        let mut c =
            TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| e.to_string())?;
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut buf = [0u8; 100];
        for i in 0..rounds {
            let msg = [i as u8; 100];
            c.write_all(&msg).map_err(|e| e.to_string())?;
            c.read_exact(&mut buf).map_err(|e| e.to_string())?;
            assert_eq!(buf, msg);
        }
        Ok(c)
    })
}

#[test]
fn plain_forwarding_and_counters() {
    let (client, server) = router_topology();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_chain(
        &Chain::new(F, "t", "fwd")
            .with_hook(ChainType::Filter, Hook::FORWARD, 0)
            .with_policy(Policy::Drop),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "fwd")
            .ct_state(NF_CT_STATE_ESTABLISHED_BIT | NF_CT_STATE_RELATED_BIT)
            .counter()
            .comment("est")
            .accept()
            .build(),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "fwd")
            .match_eq(Field::IifName, "c0")
            .match_eq(Field::OifName, "s0")
            .match_eq(Field::TcpDport, 80u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .counter()
            .comment("new")
            .accept()
            .build(),
    );
    s.commit(&b).unwrap();
    let _srv = echo_server(&server, 80);
    let _srv2 = echo_server(&server, 81);
    exchange(&client, "10.2.0.2:80", 5).unwrap();
    assert_eq!(counter(&mut s, F, "t", "fwd", "new"), 1);
    assert!(counter(&mut s, F, "t", "fwd", "est") >= 10);
    // Policy drop: port 81 is not allowed.
    assert!(exchange(&client, "10.2.0.2:81", 1).is_err());
}

#[test]
fn flowtable_offload() {
    let (client, server) = router_topology();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_flowtable(&Flowtable {
        family: F,
        table: "t".into(),
        name: "ft".into(),
        hook: Some(Hook::NETDEV_INGRESS),
        priority: Some(0),
        devices: vec!["c0".into(), "s0".into()],
        flags: Some(NFT_FLOWTABLE_COUNTER),
        ..Default::default()
    });
    b.add_chain(&Chain::new(F, "t", "fwd").with_hook(ChainType::Filter, Hook::FORWARD, 0));
    b.add_rule(
        &RuleBuilder::new(F, "t", "fwd")
            .match_eq(Field::L4Proto, libc::IPPROTO_TCP as u8)
            .ct_state(NF_CT_STATE_ESTABLISHED_BIT)
            .expr(expr::FlowOffload {
                table_name: "ft".into(),
            })
            .build(),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "fwd")
            .match_eq(Field::L4Proto, libc::IPPROTO_TCP as u8)
            .counter()
            .comment("slow")
            .build(),
    );
    s.commit(&b).unwrap();
    assert_contains_lines(
        &ruleset(),
        "flowtable ft {\nhook ingress priority filter\ndevices = { c0, s0 }\ncounter\n}",
    );
    let ft = &s.list_flowtables(F, Some("t")).unwrap()[0];
    let mut devs = ft.devices.clone();
    devs.sort();
    assert_eq!(devs, ["c0", "s0"]);

    let _srv = echo_server(&server, 80);
    let conn = exchange_open(&client, "10.2.0.2:80", 200).unwrap();
    let ct = String::from_utf8(
        Command::new("conntrack")
            .args(["-L", "-p", "tcp"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(ct.contains("[OFFLOAD"), "{ct}");
    drop(conn);
    // ~400 data packets plus handshake went through, but only the first few
    // were seen by the forward chain before the flow was offloaded.
    let slow = counter(&mut s, F, "t", "fwd", "slow");
    assert!(slow < 50, "{slow} packets on the slow path");
}

#[test]
fn nat_across_interfaces() {
    let (client, server) = router_topology();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Ipv4, "nat"));
    b.add_chain(&Chain::new(Family::Ipv4, "nat", "pre").with_hook(
        ChainType::Nat,
        Hook::PREROUTING,
        -100,
    ));
    b.add_chain(&Chain::new(Family::Ipv4, "nat", "post").with_hook(
        ChainType::Nat,
        Hook::POSTROUTING,
        100,
    ));
    let r = |c: &str| RuleBuilder::new(Family::Ipv4, "nat", c);
    // Port forwarding: 10.1.0.1:8080 -> 10.2.0.2:80
    b.add_rule(
        &r("pre")
            .match_eq(Field::IifName, "c0")
            .match_eq(Field::TcpDport, 8080u16)
            .dnat("10.2.0.2".parse().unwrap(), Some(80))
            .build(),
    );
    b.add_rule(
        &r("post")
            .match_eq(Field::OifName, "s0")
            .masquerade(0)
            .build(),
    );
    s.commit(&b).unwrap();
    let peers = echo_server(&server, 80);
    exchange(&client, "10.1.0.1:8080", 3).unwrap();
    // The server sees the router's address (masquerade).
    assert_eq!(
        peers
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .ip()
            .to_string(),
        "10.2.0.1"
    );
    let ct = String::from_utf8(
        Command::new("conntrack")
            .args(["-L", "-p", "tcp"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(
        ct.contains("src=10.1.0.2 dst=10.1.0.1")
            && ct.contains("dport=8080 src=10.2.0.2 dst=10.2.0.1 sport=80"),
        "{ct}"
    );
}

#[test]
fn netdev_ingress_and_egress() {
    let (client, server) = router_topology();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Netdev, "nd"));
    b.add_chain(
        &Chain::new(Family::Netdev, "nd", "in")
            .with_hook(ChainType::Filter, Hook::NETDEV_INGRESS, 0)
            .with_devices(["c0"]),
    );
    b.add_chain(
        &Chain::new(Family::Netdev, "nd", "out")
            .with_hook(ChainType::Filter, Hook::NETDEV_EGRESS, 0)
            .with_devices(["s0"]),
    );
    let r = |c: &str| RuleBuilder::new(Family::Netdev, "nd", c);
    b.add_rule(
        &r("in")
            .match_eq(Field::Meta(MetaKey::Protocol, 2), 0x0800u16.to_be_bytes())
            .counter()
            .comment("ipv4")
            .build(),
    );
    b.add_rule(
        &r("in")
            .match_eq(Field::TcpDport, 81u16)
            .counter()
            .comment("drop81")
            .drop()
            .build(),
    );
    b.add_rule(
        &r("out")
            .match_eq(Field::TcpDport, 80u16)
            .counter()
            .comment("egress")
            .build(),
    );
    s.commit(&b).unwrap();
    let _srv = echo_server(&server, 80);
    let _srv2 = echo_server(&server, 81);
    exchange(&client, "10.2.0.2:80", 2).unwrap();
    assert!(exchange(&client, "10.2.0.2:81", 1).is_err());
    assert!(counter(&mut s, Family::Netdev, "nd", "in", "ipv4") >= 4);
    assert!(counter(&mut s, Family::Netdev, "nd", "in", "drop81") >= 1);
    assert!(counter(&mut s, Family::Netdev, "nd", "out", "egress") >= 3);
    let c = s.get_chain(Family::Netdev, "nd", "in").unwrap();
    assert_eq!(c.hook.unwrap().devices, ["c0"]);
}

#[test]
fn bridge_family() {
    netns();
    let client = NetnsThread::new();
    let server = NetnsThread::new();
    ip("link add br0 type bridge");
    for (dev, peer, ns, addr) in [
        ("c0", "c1", &client, "10.3.0.2/24"),
        ("s0", "s1", &server, "10.3.0.3/24"),
    ] {
        ip(&format!("link add {dev} type veth peer name {peer}"));
        ip(&format!("link set {peer} netns {}", ns.tid));
        ip(&format!("link set {dev} master br0"));
        ip(&format!("link set {dev} up"));
        ns.ip(&format!("addr add {addr} dev {peer}"));
        ns.ip(&format!("link set {peer} up"));
    }
    ip("link set br0 up");
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    let f = Family::Bridge;
    b.add_table(&Table::new(f, "br"));
    b.add_chain(&Chain::new(f, "br", "fwd").with_hook(ChainType::Filter, Hook::FORWARD, 0));
    let r = || RuleBuilder::new(f, "br", "fwd");
    b.add_rule(
        &r().match_eq(Field::Meta(MetaKey::IifName, 16), "c0")
            .match_eq(Field::Meta(MetaKey::BriIifName, 16), "br0")
            .counter()
            .comment("from-client")
            .build(),
    );
    b.add_rule(
        &r().match_eq(
            Field::Payload {
                base: PayloadBase::LinkLayer,
                offset: 12,
                len: 2,
            },
            0x0806u16.to_be_bytes(),
        )
        .counter()
        .comment("arp")
        .build(),
    );
    b.add_rule(
        &r().match_eq(Field::TcpDport, 81u16)
            .counter()
            .comment("drop81")
            .drop()
            .build(),
    );
    b.add_rule(
        &r().ct_state(NF_CT_STATE_ESTABLISHED_BIT)
            .counter()
            .comment("est")
            .build(),
    );
    s.commit(&b).unwrap();
    let _srv = echo_server(&server, 80);
    let _srv2 = echo_server(&server, 81);
    exchange(&client, "10.3.0.3:80", 3).unwrap();
    assert!(exchange(&client, "10.3.0.3:81", 1).is_err());
    assert!(counter(&mut s, f, "br", "fwd", "from-client") >= 5);
    assert!(counter(&mut s, f, "br", "fwd", "arp") >= 2);
    assert!(counter(&mut s, f, "br", "fwd", "drop81") >= 1);
    assert!(
        counter(&mut s, f, "br", "fwd", "est") >= 4,
        "bridge conntrack"
    );
}
