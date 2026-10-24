mod common;
use common::*;
use crabtables::monitor::{Event, Monitor};
use crabtables::*;

#[test]
fn monitor_sees_changes_from_nft_and_us() {
    netns();
    let mut m = Monitor::new().unwrap();
    assert!(m.try_recv().unwrap().is_empty());
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(&Chain::new(Family::Inet, "t", "c"));
    b.add_rule(&RuleBuilder::new(Family::Inet, "t", "c").counter().build());
    let out = s.commit(&b).unwrap();
    let ev = m.recv().unwrap();
    let ev = if ev.len() < 4 {
        [ev, m.recv().unwrap()].concat()
    } else {
        ev
    };
    assert!(
        matches!(&ev[0], Event::New(Object::Table(t)) if t.name == "t"),
        "{ev:?}"
    );
    assert!(matches!(&ev[1], Event::New(Object::Chain(c)) if c.name == "c"));
    assert!(matches!(&ev[2], Event::New(Object::Rule(r)) if r.handle.is_some()));
    match &ev[3] {
        Event::Commit(g) => assert_eq!(g.id, out.genid),
        e => panic!("{e:?}"),
    }

    nft(&["delete", "table", "inet", "t"]);
    let mut ev = Vec::new();
    while !ev.iter().any(|e| matches!(e, Event::Commit(_))) {
        ev.extend(m.recv().unwrap());
    }
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Del(Object::Table(t)) if t.name == "t")),
        "{ev:?}"
    );
    match ev.last().unwrap() {
        Event::Commit(g) => assert_eq!(g.proc_name.as_deref(), Some("nft")),
        e => panic!("{e:?}"),
    }
}

#[test]
fn packet_trace() {
    use crabtables::monitor::TraceType;
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(&Chain::new(Family::Inet, "t", "pre").with_hook(
        ChainType::Filter,
        Hook::OUTPUT,
        -10,
    ));
    b.add_chain(&Chain::new(Family::Inet, "t", "out").with_hook(
        ChainType::Filter,
        Hook::OUTPUT,
        0,
    ));
    b.add_rule(
        &RuleBuilder::new(Family::Inet, "t", "pre")
            .match_eq(Field::UdpDport, 5000u16)
            .expr(expr::Immediate {
                dreg: Reg::R1,
                data: Data::Value(1u32.to_ne_bytes().to_vec()),
            })
            .expr(expr::Meta {
                dreg: None,
                key: MetaKey::NfTrace,
                sreg: Some(Reg::R1),
            })
            .build(),
    );
    b.add_rule(
        &RuleBuilder::new(Family::Inet, "t", "out")
            .match_eq(Field::UdpDport, 5000u16)
            .counter()
            .accept()
            .build(),
    );
    s.commit(&b).unwrap();
    let mut m = Monitor::with_trace().unwrap();
    let _sink = std::net::UdpSocket::bind("127.0.0.1:5000").unwrap();
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"x", "127.0.0.1:5000")
        .unwrap();
    m.set_recv_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut traces = Vec::new();
    while !traces.iter().any(|t: &crabtables::monitor::Trace| {
        t.chain.as_deref() == Some("out") && t.ty == Some(TraceType::Rule)
    }) {
        for e in m.recv().unwrap() {
            if let Event::Trace(t) = e {
                traces.push(t);
            }
        }
    }
    let rule = s.list_rules(Family::Inet, Some("t"), Some("out")).unwrap()[0].handle;
    let hit = traces
        .iter()
        .find(|t| t.chain.as_deref() == Some("out"))
        .unwrap();
    assert_eq!(hit.rule_handle, rule);
    assert_eq!(hit.verdict, Some(Verdict::Accept));
    assert_eq!(hit.table.as_deref(), Some("t"));
    assert!(traces.iter().all(|t| t.id == traces[0].id), "same packet");
}

/// A receive timeout is a `WouldBlock` error, not an empty list.
#[test]
fn recv_timeout() {
    netns();
    let mut m = Monitor::new().unwrap();
    m.set_recv_timeout(Some(std::time::Duration::from_millis(50)))
        .unwrap();
    let e = m.recv().unwrap_err();
    assert!(
        matches!(&e, crabtables::Error::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "{e:?}"
    );
    assert!(m.try_recv().unwrap().is_empty());
}

/// Events decoded before and after an undecodable message are kept.
#[test]
fn parse_events_keeps_decoded() {
    // A NEWTABLE message (inet) with the given attributes.
    let msg = |attrs: &[u8]| {
        let mut m = Vec::new();
        m.extend_from_slice(&(20 + attrs.len() as u32).to_ne_bytes());
        m.extend_from_slice(&(10u16 << 8).to_ne_bytes()); // NFT_MSG_NEWTABLE
        m.extend_from_slice(&[0; 10]); // flags, seq, pid
        m.extend_from_slice(&[1, 0, 0, 0]); // nfgenmsg
        m.extend_from_slice(attrs);
        m
    };
    let good = msg(&[6, 0, 1, 0, b't', 0, 0, 0]); // NFTA_TABLE_NAME "t"
    let bad = msg(&[2, 0, 1, 0]); // attribute shorter than its header
    let buf = [good.clone(), bad, good].concat();
    let mut out = Vec::new();
    let r = crabtables::monitor::parse_events(&buf, &mut out);
    assert!(r.is_err());
    assert_eq!(out.len(), 2, "{out:?}");
}
