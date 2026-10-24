//! Driving the sans-IO layer with our own I/O (a raw netlink-sys socket).
mod common;
use common::*;
use crabtables::proto::Request;
use crabtables::*;
use netlink_sys::{Socket as RawSocket, protocols::NETLINK_NETFILTER};

fn recv(sock: &RawSocket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(65536);
    sock.recv(&mut buf, 0).unwrap();
    buf
}

#[test]
fn custom_io() {
    netns();
    let mut sock = RawSocket::new(NETLINK_NETFILTER).unwrap();
    sock.bind_auto().unwrap();
    sock.set_ext_ack(true).unwrap();

    // A batch.
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Ipv4, "raw"));
    b.add_chain(&Chain::new(Family::Ipv4, "raw", "c"));
    let mut out = Vec::new();
    let mut resp = b.encode(&mut out, 1000).unwrap();
    sock.send(&out, 0).unwrap();
    resp.sentinel(&mut out);
    sock.send(&out, 0).unwrap();
    while !resp.is_done() {
        resp.feed(&recv(&sock)).unwrap();
    }
    let outcome = resp.finish(&b).unwrap();
    assert!(outcome.genid > 0);

    // A failing batch.
    let mut b = Batch::new();
    b.add_chain(&Chain::new(Family::Ipv4, "nope", "c"));
    let mut resp = b.encode(&mut out, 2000).unwrap();
    sock.send(&out, 0).unwrap();
    resp.sentinel(&mut out);
    sock.send(&out, 0).unwrap();
    while !resp.is_done() {
        resp.feed(&recv(&sock)).unwrap();
    }
    assert!(resp.finish(&b).unwrap_err().is_not_found());

    // A dump.
    let mut col = Request::chains(Family::Ipv4, None).encode(&mut out, 3000);
    sock.send(&out, 0).unwrap();
    let mut names = Vec::new();
    while !col.is_done() {
        col.feed(&recv(&sock), |m| {
            let (h, attrs) = m.nfgen()?;
            if let Some((_, Object::Chain(c))) = Object::decode(m.subtype(), h.family, attrs)? {
                names.push(c.name);
            }
            Ok(())
        })
        .unwrap();
    }
    col.finish().unwrap();
    assert_eq!(names, ["c"]);
    assert!(ruleset().contains("table ip raw"));
}
