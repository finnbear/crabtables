#![cfg(feature = "tokio")]
mod common;
use std::net::UdpSocket;
use std::time::Duration;

use common::*;
use crabtables::nflog::GroupConfig;
use crabtables::*;

fn rt() -> tokio::runtime::Runtime {
    // Current-thread runtime: everything stays in the test's network namespace.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn async_commit_and_dump() {
    netns();
    rt().block_on(async {
        let mut s = AsyncSocket::new().unwrap();
        let mut b = Batch::new();
        b.add_table(&Table::new(Family::Ipv4, "a"));
        b.add_chain(&Chain::new(Family::Ipv4, "a", "c"));
        for i in 0..100u16 {
            b.add_rule(
                &RuleBuilder::new(Family::Ipv4, "a", "c")
                    .match_eq(Field::TcpDport, i)
                    .counter()
                    .accept()
                    .build(),
            );
        }
        let out = s.commit(&b).await.unwrap();
        assert_eq!(s.get_gen().await.unwrap(), out.genid);
        let rules = s.list_rules(Family::Ipv4, Some("a"), None).await.unwrap();
        assert_eq!(rules.len(), 100);
        let rs = s.list_ruleset(Family::Unspec).await.unwrap();
        assert_eq!(rs.rules.len(), 100);

        // Errors are reported the same way.
        let mut b = Batch::new();
        b.add_rule(&RuleBuilder::new(Family::Ipv4, "a", "nope").accept().build());
        let e = s.commit(&b).await.unwrap_err();
        assert!(e.is_not_found(), "{e}");
    });
    assert!(ruleset().contains("tcp dport 99 counter packets 0 bytes 0 accept"));
}

#[test]
fn async_nflog() {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(&Chain::new(Family::Inet, "t", "out").with_hook(
        ChainType::Filter,
        Hook::OUTPUT,
        0,
    ));
    b.add_rule(
        &RuleBuilder::new(Family::Inet, "t", "out")
            .match_eq(Field::UdpDport, 9999u16)
            .log_group(3, Some("async"))
            .build(),
    );
    s.commit(&b).unwrap();
    let _sink = UdpSocket::bind("127.0.0.1:9999").unwrap();

    rt().block_on(async {
        let mut log = AsyncNflogSocket::new().unwrap();
        log.bind(&GroupConfig::new(3)).await.unwrap();
        // Nothing yet: recv must not complete.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), log.recv())
                .await
                .is_err()
        );
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = tokio::spawn(async move {
            for _ in 0..20 {
                tx.send_to(b"ping", "127.0.0.1:9999").unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        let mut n = 0;
        while n < 20 {
            let pkts = tokio::time::timeout(Duration::from_secs(5), log.recv())
                .await
                .expect("timeout")
                .unwrap();
            for p in pkts {
                let p = p.unwrap();
                assert_eq!(p.prefix_str(), Some("async"));
                assert!(p.payload.ends_with(b"ping"));
                n += 1;
            }
        }
        sender.await.unwrap();
        assert_eq!(log.stats().received, 20);
        assert_eq!(log.stats().lost, 0);
    });
}
