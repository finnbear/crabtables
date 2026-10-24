//! NFQUEUE with real packets over loopback.
mod common;
use std::net::UdpSocket;
use std::time::Duration;

use common::*;
use crabtables::nflog::CopyMode;
use crabtables::nfqueue::*;
use crabtables::sys::*;
use crabtables::*;

const F: Family = Family::Inet;

/// Output chain `out` (priority 0) queueing UDP to `port` into `queue`
/// with `flags`, and chain `after` (priority 10) counting packets that
/// come back, with and without mark 0x7.
fn setup(rules: &[(u16, u16, u16, u16)]) -> Socket {
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_chain(&Chain::new(F, "t", "out").with_hook(ChainType::Filter, Hook::OUTPUT, 0));
    b.add_chain(&Chain::new(F, "t", "after").with_hook(ChainType::Filter, Hook::OUTPUT, 10));
    for &(port, queue, count, flags) in rules {
        b.add_rule(
            &RuleBuilder::new(F, "t", "out")
                .match_eq(Field::UdpDport, port)
                .queue(queue, count, flags)
                .build(),
        );
        b.add_rule(
            &RuleBuilder::new(F, "t", "after")
                .match_eq(Field::UdpDport, port)
                .counter()
                .comment(&format!("p{port}"))
                .build(),
        );
        b.add_rule(
            &RuleBuilder::new(F, "t", "after")
                .match_eq(Field::UdpDport, port)
                .match_eq(Field::Mark, 7u32)
                .counter()
                .comment(&format!("m{port}"))
                .build(),
        );
    }
    s.commit(&b).unwrap();
    s
}

fn counter(s: &mut Socket, comment: &str) -> u64 {
    s.list_rules(F, Some("t"), Some("after"))
        .unwrap()
        .iter()
        .find(|r| r.comment() == Some(comment))
        .unwrap()
        .counters()
        .map(|c| c.packets)
        .sum()
}

fn send(port: u16, payload: &[u8]) {
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.set_nonblocking(true).unwrap();
    // A queued packet blocks the sending call until the verdict on some
    // kernels paths; non-blocking sends return immediately.
    let _ = tx.send_to(payload, ("127.0.0.1", port));
}

fn read(rx: &UdpSocket) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = rx.recv(&mut buf).unwrap();
    buf[..n].to_vec()
}

fn sink(port: u16) -> UdpSocket {
    let s = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    s
}

fn recv_one(q: &mut NfqSocket) -> OwnedQ {
    q.set_recv_timeout(Some(Duration::from_secs(3))).unwrap();
    let p = q.recv().unwrap().next().expect("a packet").unwrap();
    OwnedQ {
        queue: p.queue,
        id: p.id,
        payload: p.payload.to_vec(),
        mark: p.mark,
        uid: p.uid,
        ct: p.ct.is_some(),
        hook: p.hook,
    }
}

#[derive(Debug)]
struct OwnedQ {
    queue: u16,
    id: u32,
    payload: Vec<u8>,
    mark: Option<u32>,
    uid: Option<u32>,
    ct: bool,
    hook: u8,
}

#[test]
fn accept_drop_and_mark() {
    netns();
    let mut s = setup(&[(6000, 3, 1, 0)]);
    let rx = sink(6000);
    let mut q = NfqSocket::new().unwrap();
    q.bind(&QueueConfig::new(3)).unwrap();

    send(6000, b"first");
    let p = recv_one(&mut q);
    assert_eq!((p.queue, p.id, p.hook), (3, 1, NF_INET_LOCAL_OUT as u8));
    assert!(p.payload.ends_with(b"first"));
    q.verdict(3, p.id, QueueVerdict::Accept).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(read(&rx), b"first");

    send(6000, b"second");
    let p = recv_one(&mut q);
    q.verdict(3, p.id, QueueVerdict::Drop).unwrap();
    assert!(rx.recv(&mut buf).is_err(), "dropped");

    send(6000, b"third");
    let p = recv_one(&mut q);
    q.verdicts()
        .verdict_with(
            3,
            p.id,
            QueueVerdict::Accept,
            &VerdictOptions {
                mark: Some(7),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(read(&rx), b"third");
    assert_eq!(counter(&mut s, "p6000"), 2);
    assert_eq!(counter(&mut s, "m6000"), 1, "verdict mark applied");
    let st = q.stats();
    assert_eq!((st.received, st.lost, st.verdict_errors), (3, 0, 0));
}

#[test]
fn mangle_payload() {
    netns();
    let _s = setup(&[(6001, 3, 1, 0)]);
    let rx = sink(6001);
    let mut q = NfqSocket::new().unwrap();
    q.bind(&QueueConfig::new(3)).unwrap();
    send(6001, b"hello");
    let p = recv_one(&mut q);
    // IPv4 (20) + UDP (8) + "hello". Rewrite the payload, clear the UDP
    // checksum (optional for IPv4) and fix the IP header checksum (the
    // length is unchanged).
    let mut pkt = p.payload.clone();
    pkt[28..33].copy_from_slice(b"HELLO");
    pkt[26] = 0;
    pkt[27] = 0;
    q.verdicts()
        .verdict_with(
            3,
            p.id,
            QueueVerdict::Accept,
            &VerdictOptions {
                payload: Some(&pkt),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(read(&rx), b"HELLO");
}

#[test]
fn repeat_and_requeue() {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_chain(&Chain::new(F, "t", "out").with_hook(ChainType::Filter, Hook::OUTPUT, 0));
    // Queue unmarked packets; a repeated packet carrying mark 1 passes.
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 6002u16)
            .match_neq(Field::Mark, 1u32)
            .queue(4, 1, 0)
            .build(),
    );
    s.commit(&b).unwrap();
    let rx = sink(6002);
    let mut q4 = NfqSocket::new().unwrap();
    q4.bind(&QueueConfig::new(4)).unwrap();
    let mut q5 = NfqSocket::new().unwrap();
    q5.bind(&QueueConfig::new(5)).unwrap();

    send(6002, b"r");
    let p = recv_one(&mut q4);
    q4.verdicts()
        .verdict_with(
            4,
            p.id,
            QueueVerdict::Repeat,
            &VerdictOptions {
                mark: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(read(&rx), b"r", "repeated with mark 1, then accepted");

    // Requeue to queue 5: the packet arrives there with a new id.
    send(6002, b"q");
    let p = recv_one(&mut q4);
    q4.verdict(4, p.id, QueueVerdict::Queue(5)).unwrap();
    let p5 = recv_one(&mut q5);
    assert_eq!(p5.queue, 5);
    assert!(p5.payload.ends_with(b"q"));
    q5.verdict(5, p5.id, QueueVerdict::Accept).unwrap();
    assert_eq!(read(&rx), b"q");
}

#[test]
fn batch_verdict_and_handles_from_threads() {
    netns();
    let mut s = setup(&[(6003, 6, 1, 0)]);
    let rx = sink(6003);
    let mut q = NfqSocket::new().unwrap();
    q.bind(&QueueConfig::new(6).copy_mode(CopyMode::Meta))
        .unwrap();
    for _ in 0..10 {
        send(6003, b"b");
    }
    let mut ids = Vec::new();
    q.set_recv_timeout(Some(Duration::from_secs(3))).unwrap();
    while ids.len() < 10 {
        for p in q.recv().unwrap() {
            let p = p.unwrap();
            assert!(p.payload.is_empty(), "meta copy mode");
            ids.push(p.id);
        }
    }
    assert_eq!(ids, (1..=10).collect::<Vec<_>>());
    // Accept 1..=6 at once with a mark, the rest from another thread.
    q.verdicts()
        .verdict_batch(6, 6, QueueVerdict::Accept, Some(7))
        .unwrap();
    let h = q.verdicts();
    std::thread::spawn(move || {
        for id in 7..=10 {
            h.verdict(6, id, QueueVerdict::Accept).unwrap();
        }
    })
    .join()
    .unwrap();
    let mut buf = [0u8; 8];
    for _ in 0..10 {
        rx.recv(&mut buf).unwrap();
    }
    assert_eq!(counter(&mut s, "m6003"), 6);
    assert_eq!(counter(&mut s, "p6003"), 10);
}

#[test]
fn fail_open_max_len_and_bypass() {
    netns();
    let _s = setup(&[
        (6004, 7, 1, 0),
        (6005, 8, 1, NFT_QUEUE_FLAG_BYPASS),
        (6006, 9, 1, 0),
    ]);
    let rx = sink(6004);
    let mut buf = [0u8; 8];

    // A full queue with fail-open accepts packets without queueing them.
    let mut q = NfqSocket::new().unwrap();
    q.bind(&QueueConfig::new(7).max_len(2).fail_open(true))
        .unwrap();
    for _ in 0..5 {
        send(6004, b"f");
    }
    let mut passed = 0;
    while rx.recv(&mut buf).is_ok() {
        passed += 1;
    }
    assert_eq!(passed, 3, "two held in the queue, three passed");
    let ps = proc_stats().unwrap();
    let st = ps.iter().find(|p| p.queue == 7).unwrap();
    assert_eq!((st.waiting, st.queue_dropped), (2, 0));

    // Without fail-open, the excess is dropped and counted by the kernel.
    q.configure(&QueueConfig::new(7).max_len(2).fail_open(false))
        .unwrap();
    for _ in 0..3 {
        send(6004, b"d");
    }
    assert!(rx.recv(&mut buf).is_err());
    let ps = proc_stats().unwrap();
    assert_eq!(ps.iter().find(|p| p.queue == 7).unwrap().queue_dropped, 3);

    // No listener: bypass accepts, otherwise drop.
    let rx5 = sink(6005);
    send(6005, b"y");
    assert_eq!(read(&rx5), b"y");
    let rx6 = sink(6006);
    send(6006, b"n");
    assert!(rx6.recv(&mut buf).is_err());

    // Unbinding drops the packets still waiting for a verdict.
    q.unbind(7).unwrap();
    assert!(rx.recv(&mut buf).is_err());
    std::thread::sleep(Duration::from_millis(50));
    assert!(proc_stats().unwrap().iter().all(|p| p.queue != 7));
}

/// Overflow the socket: the kernel drops packets it cannot deliver and the
/// id gaps account for every one of them.
#[test]
fn overflow_accounting() {
    netns();
    let _s = setup(&[(6007, 10, 1, 0)]);
    let _rx = sink(6007);
    let mut q = NfqSocket::new().unwrap();
    q.set_recv_buffer_size(4096).unwrap();
    q.bind(&QueueConfig::new(10).max_len(100_000)).unwrap();
    const N: u64 = 2000;
    for _ in 0..N {
        send(6007, &[0; 200]);
    }
    let v = q.verdicts();
    let drain = |q: &mut NfqSocket| {
        while let Some(pkts) = q.try_recv().unwrap() {
            for p in pkts {
                let p = p.unwrap();
                v.verdict(p.queue, p.id, QueueVerdict::Accept).unwrap();
            }
        }
    };
    drain(&mut q);
    send(6007, &[0; 200]);
    std::thread::sleep(Duration::from_millis(50));
    drain(&mut q);
    let st = q.stats();
    let ps = proc_stats().unwrap();
    let kernel = ps.iter().find(|p| p.queue == 10).unwrap();
    assert!(st.overruns >= 1 && st.lost > 0, "{st:?}");
    assert_eq!(st.received + st.lost, N + 1, "{st:?}");
    assert_eq!(st.lost, u64::from(kernel.user_dropped), "{st:?} {kernel:?}");
    assert_eq!(u64::from(kernel.id_sequence), N + 1);
}

#[test]
fn metadata_flags() {
    netns();
    let mut s = setup(&[(6008, 11, 1, 0)]);
    // Conntrack must be active for ct information.
    let mut b = Batch::new();
    b.add_rule(
        &RuleBuilder::new(F, "t", "after")
            .ct_state(NF_CT_STATE_NEW_BIT)
            .build(),
    );
    s.commit(&b).unwrap();
    let _ = std::process::Command::new("conntrack").arg("-L").output();
    let _rx = sink(6008);
    let mut q = NfqSocket::new().unwrap();
    q.bind(&QueueConfig::new(11).uid_gid(true).conntrack(true))
        .unwrap();
    send(6008, b"m");
    let p = recv_one(&mut q);
    assert_eq!(p.uid, Some(0));
    assert!(p.ct, "conntrack attributes");
    assert_eq!(p.mark, None);
    q.verdict(11, p.id, QueueVerdict::Accept).unwrap();

    // A verdict for an unknown id is reported by the kernel.
    q.verdict(11, 999, QueueVerdict::Accept).unwrap();
    send(6008, b"m");
    let _ = recv_one(&mut q);
    assert_eq!(q.stats().verdict_errors, 1);
}

#[test]
fn isolation_and_fanout() {
    netns();
    let _s = setup(&[(6009, 12, 2, NFT_QUEUE_FLAG_CPU_FANOUT)]);
    let _rx = sink(6009);
    let mut a = NfqSocket::new().unwrap();
    a.bind(&QueueConfig::new(12)).unwrap();
    let mut b = NfqSocket::new().unwrap();
    b.bind(&QueueConfig::new(13)).unwrap();
    let mut c = NfqSocket::new().unwrap();
    assert_eq!(
        c.bind(&QueueConfig::new(12)).unwrap_err().errno(),
        Some(libc::EPERM)
    );
    assert_eq!(
        a.bind(&QueueConfig::new(12)).unwrap_err().errno(),
        Some(libc::EBUSY)
    );
    // Fanout by CPU: all packets from this thread go to one of 12, 13.
    for _ in 0..4 {
        send(6009, b"x");
    }
    let mut got = 0;
    for q in [&mut a, &mut b] {
        while let Some(pkts) = q.try_recv().unwrap() {
            for p in pkts {
                let p = p.unwrap();
                assert!(p.queue == 12 || p.queue == 13);
                got += 1;
            }
        }
    }
    assert_eq!(got, 4);
    // Another socket can use the same queue numbers in another namespace,
    // and nf_tables sockets work alongside.
    let mut nft_sock = Socket::new().unwrap();
    assert_eq!(nft_sock.list_tables(F).unwrap().len(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn async_queue() {
    netns();
    let _s = setup(&[(6010, 14, 1, 0)]);
    let rx = sink(6010);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut q = AsyncNfqSocket::new().unwrap();
        q.bind(&QueueConfig::new(14)).await.unwrap();
        let v = q.verdicts();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), q.recv())
                .await
                .is_err()
        );
        for i in 0..5u8 {
            send(6010, &[i]);
        }
        let mut n = 0;
        while n < 5 {
            for p in tokio::time::timeout(Duration::from_secs(3), q.recv())
                .await
                .unwrap()
                .unwrap()
            {
                let p = p.unwrap();
                v.verdict(
                    p.queue,
                    p.id,
                    if n % 2 == 0 {
                        QueueVerdict::Accept
                    } else {
                        QueueVerdict::Drop
                    },
                )
                .unwrap();
                n += 1;
            }
        }
    });
    let mut buf = [0u8; 4];
    let mut got = Vec::new();
    while let Ok(n) = rx.recv(&mut buf) {
        got.push(buf[..n].to_vec());
    }
    assert_eq!(got, vec![vec![0], vec![2], vec![4]]);
}

/// A failed re-bind keeps the loss accounting of the existing binding.
#[test]
fn failed_rebind_keeps_tracking() {
    netns();
    let _s = setup(&[(6000, 3, 1, 0)]);
    let _rx = sink(6000);
    let mut q = NfqSocket::new().unwrap();
    q.bind(&QueueConfig::new(3)).unwrap();
    for _ in 0..3 {
        send(6000, b"x");
        let p = recv_one(&mut q);
        q.verdict(3, p.id, QueueVerdict::Accept).unwrap();
    }
    assert!(q.bind(&QueueConfig::new(3)).is_err());
    send(6000, b"x");
    let p = recv_one(&mut q);
    assert_eq!(p.id, 4);
    q.verdict(3, p.id, QueueVerdict::Accept).unwrap();
    assert_eq!(q.stats().lost, 0);
}
