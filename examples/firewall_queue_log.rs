//! A simple firewall whose decisions are partly made in userspace, with
//! three independent sockets:
//!
//! * an nf_tables socket that installs the ruleset and reads counters,
//! * an NFQUEUE socket (queue 0) that inspects DNS-SD traffic and drops
//!   packets containing "bad",
//! * an NFLOG socket (group 1) that prints new HTTP connections.
//!
//! The table is created with the owner flag, so the kernel removes it when
//! the program exits; its policy is accept and SSH is always allowed, so it
//! cannot lock you out. The queue rule uses `bypass`: if the queue listener
//! is gone, packets are accepted.
//!
//! ```sh
//! sudo cargo run --example firewall_queue_log -- [seconds] [--demo]
//! ```
//!
//! With `--demo` the example also generates matching traffic on loopback.
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crabtables::nflog::{GroupConfig, NflogSocket};
use crabtables::nfqueue::{NfqSocket, QueueConfig, QueueVerdict};
use crabtables::sys::*;
use crabtables::*;

const QUEUE: u16 = 0;
const LOG_GROUP: u16 = 1;

fn ruleset() -> Batch {
    let (f, t) = (Family::Inet, "fw_example");
    let mut b = Batch::new();
    b.add_table(&Table::new(f, t).with_flags(NFT_TABLE_F_OWNER));
    b.add_chain(
        &Chain::new(f, t, "input")
            .with_hook(ChainType::Filter, Hook::INPUT, 0)
            .with_policy(Policy::Accept),
    );
    let r = || RuleBuilder::new(f, t, "input");
    b.add_rule(
        &r().ct_state(NF_CT_STATE_ESTABLISHED_BIT | NF_CT_STATE_RELATED_BIT)
            .accept()
            .build(),
    );
    b.add_rule(
        &r().match_eq(Field::TcpDport, 22u16)
            .counter()
            .comment("ssh")
            .accept()
            .build(),
    );
    b.add_rule(
        &r().ct_state(NF_CT_STATE_INVALID_BIT)
            .counter()
            .comment("invalid")
            .drop()
            .build(),
    );
    // Userspace inspection: UDP 5353 goes to queue 0 (accepted if nobody listens).
    b.add_rule(
        &r().match_eq(Field::UdpDport, 5353u16)
            .counter()
            .comment("queued")
            .queue(QUEUE, 1, NFT_QUEUE_FLAG_BYPASS)
            .build(),
    );
    // Log new HTTP connections to NFLOG group 1, then accept them.
    b.add_rule(
        &r().match_eq(Field::TcpDport, 80u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .log_group(LOG_GROUP, Some("http: "))
            .counter()
            .comment("http")
            .accept()
            .build(),
    );
    b
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seconds: u64 = args.iter().find_map(|a| a.parse().ok()).unwrap_or(30);
    let demo = args.iter().any(|a| a == "--demo");

    // 1. The ruleset, on its own socket (which owns the table).
    let mut nft = Socket::new()?;
    if let Err(e) = nft.commit(&ruleset()) {
        eprintln!("installing the ruleset failed: {e}");
        return Err(e);
    }
    println!("ruleset installed (removed automatically on exit)");

    // 2. NFQUEUE on a separate socket and thread.
    let mut queue = NfqSocket::new()?;
    queue.set_recv_buffer_size(4 << 20)?;
    queue.bind(&QueueConfig::new(QUEUE).fail_open(true))?;
    std::thread::spawn(move || -> Result<()> {
        let verdicts = queue.verdicts();
        loop {
            for p in queue.recv()? {
                let p = p?;
                // IPv4 + UDP headers are 28 bytes for packets without options.
                let data = p.payload.get(28..).unwrap_or(&[]);
                let bad = data.windows(3).any(|w| w == b"bad");
                let verdict = if bad {
                    QueueVerdict::Drop
                } else {
                    QueueVerdict::Accept
                };
                println!(
                    "[queue] packet {} ({} bytes): {verdict:?}",
                    p.id,
                    p.payload.len()
                );
                verdicts.verdict(p.queue, p.id, verdict)?;
            }
            let st = queue.stats();
            if st.lost > 0 {
                println!("[queue] lost {} packets", st.lost);
            }
        }
    });

    // 3. NFLOG on a separate socket and thread.
    let mut log = NflogSocket::new()?;
    log.set_recv_buffer_size(4 << 20)?;
    log.bind(&GroupConfig::new(LOG_GROUP))?;
    std::thread::spawn(move || -> Result<()> {
        loop {
            for p in log.recv()? {
                let p = p?;
                let src = p
                    .payload
                    .get(12..16)
                    .map(|a| std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]));
                println!(
                    "[log] {}from {:?} (seq {:?})",
                    p.prefix_str().unwrap_or(""),
                    src,
                    p.seq
                );
            }
            let st = log.stats();
            if st.lost > 0 || st.overruns > 0 {
                println!(
                    "[log] received {} lost {} overruns {}",
                    st.received, st.lost, st.overruns
                );
            }
        }
    });

    if demo {
        std::thread::spawn(|| {
            let _http = TcpListener::bind("127.0.0.1:80").ok();
            let dns = UdpSocket::bind("127.0.0.1:5353").ok();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            loop {
                let _ = tx.send_to(b"good query", "127.0.0.1:5353");
                let _ = tx.send_to(b"bad query", "127.0.0.1:5353");
                let _ = TcpStream::connect_timeout(
                    &"127.0.0.1:80".parse().unwrap(),
                    Duration::from_millis(200),
                );
                if let Some(d) = &dns {
                    d.set_nonblocking(true).unwrap();
                    let mut buf = [0u8; 64];
                    while let Ok(n) = d.recv(&mut buf) {
                        println!("[dns server] got {:?}", String::from_utf8_lossy(&buf[..n]));
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        std::thread::sleep(Duration::from_secs(2));
        for r in nft.list_rules(Family::Inet, Some("fw_example"), Some("input"))? {
            if let (Some(name), Some(c)) = (r.comment(), r.counters().next()) {
                println!(
                    "[counters] {name:>8}: {} packets, {} bytes",
                    c.packets, c.bytes
                );
            }
        }
    }
    println!("done");
    Ok(())
}
