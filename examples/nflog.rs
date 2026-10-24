//! Print packets logged with `log group N`.
//!
//! ```sh
//! sudo nft add rule inet filter input tcp dport 22 log group 5
//! sudo cargo run --example nflog -- 5
//! ```
use crabtables::nflog::{GroupConfig, NflogSocket};

fn main() -> crabtables::Result<()> {
    let group: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let mut sock = NflogSocket::new()?;
    // A large buffer absorbs bursts; losses are counted either way.
    sock.set_recv_buffer_size(8 << 20)?;
    sock.bind(&GroupConfig::new(group))?;
    println!("listening on NFLOG group {group}");
    loop {
        for pkt in sock.recv()? {
            let p = pkt?;
            println!(
                "{} seq={:?} hook={} in={:?} out={:?} mark={:?} {} bytes",
                p.prefix_str().unwrap_or(""),
                p.seq,
                p.hook,
                p.indev,
                p.outdev,
                p.mark,
                p.payload.len()
            );
        }
        let st = sock.stats();
        if st.lost > 0 {
            println!(
                "received {}, lost {} ({} overruns)",
                st.received, st.lost, st.overruns
            );
        }
    }
}
