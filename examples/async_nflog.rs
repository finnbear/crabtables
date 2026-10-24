//! NFLOG with tokio, alongside ruleset monitoring.
//!
//! ```sh
//! sudo cargo run --features tokio --example async_nflog -- 5
//! ```
use crabtables::nflog::GroupConfig;
use crabtables::{AsyncMonitor, AsyncNflogSocket};

#[tokio::main(flavor = "current_thread")]
async fn main() -> crabtables::Result<()> {
    let group: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let mut log = AsyncNflogSocket::new()?;
    log.bind(&GroupConfig::new(group)).await?;
    let mut mon = AsyncMonitor::new()?;
    loop {
        tokio::select! {
            pkts = log.recv() => {
                for p in pkts? {
                    let p = p?;
                    println!("log: {} {} bytes", p.prefix_str().unwrap_or(""), p.payload.len());
                }
            }
            events = mon.recv() => {
                for e in events? {
                    println!("ruleset: {e:?}");
                }
            }
        }
    }
}
