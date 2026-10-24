//! A small firewall built in one atomic transaction.
//!
//! The table is created with the "owner" flag: the kernel removes it as soon
//! as this process exits, so it is safe to try out (it also only uses
//! policy `accept`).
//!
//! ```sh
//! sudo cargo run --example firewall
//! ```
use std::time::Duration;

use crabtables::sys::*;
use crabtables::*;

fn main() -> Result<()> {
    let mut sock = Socket::new()?;
    let (f, t) = (Family::Inet, "example");
    let mut b = Batch::new();
    b.add_table(&Table::new(f, t).with_flags(NFT_TABLE_F_OWNER));

    // An interval set of blocked networks.
    b.add_set(&Set::keyed(f, t, "blocked", &[Field::IpSaddr]).with_flags(NFT_SET_INTERVAL));
    let mut blocked = SetElemList::new(f, t, "blocked");
    blocked
        .elems
        .extend(SetElem::range(&[192, 0, 2, 0], &[192, 0, 2, 255], None)?);
    blocked.elems.extend(SetElem::range(
        &[198, 51, 100, 0],
        &[198, 51, 100, 255],
        None,
    )?);
    b.add_elems(&blocked);

    // A meter: per-source rate limit on new SSH connections, remembered
    // for one minute.
    b.add_set(
        &Set::keyed(f, t, "ssh_meter", &[Field::IpSaddr])
            .with_flags(NFT_SET_EVAL)
            .with_timeout(Duration::from_secs(60)),
    );

    // A verdict map dispatching by destination port.
    b.add_chain(&Chain::new(f, t, "web"));
    b.add_rule(
        &RuleBuilder::new(f, t, "web")
            .counter()
            .comment("web traffic")
            .accept()
            .build(),
    );
    b.add_set(&Set::keyed(f, t, "ports", &[Field::TcpDport]).vmap());
    b.add_elems(
        &SetElemList::new(f, t, "ports")
            .with(
                SetElem::new(80u16.to_be_bytes().to_vec())
                    .with_verdict(Verdict::Jump("web".into())),
            )
            .with(
                SetElem::new(443u16.to_be_bytes().to_vec())
                    .with_verdict(Verdict::Jump("web".into())),
            ),
    );

    b.add_chain(
        &Chain::new(f, t, "input")
            .with_hook(ChainType::Filter, Hook::INPUT, 0)
            .with_policy(Policy::Accept),
    );
    let rule = || RuleBuilder::new(f, t, "input");
    b.add_rule(
        &rule()
            .ct_state(NF_CT_STATE_ESTABLISHED_BIT | NF_CT_STATE_RELATED_BIT)
            .accept()
            .build(),
    );
    b.add_rule(
        &rule()
            .in_set("blocked", &[Field::IpSaddr])
            .counter()
            .comment("blocked")
            .drop()
            .build(),
    );
    b.add_rule(
        &rule()
            .match_eq(Field::TcpDport, 22u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .dynset(
                DynsetOp::Update,
                "ssh_meter",
                &[Field::IpSaddr],
                None,
                vec![limit_expr(10, Duration::from_secs(60), 5, LimitType::Packets, true).into()],
            )
            .log_group(1, Some("ssh flood: "))
            .counter()
            .comment("ssh flood")
            .drop()
            .build(),
    );
    b.add_rule(&rule().vmap("ports", &[Field::TcpDport]).build());

    match sock.commit(&b) {
        Ok(out) => println!("committed, generation {}", out.genid),
        Err(e) => {
            // e.g. "batch operation #9 (add rule inet example input) failed:
            //       No such file or directory at expression #3 `lookup` (set blocked)"
            eprintln!("{e}");
            return Err(e);
        }
    }

    for _ in 0..3 {
        std::thread::sleep(Duration::from_secs(1));
        for r in sock.list_rules(f, Some(t), None)? {
            if let (Some(c), Some(name)) = (r.counters().next(), r.comment()) {
                println!("{name:>12}: {} packets, {} bytes", c.packets, c.bytes);
            }
        }
    }
    println!("exiting: the kernel removes the owned table");
    Ok(())
}
