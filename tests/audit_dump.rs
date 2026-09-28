//! Chapter 10: dump the pinned verifying keys, from which `docs/CONSTRAINTS.md` is built.
//! Ignored; run by hand: `cargo test --test audit_dump -- --ignored --nocapture`.
use zmap_wake::{keys, Kind};

#[test]
#[ignore = "writes docs/pinned_vk_*.txt"]
fn dump_pinned_verifying_keys() {
    for kind in [Kind::Hop, Kind::Genesis] {
        let pinned = format!("{:#?}", keys::keys(kind).vk.pinned());
        let path = format!("docs/pinned_vk_{}.txt", kind.name());
        std::fs::write(&path, &pinned).unwrap();
        println!("{path}: {} bytes, vk_id {}", pinned.len(), keys::vk_id_hex(kind));
    }
}
