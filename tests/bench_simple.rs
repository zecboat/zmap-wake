//! Chapter 7 / P6: prove and verify timings, 10 runs, on this machine. Ignored; run by hand:
//! `cargo test --release --test bench_simple -- --ignored --nocapture`, once with the default
//! thread pool and once with `RAYON_NUM_THREADS=1`.
use std::time::Instant;
use zmap_wake::testing::carrier;
use zmap_wake::{keys, prove_hop, verify_hop};

#[test]
#[ignore = "timing only"]
fn prove_verify_10_runs() {
    let t = Instant::now();
    keys::warm();
    println!("keygen (both circuits): {:.2?}", t.elapsed());
    let f = carrier();
    let (mut p, mut v, mut size) = (Vec::new(), Vec::new(), 0);
    for _ in 0..10 {
        let t = Instant::now();
        let proof = prove_hop(&f.witness).unwrap();
        p.push(t.elapsed().as_secs_f64());
        let t = Instant::now();
        verify_hop(&proof.proof, &proof.instance).unwrap();
        v.push(t.elapsed().as_secs_f64());
        size = proof.proof.len();
    }
    let stats = |x: &[f64]| {
        let mut s = x.to_vec();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        (s[0], s[s.len() / 2], s[s.len() - 1])
    };
    let (pmin, pmed, pmax) = stats(&p);
    let (vmin, vmed, vmax) = stats(&v);
    println!(
        "threads {}: prove min/med/max {:.2}/{:.2}/{:.2} s; verify {:.1}/{:.1}/{:.1} ms; proof {} bytes",
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
        pmin, pmed, pmax, vmin * 1e3, vmed * 1e3, vmax * 1e3, size
    );
}
