# Wake v1 — the review package

**Status: DRAFT. Not reviewed. Nothing that depends on this crate may report "verified"
until §11 of `../../WAKE-v1.md` has happened.** This file is the index a reviewer reads first.
Assembled 2026-09-25.

## The question

> Can a prover satisfy `WAKE_HOP` with `ρ ≠ nf_prev`, or with `nf` not derived from the
> witnessed `nk`, or with `cm` not in the tree at `anchor`?

If the answer to any part is yes, every asset built on Wake can be forged silently. Halo 2
removes the trusted setup, not the reviewer.

## Read in this order

| # | File | What |
|---|---|---|
| 1 | `../../WAKE-v1.md` | the specification: statements, circuit, witness, encodings, verification, this gate. Two errata are marked in the text (`anchor_height` in §7.2; genesis proved by the first holder, in ZMAP §12.3). |
| 2 | `CONSTRAINTS.md` | one line per gate, lookup and copy constraint, with origin |
| 3 | `diff_vs_orchard_circuit.md` | `diff -u` of `configure` and `synthesize_base` against `orchard 0.15.3 src/circuit.rs`: 247 code lines deleted, one constraint added, `root = anchor` made unconditional, `pk_d` witnessed |
| 4 | `../src/circuit.rs` | the circuit, with every deletion and change marked in brackets |
| 5 | `../tests/negative.rs` | ten attacks, each caught by exactly one named constraint, shown by removing that constraint |
| 6 | `pinned_vk_hop.txt`, `pinned_vk_genesis.txt` | the pinned verifying keys; they differ in two lines |
| 7 | `../src/witness.rs` | witness derivation with an independent off-circuit recomputation of `cm` and `nf` |

## What has been shown, and how

| Claim | Evidence | Command |
|---|---|---|
| The witness derivation reproduces the library's `cm` and `nf` for V2 and V3 notes | `src/witness.rs` tests; mutating the commit domain fails 5 of 9 | `cargo test --lib` |
| Both circuits are satisfiable at `K = 11` with real notes | `tests/positive.rs` | `cargo test --test positive` |
| Real proofs round-trip; wrong key, wrong instance, trailing bytes, truncation all fail | `tests/positive.rs` | same |
| Each of ten attacks is caught by exactly one constraint | `tests/negative.rs` with the `sabotage` feature | `cargo test --test negative` |
| The sabotage knob changes nothing when unused | the pinned `vk_id` test runs with the feature on and matches constants computed without it | `cargo test --lib keys` |
| The two circuits differ only in the one added constraint | `diff` of the pinned keys is two permutation commitments | see `CONSTRAINTS.md` §0 |
| A complete real chain on mainnet (genesis + two hops + note in hand) verifies against a full node, and the wrong note in hand fails | `tests/mainnet_wake_test_001.rs`: Wake Test #001, 3 proofs, throwaway wallets; lading published in `test_vector/` | `cargo test --release --test mainnet_wake_test_001 -- --ignored` (needs zebrad) |
| Every proof in that chain can be rebuilt by its own holder, and matches the published instances | same file, second test | needs copies of the two throwaway wallets |
| The verifier names which check failed and never succeeds on a subset | `tests/chain.rs`: every `WakeFailure` from one mutation | `cargo test --test chain` |

## Identifiers

```
kind       wake-v1
k          11
vk_id hop     c10ee672500b17ea7c94376b6bc1ee988870b9354d1bd391ed1f1324c953707f
vk_id genesis decb572630f885fd6a98266f5faea215193597eb5e83a6da8e6912bb083334e9
```

`vk_id = BLAKE2b-256(personal "WAKE-v1-vk", "wake-v1" ‖ name ‖ I2BEOSP_32(k) ‖ pinned_vk)`.
Recompute: `cargo test --test audit_dump -- --ignored --nocapture`.

## The mainnet test vector: policy

`WAKE-v1.md` §11 item 5 asks for one real hop, lading and note ρ given, verifiable by anyone
with a node. A lading discloses which transactions carried the unit to whoever holds it (§9),
and publishing one puts those links in public, which §7.3 forbids for real assets. So the
published vectors are **throwaways**: a collection minted for testing ("Wake Test", WKT) and
passed between wallets that hold nothing else. They link nothing anyone owns.

Two are published in `test_vector/`: **#004** (genesis only, one transfer) and **#001** (genesis
plus two hops, three transfers). Ladings of real assets are never published and are not in this
repository.

## What a lading discloses (the privacy question, answered precisely)

- **To the chain: nothing.** Proofs are off-chain. The memo carries only the consignment
  hash, encrypted to the recipient. Action pairing (§5.5) is invisible: ρ is inside the
  commitment. A v0.5 transfer is indistinguishable on chain from any other Ironwood
  transaction.
- **To the recipient, in v1: the transaction graph of that unit.** Each hop exposes
  `(nf_prev, nf)`. Nullifiers are public already; the chain does not reveal which output a
  spent nullifier produced, and the pair does. Not addresses, values or keys.
- **Mitigation available without recursion: a k-hop circuit.** `WAKE_HOPS_k` takes k
  consecutive notes and enforces every `ρ_{j+1} = nf_j` inside the proof, exposing only
  `cmx_0` and `nf_last`. The recipient already knows both (genesis is public by design;
  `nf_last` is their own note's ρ). For chains of at most k hops the lading then discloses
  **nothing the recipient does not already hold**; longer chains leak one link per k hops.
  Coin Voting's delegation circuit fits five note slots at `K = 12`, so k = 5 is realistic.
  Recommended as v1.5; recursion (v2) removes even the per-k link.
- **Compaction by issuer attestation** (§12.3 job 2) hides history too, at the cost of trust.

## Known limitations, stated so nobody assumes otherwise

- No external review has happened. This package is the input to one.
- The lightwalletd oracle compiles and is untested against an endpoint.
- The layout diagram has not been rendered (offline; needs `plotters`).
- `WAKE-v1.md` §7.2 gained `anchor_height`; §12.3 of ZMAP gained the first-holder rule.
  Both are errata to a draft, not versions.
- The circuit reuses orchard's chips under the `unstable-voting-circuits` feature, pinned to
  `orchard =0.15.3`. If the feature moves, vendor the three files (`zecboat_wake_circuit.md` §5).

## Precedent for the route

OrchardZSA's protocol audit by Least Authority, commissioned by Zcash Community Grants,
completed 2025-01-03 (`../../other_custom_circuits.md` §2). Ask ZCG whether the same route is
open to an overlay project. Zcash Coin Voting shipped a custom Halo 2 circuit on the same
crate and feature (`voting-circuits 0.12.1`); its author is the one person who has done this
against this crate version.
