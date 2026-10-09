# Wake v1 — the review package

**Status: DRAFT. Not reviewed. Nothing that depends on this crate may report "verified"
until §11 of `../../WAKE-v1.md` has happened.** This file is the index a reviewer reads first.
Assembled 2026-09-25; brought up to date 2026-10-06 (chain access through a light server, and
Knotline v1: see "Added since the first package" below).

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

- **To the chain, when the lading is delivered off-chain: nothing.** The memo carries only
  the consignment hash, encrypted to the recipient. Action pairing (§5.5) is invisible: ρ is
  inside the commitment. Such a transfer is indistinguishable on chain from any other Ironwood
  transaction.
- **To the chain, with Knotline v1: the shape, not the content.** The transfer carries twelve
  more outputs than a plain one (its proof, sealed, and the key for the recipient), so it can
  be recognised as a transfer of this kind. Nobody but the holders from that transfer onward
  can read the proof. `KNOTLINE-v1.md` §6, §7 and §10; unreviewed.
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
- The lightwalletd oracle has been run against public mainnet servers since 2026-10-05
  (`examples/light_verify.rs`); it relays the server's word and can never yield Verified.
- Knotline v1 has had no outside review of any kind.
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

## Added since the first package (2026-10-06)

Nothing here changes the circuits, the keys, the prover or the witness: `src/circuit.rs`,
`src/keys.rs`, `src/prove.rs`, `src/witness.rs` and both pinned verifying keys are unchanged
since the first package, and the `vk_id`s above still hold.

| What | Where | Why a reviewer may care |
|---|---|---|
| Chain access through a light server | `src/oracle_lightwalletd.rs`, `src/oracle.rs` (`OracleTrust`, `is_local_url`) | Decides which results may be called Verified. A zebrad that is not on loopback is now `ServerAsserted`. Transactions from a server are checked against their id |
| `WAKE-v1.md` §8.1 amended | `docs/WAKE-v1.md` | A named "checked via provider" state between Verified and Unverified |
| `WAKE-v1.md` §7.3: canonical serialisation of a lading | `docs/WAKE-v1.md`, `src/lading.rs` | Knotline's recipient rebuilds the lading and compares hashes, so the bytes must be reproducible |
| **Knotline v1**: the lading carried on chain, one sealed proof per transfer | `docs/KNOTLINE-v1.md`, `src/knotline.rs` | New construction, frozen wire format, privacy claims unreviewed |

Questions on Knotline, in order:

1. The only encryption of a knot is Zcash note encryption to an address whose spending key is
   derived from the knot's random key (`knot_keys`). Is there a pitfall in a derived,
   never-spent address used this way, or in handing the 32-byte key to the recipient in a memo?
2. Does the chain of keys give what §6 of the specification claims: an earlier holder cannot
   read, or even recognise, later knots?
3. `unpack_knot`, `from_memos` and `walk_back` parse data from the chain. Are all lengths and
   counts bounded, and can a crafted knot make a reader loop, over-allocate or accept a
   partial lading?
4. Is anything in a knot or in the key memo distinguishable to someone without the key, beyond
   the number of outputs?

Evidence: `cargo test --lib knotline` (round trips, refusals, and `v1_format_is_frozen`, which
pins the address derivation, both knot layouts and the canonical lading by hash). Three mainnet
transactions made with a throwaway test item are listed in `KNOTLINE-v1.md` §9.

## Changed after an internal automated review (2026-10-08)

An internal automated review (not an external one) of the code above found no forgery. What it
found changed the following; the circuits, keys, prover, witness and `vk_id`s are still
unchanged.

| What | Where | Why a reviewer may care |
|---|---|---|
| W3–W5 before W1–W2 | `src/verify.rs` | A forged lading fails as forged, and the oracle is never asked about heights a forger chose |
| `is_local_url` parses the URL; the curl path is gone | `src/oracle.rs` | `https://127.0.0.1@attacker/` and `127.evil.example` used to pass as loopback |
| "Not on chain" only from RPC error −5 of a zebrad on this machine | `src/oracle.rs` | Any other zebrad error used to become a forgery verdict |
| The zebrad path recomputes the txid | `src/oracle.rs` | As the light-server path already did |
| Hex decoding never slices text | `src/oracle.rs` | Non-ASCII input panicked |
| Block cover completed whatever each request answers | `src/oracle_lightwalletd.rs` | An active server could defeat it; `KNOTLINE-v1.md` §7 now says it holds against an honest server only |
| Canonical lading enforced on input | `src/lading.rs` (`deny_unknown_fields`, `parse` compares with `to_bytes`) | `WAKE-v1.md` §7.3 was normative but unchecked |
| Knot reader refuses non-zero trailing bytes; walk bound 512 | `src/knotline.rs` | One encoding per knot; a bounded walk |
| `WAKE-v1.md`: pool normative (Ironwood only), soundness of a free `nk` written down in §9, basis of `MIN_DEPTH` in §8 | `docs/WAKE-v1.md` | §11 question 1 now has the reference's own argument to check |
| `TRUST_MODEL.md` rows 1, 4, 6–8, 10, 12, 13, the verdict table, gaps 9–10 | `docs/TRUST_MODEL.md` | Row 1 no longer says Wake adds nothing to consensus |

Free `nk`, pinned in tests: `positive.rs::a_chosen_nk_proves_a_different_nf` shows a chosen
`nk` proves a different `nf` for the same note, anchor and `ρ` (by design; `WAKE-v1.md` §9); the
negative case formerly named `forged_nk` is now `nf_inconsistent_with_witnessed_nk`, which is
all it ever caught.

Still open from that review, for the external one: negative tests for the kept gadgets with a
malicious synthesizer.

## A second internal automated review (2026-10-09)

A second automated review, by a different model from the first, read the circuit and verifier
at `a39ac96` (wallet `d5c6df8`), probed the kept gadgets under a malicious synthesizer in a
scratch copy, dumped the pinned verifying keys afresh (byte-identical), accounted for the
blinding rows, verified the published vector against a full node and a public light server,
and checked zebrad's JSON action order against the raw bytes. It found no soundness issue. It
found, and the next commit closes: the issuance badge green on a provider-checked lineage
(WAKE §8.1(c)); the zebrad path reading actions from JSON rather than the checked hex; heights
from a light server unbounded or substituted; a genesis alone in its block uncheckable through
a provider under the cover rule (KNOTLINE §7 now widens the cover); two URL parsers; and six
points of specification wording. Its questions for a human auditor are merged into the list
above where they were new (the free-`nk` reduction's completeness; non-canonical Merkle node
encodings; Sinsemilla incomplete-addition cases after the deletion; blinding sufficiency for
this query profile; transcript binding of the instance in the IPA verifier; full-width `rcm`
window aliasing; whether 100 blocks is the right `MIN_DEPTH` for a provider-checked result).
Neither automated review is an external review in the sense of `WAKE-v1.md` §11 item 4.

## A regression pass over the fixes (2026-10-09, same second model)

The second model also re-read every commit from the first review's fixes onward, asking of
each named finding what the attacker did before, whether the diff stops it, and what the diff
opens. Three fixes did not close what they claimed, and the next commit closes them: the lading
rule for a carrier without a `consignment_hash` (a unit at its first holder, or sent before
0.7.0) still let a copy sent by anyone displace the genuine lading, because the rule was keyed
on the note's ρ, which is public; the send planner preferred "has a lading" over "has a lading
that verifies"; and the recovery-phrase export on a YubiKey wallet compared the PIN locally,
with no lockout. The remedies: a lading is stored only after the oracle-free checks pass, and
then only for the note it arrived with; a failed one is recorded against that copy; the send
spends the copy whose lineage checks out best; the device proves the PIN. The rest of that
pass (fee bound as a question rather than a refusal, chain source decided once at start and
kept beside the wallet, one bounded registry client, a walk-in-progress guard, lower-case hex
and padded base64 enforced in `Lading::parse`, and the documents here) is in the same commit.
Its open questions for a human auditor are added above: whether a lading should ever be chosen
by `(asset, ρ)` at all, whether a wallet may extend a lading it has not verified (the reference
now never does), and whether a locally compared PIN could ever be acceptable (the reference no
longer does that either).

## The wallet and ZMAP pass (2026-10-09, the first model again, on the fixed tree)

A fourth automated session read ZMAP v0.5 and the wallet on the tree with every earlier fix in.
It found one High: the wallet named an issuer by a self-chosen name plus 32 bits of its key,
and the Registry is open, so an impostor with a ground key and the same name reached the same
green badge (measured grind rate reported). Remedied the same day: the keys of the collections
the wallet vouches for are pinned in the binary, a registry-only collection is never green,
the fingerprint shown is long, and a look-alike name is flagged. It also found that a stranger's
upper-case copy of an asset id framed the genuine unit in the issuance check (now: lower-case
ids only, every copy judged), that the collection audit ran through the provider whatever the
setting and took transactions on trust (now: through the chain source, checked against the
id, labelled), that the audit's post-close check was narrower than the specification (now:
any output after the close is a breach), and a list of smaller items (the viewing key gated
like the seed; the installer verifying a signed manifest before trusting its sums; proxies
ignored; the CSP tightened). Its questions for a human auditor: whether any fingerprint
shorter than the full key is acceptable for issuer identity; Unicode normalisation of the
description an asset id is derived from; whether the §5.4 lineage lock can be abused to lock
a large note; the spendable-note semantics of the pinned `zcash_client_sqlite` for a stored
unmined transaction.

## The second regression pass (2026-10-09, over hardening 12 and 13)

A fifth session re-read the two fix commits above and the catch-ups that mirror them. It
confirmed nineteen of the twenty-eight findings closed and found that three of the fixes had
opened new paths: the send planner ranked copies without the manifest's genesis (so a copy with
a self-consistent lading outranked a genuine unit at its first holder), the walk-in-progress
guard let a send read "being collected" as "absent" and offer an unproven send, and the chain
source decided at start could fix the provider for a whole session after one silent probe. The
next commit closes them (the planner ranks with the genesis and asks no oracle; the send waits
for a walk or refuses; a provider default re-asks the node and moves to it once it answers, never
back) and the smaller items it listed. Its questions for a human auditor, added to the list
above: whether any ranking of copies is acceptable without the issuer's genesis, whether a wallet
should ever offer an unproven send of a carrier whose memo commits to a lading hash, whether a
provider default is acceptable at all, and whether any confusable-name heuristic suffices for
an open registry.

