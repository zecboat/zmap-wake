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

## The Knotline pass (2026-10-09, the first model, on the tree after hardening 14)

A sixth session read Knotline v1 against the owner's node and a public light server. Integrity
held as claimed: no crafted knot stores a mismatching lading, loops the walk, or gets a partial
line accepted; the cryptographic part of section 6 held. Two things did not: a stranger's
10,000-zat note with a key memo could make the wallet walk a 512-knot line of the stranger's
choosing on every pass, with sends waiting for it; and the block cover of section 7 does not
hide the wanted transaction from the server itself, which sees every transaction's action count
in the compact blocks it serves and can pick the 14-action knot transfer out of each block
(measured on the three mainnet transfers). The next commits answer the first (a walk runs
automatically only for an asset a pinned manifest or a passed audit names, in a background job
under a time and byte budget; the send collects only the unit being sent; a failed line backs
off with a doubling delay kept in the database; the walk is bounded in hops per knot and bytes;
a wrong hint stops the fetch) and state the second plainly in section 7 and the trust model,
with a uniform transfer shape planned for 0.7.2. Its questions for a human auditor: the shared
derived spending key of the knot address under Orchard's key structure; whether the
rho-uniqueness argument for the chaining rule needs any assumption beyond nullifier uniqueness;
mempool and relay limits for a six-proof start of line; what else in a compact block
distinguishes a knot transfer; whether OVK recovery of knot outputs is the right default.

## The gate pass (2026-10-09, over hardening 12 to 15)

A seventh session re-read hardening 12 to 15 as the release gate. The WAKE verifier: no
Medium or worse. The lading path: three Medium, each the case beside one a fix had closed. The
"known asset" gate of hardening 15 accepted a memo that merely named a pinned key; the
"never absent" rule of hardening 14 covered a walk in progress but not a failed or backing-off
one, so a send could still be offered unproven and strip the memo's hash; the ranking of
hardening 14 needed the manifest's genesis from the network at send time, so with the registry
unreachable a copy with a self-made lading outranked a genuine first-holder unit. Hardening 16
answers them: a known asset is one *listed* in a manifest the wallet holds and has verified;
those manifests come from the chain (the audit's copy) or are built into the wallet, and the
website is never asked (the owner's rule: verification is from the network, not the site);
each walk has its own budget and a pass that runs out records nothing against carriers it did
not reach; a send of a unit whose memo commits to an uncollected lading is refused, with an
explicit abandon only under its own warning; several copies are sent only when exactly one
checks out against the manifest's genesis, never by a txid tie-break; the back-off holds the
walk only; a self-send re-walk runs the same local checks; a server that did not answer is a
transient failure, not a wrong hint; the issuer refusal fails closed against the built-in
issuance keys. Its questions for a human auditor: whether storing a lading should require the
genesis to match a trusted manifest when one exists (`verify_local` accepts any genesis), and
whether an unproven send should ever be possible for a carrier whose memo commits to a hash.


## The gate's second pass (2026-10-09, over hardening 12 to 16)

An eighth session re-read hardening 12 to 16 and catch-up 7 to 11, and confirmed by enumerating
every outbound client that no request to the website is made while a unit is verified, copies
are ranked, or the wallet decides which lines to walk. The circuit, keys, prover and witness
were unchanged in the range; `verify_local` and `verify_chain` were found sound as far as read.
The gate was not passed: three Medium. The send planner ranked a held lading as "checks out"
when its genesis *label* equalled the manifest's, which anyone can write over real proofs of
their own note, so a stranger's relabelled copy tied the genuine unit (every send refused) or
was spent in its place beside a genuine copy that had no lading (demonstrated offline with the
test vector relabelled). The wallet hinted the W1 genesis fetch from the lading's own anchor
height, and since catch-up 10 a wrong hint fails the fetch, so through a provider a lading with
a false genesis read "could not be checked" rather than Broken, and a lading anchored later
than its genesis block, which §8 allows, could never be checked (demonstrated against a public
server). And hardening 16's claim that the planner's genesis was at hand offline did not hold:
it still went through the issuance badge's chain check, so with the chain source down a
first-holder unit was offered "unproven" with the wrong reason. Hardening 17 answers them:
rank 5 requires the lading's first proof to open from the commitment the signed manifest
states at the genesis output (W1 done offline; the relabelled vector is now a test); the
planner's genesis, with that commitment and the stated block, is read from the manifest the
wallet holds with no network; the W1 fetch is hinted from the manifest's stated block, never
from the lading, and a fetch that still reports a wrong hint is asked once more without one
(`WAKE-v1.md` §8 and `KNOTLINE-v1.md` §7 now say so). The lower findings: every failure of
the source (connection, tip, tree state, transaction, a node's answer) is now marked transient
in both oracles and waits a flat minute instead of a doubling day; copies whose walks failed
before are walked last and an on-demand collection lifts the delay but keeps the count; the
walk's byte budget counts the cover the server sent; the issuer refusal compares the decoded
Orchard viewing key, not the string; read-only adoption fails closed; an Orchard-pool carrier is
never refused as "uncollected"; the documentation that said more than the code was corrected.
The estimate now applies the send's own refusal, so the screen never names a copy the send
then declines. Its questions for a human auditor: whether binding the genesis label to the
manifest's commitment is equivalent to W1 for the purpose of choosing a copy (a reorg between
minting and checking); whether §8 should instead require `hops[0].anchor_height` to be the
genesis block; which of the orchard and halo2 issues of the 2026 audit touch the gadgets WAKE
keeps; and whether §9's reduction for a free `nk` states sufficient assumptions.

## The gate's third pass (2026-10-09, over hardening 12 to 17)

A ninth session re-read hardening 12 to 17 and catch-up 7 to 12. The WAKE verifier: nothing
Medium or worse. The three pinned collections: every claim of hardening 17 confirmed, with all
thirty built-in commitments checked against mainnet. The website: confirmed absent from every
path that verifies, ranks or walks. Two Medium remained, both confined to units whose trusted
genesis stated no commitment: the twenty units of the two collections minted before identity
v1, whose built-in manifests gave an outpoint and a block only, and any collection trusted
through a registry audit. For those, hardening 17's binding could not be made, so a valid
lading ranked as "cannot be bound" and any second carrier, even a bare copy, froze every send
beyond the first holder; and their genesis still came through the issuance badge's chain
check, the case hardening 17 claimed closed. Hardening 18 answers them by the owner's
decision: nobody holds a pre-v1 unit and 0.7.1 is not built for them, so their manifests and
the pre-v1 badge path are removed from the build, and a registry collection's genesis, with
its commitment and block, is read offline from the passed audit's chain copy under the key
the audit verified. The planner's genesis now has no network fallback at all. The lower
findings: the remaining answers of a node or server in an unexpected shape are marked as the
source's failure, "not known" from the wallet's own node counts against the line, and every
failed attempt counts for the walk ordering so a line that fails "transiently" still goes
last; a copy whose genesis label or first commitment is not the manifest's is Broken after the
oracle-free checks, with no chain request, so a stranger's copy never makes the wallet ask the
chain source for a transaction the stranger chose; the send's own pre-collection pass adopts a
hash-less lading on its writable connection; the offline listing check verifies the chain
copy's signature; the trust model's row 12 says what hardening 17 did and did not cover. The
pass's questions for a human auditor: whether the offline binding argument (a genesis proof
opening the manifest's commitment, the chain rule, and a final nullifier equal to a real
note's ρ, implying descent without W2) is complete given free `nk` and `ψ`; which of the 2026
orchard and halo2 findings touch the gadgets WAKE keeps; and whether a light-server verdict
may substitute the tip's consensus branch when the server reports no height.

## The gate's fourth pass (2026-10-09, over hardening 12 to 18): passed

A tenth session re-read hardening 12 to 18 and catch-up 7 to 13 and found no Critical, High or
Medium issue in the WAKE verifier as the wallet uses it, nor in the path by which a lading is
stored, chosen and sent, at the wallet's `9f6cb3b` and this repository's `f2e4d97`. Every claim
of hardening 18 held: the pre-v1 collections are gone with no path left that reads them; the
planner's genesis comes from a held signed manifest and from nowhere else; all thirty pinned
genesis outputs match mainnet in txid, index, commitment and block (the reviewer's own probe
against the owner's node); a copy whose genesis is not the manifest's is Broken inside the
verifier with no chain request; every failed walk attempt counts for the ordering; and no path
that verifies, ranks or walks reaches the website. The circuit was out of that session's scope.
What stayed open was Low or Informational, and hardening 19 answers it: the claim about
chain requests is stated exactly (the verifier makes none for a mismatching copy; the Knotline
walk that collected it did, within its budget); a provider's own failures weigh a tenth of a
line's in the walk order, so an outage cannot push a genuine unit behind every copy sent since;
a unit of a collection the wallet does not know gets a grey "not known" state, and the red
"not issued by" is kept for a verified manifest that does not list the unit; the optional
drop-box client follows no redirects and reads its body in bounded pieces; a failed local
store after signing no longer skips the drop-box delivery; the offline verdict is a pure
function with the copy cases as tests; stale comments and the unused ed25519 dependency are
gone. Left for 0.7.2: a registry collection's genesis outpoint taken from the audit's
chain-derived unit list rather than its manifest; the Knotline question of whether each knot
should carry the genesis so a stranger's line can be refused after one fetch. The pass's
questions for a human auditor: which of the 2026 orchard and halo2 findings touch the gadgets
WAKE keeps, in the pinned halo2_gadgets 0.5.0 and orchard 0.15.3; whether row 14's "invented
anchors read Verified" is conservative or constructible; and whether an anchor no block ever
had should be Broken rather than "could not be checked" when the wallet's own node answers.

## The gate's fifth pass (2026-10-09, over hardening 12 to 19): the gate holds

An eleventh session re-read hardening 12 to 19 and catch-up 7 to 14, ran the wallet core's
tests and a live redirect probe, and found no Critical, High or Medium issue in the verifier
or the lading path at the wallet's `13551f4` and this repository's `c89b285`; hardening 19
opened nothing above Low. Five Low and four Informational items remained, and hardening 20
answers them, with one decision by the owner: **the drop-box route is removed from the
wallet**. It was the 0.7.0 draft's optional off-chain hand-over, an address the holder could
name; nothing ever used it by default and zecboat.com never ran one; every pass found
something to patch in it (redirects on the download, then on the upload, body bounds,
delivery on a failed store), and it put a party in the middle that saw both sides' network
addresses. A lading now travels in the transfer or as a sealed file. The other answers: a
memo naming a key this wallet knows, for an asset that key's manifest does not list, gets the
red "not issued by" answer again, named after that collection, and "unknown" is kept for a
key the wallet has never seen; the broadcast client follows no redirects; the send is not
refused because some copy's walk is in progress, only when the copy it would spend is being
collected; an asset no manifest names a genesis for is "unverified" without any chain
request; the "unknown" state is grey rather than amber; the stale example comment is
corrected; the walk sort runs its database reads once per carrier. Left for 0.7.2 and stated
in TRUST_MODEL row 12: the walk order is a cost, not a guarantee, since a stranger can label
their own line's failures "transient" through a provider's "not known", and the tie-break is
insertion order; and the double verification of proofs in the badge. The pass's questions for
a human auditor: whether a memo naming a pinned key for an unlisted asset should be the
strongest negative issuance verdict, and whether "closed" makes a manifest exhaustive; whether
a light server's "not known" may be classed as the source's failure when the stranger chose
the transaction asked for, or a second source should be asked; and the orchard and halo2
findings of 2026 against the kept gadgets.

## The gate's sixth pass (2026-10-09, over hardening 12 to 20)

A twelfth session re-read hardening 12 to 20 and catch-up 7 to 15, with the drop-box removal
as its first question, and found it complete in code: no path, setting, environment variable
or control names a drop-box. It found no Critical or High issue, and one Medium: hardening
20's red "not issued by" answer for a memo naming a known key had been placed after the older
amber "registered but not checked yet" answer, which catches every registered key once the
wallet has scanned the Registry, the pinned ones included, so the red answer never fired and a
forgery dressed as a pinned collection read amber, named after the genuine collection, with a
Check that could never clear it. The previous pass had rated the same item Low; this one
rates it Medium because hardening 20 claimed it fixed. Hardening 21 moves the decision ahead
of the amber branch, as one pure function of what the holder's memos claim, and tests that
order with the pinned collection also registered; it also follows the newest-audit rule, so
an older pass never outranks a newer failure, and reads every holder memo. Its other findings,
Low and Informational: with no manifest genesis the oracle-free checks were skipped too, so a
failing lading of an unknown asset read "unverified" rather than Broken (fixed: those checks
run whatever the manifest says); a send whose record is not in the transfer could lose that
record for good on a local write failure after signing, with nothing shown (fixed: the sealed
file is written from memory after signing and before the lineage rows, the sender's copy is stored before the
lineage row, and the confirmation says beforehand when a record will not travel); the
broadcast reply is now read under a bound; opening the send of an asset no manifest lists
walks its lines, which KNOTLINE §6 now counts as asking; row 9 said grey for an amber state.
Its questions for a human auditor: whether a pinned key's manifest is exhaustive when check
9's completeness rests on a provider's scan; whether a lading whose proofs verify but whose
asset has no manifest genesis deserves a state of its own; the 2026 orchard and halo2
findings against the kept gadgets in the pinned versions; and whether a lineage record must
be persisted before the transaction is stored.

## The gate's seventh pass (2026-10-09, over hardening 12 to 21)

A thirteenth session re-read hardening 12 to 21 and catch-up 7 to 16 and found the sixth
pass's Medium closed: a forgery naming a pinned key reads red. It found no Critical or High,
and one Medium that hardening 21 itself opened: the decision read the `ik` of every memo held
under the asset id from raw JSON, so a stranger's single carrier note with a bare `ik` and no
`desc`, which the memo parser accepted as a pre-v1 memo, turned a genuine unit's badge red,
named after a pinned collection (shown by a probe). Hardening 22 answers it at the root: a
memo claims a key only when its `ik` and `desc` derive the asset id (ZMAP §4), so a claim
cannot cross from one key's asset to another's; and half a v1 memo, `ik` without `desc` or
the reverse, is no unit at all. The decision's glue is now a pure function with the decoy
beside a genuine memo as a test. The pass's two Lows are answered as well: "a key this wallet
knows" is scoped per registration, so a key reused for a second, unchecked collection is not
exhaustive for it and an audit cached without its manifest does not count; and a key whose
newest audit failed is red "check failed", not amber "not checked yet". Its remaining items:
the advance notice that a record will not travel now covers a first send from the genesis
output with the route off, and the finished send names the saved file; the dead first-memo
helper is gone. Left as cost: the oracle-free checks re-run on every badge view of an
unlisted asset's lading. The pass's questions for a human auditor: whether a per-asset
issuance verdict computed from memos is sound at all, or must be per carrier and tied to the
lineage; and the 2026 orchard and halo2 findings against the kept gadgets.
