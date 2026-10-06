# Wake trust model — who is trusted for what

2026-09-28 (rows 8, 9 and gap 3 updated the same day for A3b phase 4); **row 4, the verdict
table and gaps 6 to 8 updated 2026-10-06** for `WAKE-v1.md` §8.1 as amended and for Knotline v1. Covers Wake v1 (`zmap-wake` tag `wake-v1-draft-2026-09-28`), its use in the Zecboat
wallet (`zecboat_next` `8d9ba86`) and the issuance tool (`zecboat_mint_wake` `50eac78`).
Statements marked **[code]** were checked against the source on this date; the rest come from the
spec (`WAKE-v1.md`, `ZMAP-v0.5.md`) or are design intent.

**The claim Wake makes:** *the note in this wallet descends, through on-chain spends, from the
genesis output the issuer designated for this asset.* It does not claim ownership, value,
non-spending, or anything about who made the transfers.

---

## The table

| # | Party | Trusted for | If it lies, fails or disappears | Defence |
|---|---|---|---|---|
| 1 | **Zcash consensus** | Every Orchard/Ironwood Action sets `ρ_new = nf_old`, and every nullifier appears once | Wake means nothing | The base assumption. Wake adds nothing on top of it. |
| 2 | **The Wake circuit, Halo 2 and the Orchard gadgets** | Soundness: a valid proof implies the relation in `WAKE-v1.md` §4 | **Forgery**: a proof of descent that isn't true | Negative and sabotage tests, a constraint listing, a diff against Orchard. Pinned versions include the CVE-2026-54496 fix. **External review is still required (§11.4). This is the one row where a failure is silent.** |
| 3 | **The issuer** (holder of `ik`) | Naming the genesis outputs and minting only what it declares | Extra units, or a genesis pointing somewhere else | Manifest signed by `ik`; pin, close and genesis list on chain; issuer viewing key published; the audit checks count, closure and value (checks 8, 9, 14). **[code]** The wallet shows `GenesisMismatch` (Broken) when a lading's genesis differs from the one the manifest names. |
| 4 | **The chain oracle** used by the verifier | Answering "is this root real at height h" and "what is `cmx` at this output" | It can hide or fake roots, making a unit look unproven or, if faked consistently with a forged proof, look proven | **[code]** Only an oracle marked `FullNode` can produce **Verified**, and only a zebrad whose URL is loopback is marked so (`oracle::is_local_url`). Every other answer (lightwalletd/zainod, or a zebrad reached over a network) is `ServerAsserted` and gives at most **Checked via provider**, never Verified (`WAKE-v1.md` §8.1). Anchors must be 100 blocks deep (`MIN_DEPTH`). A transaction returned by a server is checked against the id it was asked for; a server that does not know a transaction yields "could not be checked", never Broken. |
| 5 | **The network path** to nodes and servers | Nothing | Can read or alter traffic. Today zainod is plain HTTP on the LAN; zebrad RPC is plain HTTP on localhost. | Row 4's rules. Spends need keys and are checked by the network, so funds cannot be taken this way. Planned: warn on non-HTTPS endpoints; bind to localhost where possible. |
| 6 | **The sender** of a unit | Delivering the lading | If it withholds, the unit shows **No lading**: unproven, not forged | The memo's `consignment_hash` commits to the lading. A later lading must hash to it. |
| 7 | **The drop-box** (zecboat.com or a shared folder) | Availability only | It can withhold. It cannot read ladings, because they're sealed to the recipient, and it cannot frame a unit | **[code]** A fetched lading must open with the recipient's keys **and** hash to the memo's value, or it is discarded and nothing is stored. A bad drop-box leaves a unit at *No lading*, never *Broken*. The hash used as the filename is 64 hex characters (validated when the memo is parsed). First delivery wins; a squatter would need the hash before the sender uploads. |
| 8 | **zecboat.com** (manifest and artwork host) | Availability of **artwork** (and manifests for pinned collections) | Since A3b phase 4 (2026-09-28) it is **not needed to validate** a registered collection: the manifest is read from the chain. Without it, artwork cannot be shown (only its hash is on chain) and the default lading drop-box is gone | Manifests are checked against a pinned key, or (phase 4) against the registered key after a passed audit; artwork is checked against its hash. **[code]** Proven 2026-09-28: with zecboat.com replaced by a dead address, Lagos #007 is still Verified. |
| 9 | **The Zecboat Registry** (its key is pinned in the wallet) | Since phase 4: **the root of trust for registered collections.** A collection found there **and passing all 17 audit checks** is trusted like a pinned one | It can list or omit collections. A registration alone proves only that the `ik` holder registered that viewing key; trust comes from the audit | **[code]** Trusted only on a complete, passed audit that kept the manifest etched on chain and lists the unit (`pick_listing`); a registered but unchecked collection shows grey "not checked yet", never a red "not issued". The audit is to a block: re-checking confirms nothing was issued since. |
| 10 | **The recipient's own wallet software** | Running every check honestly and reporting which one failed | A bad build could show anything | Published build hashes; open source; the four-state badge (Verified / Unverified / No lading / Broken) never collapses "unproven" into "forged". Reproducible builds are **not** yet in place. |
| 11 | **The holder**, when selling | Nothing | Can prove a note and then spend it before the buyer is paid. "One successor" is guaranteed; "one claimant" is not | **Market rule, not code:** `SETTLEMENT_RULE.md`. The unit moves first; the buyer pays (or escrow releases) only when the buyer's own wallet shows Verified against the buyer's own zebrad. Every seller trick shows as something other than Verified. |

## What a verdict means

| Badge | Means | Depends on rows |
|---|---|---|
| **Verified** | Proofs valid, chain rule holds, anchors ≥100 deep, checked against a full node, genesis matches the issuer's signed manifest | 1, 2, 3, 4 (full node), 10 |
| **Checked via provider** | The same five checks pass, but the chain's answers came from a server the holder does not run. The report names that server and must not look like Verified in wording, colour or mark | 1, 2, 3, 4 (server), 10 |
| **Unverified** | Proofs and chain rule hold, but something outside them could not be confirmed (shallow anchor, no trusted manifest, or a server answer in an implementation that has no provider state) | 1, 2 |
| **No lading** | Nothing to check yet | none; says nothing about the asset |
| **Broken** | Evidence of forgery or tampering: a bad proof, a broken chain, genesis not on chain, a hash mismatch on a held lading, the wrong final note, or a genesis mismatch | whoever made the lading |

## Known gaps (as of 2026-09-28)

1. **Row 2 is unreviewed.** It is the only row where a failure isn't visible.
2. **Row 11: settlement is a written rule (`SETTLEMENT_RULE.md`), not enforced by code.** Seller protection needs an escrow; a one-transaction swap is not designed.
3. ~~Lagos Post Card can't reach Verified lineage yet.~~ **Closed 2026-09-28 by A3b phase 4:** once
   Lagos is checked in Collections, its units get the issuer badge and a genesis from the chain,
   with no `PINNED_V1` line.
4. **Row 5:** plain-HTTP endpoints with no warning.
5. **Row 10:** builds are not reproducible; users can compare hashes but can't rebuild to match.
6. **Privacy, not trust:** a v1 lading shows its recipient the lineage's nullifiers, which link
   the transfers. A lading must never be published in a form anyone but the note's holders can
   read (`WAKE-v1.md` §7.3); v1.5 and v2 reduce what the recipient learns.
7. **Knotline v1 is unreviewed** (`KNOTLINE-v1.md`). It writes each hop proof to the chain sealed
   under a one-time key. Integrity does not rest on it (a wrong knot cannot produce a lading that
   matches the transfer's hash), but its privacy claims (§6 and §10 there) have been checked only
   by its authors, and a knot cannot be withdrawn.
8. **A light server sees what a wallet asks for.** A wallet without its own node asks its server
   for the transactions and tree states of a lineage. The reference fetches whole blocks to blur
   which transaction was wanted; that is thin cover, and an anonymising transport is not built.

## Out of scope for Wake

Ownership, price, and what an asset means (the overlay's job); crossing the Orchard→Ironwood
bundle boundary (v2); the right to spend (Zcash's spend authorization, untouched by Wake).
