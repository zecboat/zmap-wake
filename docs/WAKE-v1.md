# WAKE v1 — proofs of note lineage on Zcash

> **STATUS: DRAFT FOR EXTERNAL REVIEW.** Part of Zecboat v0.7.0. Until the review is published,
> wallets show a passing lineage as "awaiting external review", never "verified" (§11).

**Status: DRAFT. Not published. No external security review has been performed.**
A missing constraint in this circuit is a forgery. Implement nothing that depends on it for a
"verified" claim until §11's review has happened.

| | |
|---|---|
| Version | 1 (draft) |
| Date | 2026-09-24 |
| Network | Zcash mainnet, NU6.3 "Ironwood" and later; Orchard and Ironwood pools |
| Proof system | Halo 2, inner-product argument over the Pallas/Vesta cycle, no trusted setup |
| Reference implementation | `zmap-wake` (planned; build plan in `zecboat_wake_circuit.md`) |
| Used by | ZMAP v0.5 §9 check 7, §15, as `proof_kind: "wake-v1"` |
| Licence of this document | Public. Implement it freely, with or without attribution. |

---

## 1. Overview

A **wake** is the trail a note leaves when it is spent. Zcash consensus already records it: the
Orchard Action circuit constrains every output note's `ρ` to equal the nullifier of the note
spent in the same Action, so each spent note has exactly one successor, and the link is committed
inside the successor's note commitment where only its holder can read it.

WAKE lets that holder prove the link without revealing the note, its value, its address, the
spent note, or the nullifier-deriving key. A chain of WAKE proofs from a designated genesis output
to a note in hand proves the note descends from that output through a sequence of on-chain spends,
each of which could have had no other successor.

WAKE proves **descent**. It does not name assets, price them, or say who owns them. Those are the
overlay's job (ZMAP, or any other). WAKE is deliberately ignorant of memos.

### 1.1 What is normative

Sections 3–8 are normative. §2 is background. §9–§12 are considerations and process.

## 2. Background — the consensus fact WAKE rests on

Zcash Protocol Specification §4.7.3 (Orchard) and the NU6.3 circuit serving both Orchard and
Ironwood: for each Action, `ρ^new = nf^old`. In `orchard 0.15.3` this is `circuit.rs:801`.
Consequences:

- every nullifier is revealed at most once (consensus);
- every Action has exactly one spend and one output, so a revealed nullifier is the `ρ` of
  exactly one note ever created;
- dummy spends reveal real nullifiers subject to the same uniqueness rule, so a forger cannot
  manufacture a second note with a chosen `ρ`.

Two boundaries where the link does **not** cross: between bundles of the same transaction
(the Orchard→Ironwood migration, since post-NU6.3 Orchard bundles pair each spend with a
fabricated zero-value self-output), and across any future pool. WAKE v1 does not bridge these;
see §10.

## 3. Terminology

| Term | Meaning |
|---|---|
| note | an Orchard-protocol note `(g_d, pk_d, v, ρ, ψ, rcm)` in the Orchard or Ironwood pool |
| `cm`, `cmx` | its commitment and extracted commitment (`Extract_P(cm)`) |
| `nf` | its nullifier, `DeriveNullifier_nk(ρ, ψ, cm)` |
| `nk` | the nullifier-deriving key, a component of the full viewing key |
| anchor | a root of the pool's note-commitment tree at some block height |
| genesis | the output the overlay designates as the origin: `(txid, action_index)` → `cmx_0` |
| hop `j` | the note `N_j` whose `ρ` equals `nf_{j-1}`; `N_0` is the genesis note |
| wake proof | a proof for one hop |
| lading | the ordered list of wake proofs for a note, delivered with it (the bill of lading) |
| oracle | the chain source a verifier chooses to answer "is this a root" and "what is `cmx` at this output" |

## 4. Statements

### 4.1 WAKE_HOP

```
instance   anchor       ∈ 𝔽_p    a note-commitment-tree root
           nf_prev      ∈ 𝔽_p    the nullifier this note's ρ must equal
           nf           ∈ 𝔽_p    this note's nullifier

witness    g_d, pk_d    ∈ P*     non-identity Pallas points
           v            ∈ [0, 2^64)
           ρ, ψ         ∈ 𝔽_p
           rcm          ∈ 𝔽_q    the commitment trapdoor
           nk           ∈ 𝔽_p
           path         32 siblings ∈ 𝔽_p
           pos          ∈ [0, 2^32)

relation   cm   = NoteCommit^Orchard_rcm(g_d, pk_d, v, ρ, ψ)          [spec §5.4.8.4]
           root = MerklePath(cmx, path, pos) with cmx = Extract_P(cm)   [spec §4.9, MerkleCRH^Orchard]
           root = anchor
           ρ    = nf_prev
           nf   = DeriveNullifier_nk(ρ, ψ, cm)                          [spec §4.16]
```

### 4.2 WAKE_GENESIS

Identical to WAKE_HOP with `nf_prev` replaced by `cmx_0 ∈ 𝔽_p` and the constraint `ρ = nf_prev`
replaced by `Extract_P(cm) = cmx_0`.

### 4.3 What is deliberately absent

No value commitment, no spend authorisation (`rk`, `α`, `ak`), no `ivk` commitment, no output
note. WAKE never proves the right to spend; it proves that a note exists in the tree, what its `ρ`
is, and what its nullifier is. The holder's `nk` suffices, so a view-only wallet can produce
wake proofs.

## 5. Circuit

- **Arithmetisation:** the Orchard Action circuit's chips (`SinsemillaChip`, `MerkleChip`,
  `EccChip`, `PoseidonChip`) and the Orchard note-commitment gadget with its canonicity
  constraints, unchanged. Implementations SHOULD derive the circuit from
  `orchard/src/circuit.rs` by deletion, so a reviewer can diff.
- **Domains:** exactly Orchard's: `MerkleCRH^Orchard`, `NoteCommit^Orchard`, the Poseidon
  nullifier PRF, and Orchard's fixed bases. A circuit using any other domain proves membership
  in a tree that does not exist.
- **Size:** `k = 11` (2,048 rows), the Action circuit's parameter. Implementations MUST state
  their `k` in the verifying-key identifier (§7.4).
- **Instance column:** one column, rows in this order:
  `[anchor, nf_prev, nf]` for WAKE_HOP and `[anchor, cmx_0, nf]` for WAKE_GENESIS.
- **The one added constraint** relative to the Action circuit's spend half: the witnessed `ρ`
  cell (the same cell that feeds the note commitment and the nullifier derivation) is
  constrained equal to instance row 1. It MUST be the cell inside the commitment, not a copy.

## 6. Witness derivation (off-circuit, normative for interoperability)

Given a decrypted note and the holder's full viewing key:

| Field | Derivation |
|---|---|
| `g_d`, `pk_d` | from the note's recipient address, as the Orchard spec |
| `ψ` | `PRF^expand_rseed([0x09] ‖ ρ)` → `ToBase` |
| `rcm` | note version V2: `PRF^expand_rseed([0x05] ‖ ρ)` → `ToScalar`. Note version V3 (Ironwood, ZIP 2005): `PRF^expand_rseed([0x0B] ‖ g_d* ‖ pk_d* ‖ I2LEOSP_64(v) ‖ ρ ‖ ψ)` → `ToScalar` |
| `nk` | `FullViewingKey::nk()`, public in `orchard 0.15.3` under the `unstable-voting-circuits` feature (`keys.rs:346`); equivalently bytes 32..64 of the raw full-viewing-key encoding (spec §5.6.4.4). Implementations MUST use one of these and MUST NOT re-derive `nk` from the spending key, so a view-only wallet can prove |
| `path`, `pos` | the note's authentication path at `anchor` |

An implementation MUST verify, in tests, that its derivation reproduces the library's own
`commitment()` and `nullifier()` for both note versions before it proves anything. A wrong
`rcm` derivation does not produce an invalid proof; it produces a valid proof of a note that is
not in the tree, which fails at verification with no indication of why.

## 7. Encodings

### 7.1 Field elements

`𝔽_p` elements are 32 bytes, little-endian canonical (`to_repr()`), and MUST be canonical on
input: a verifier MUST reject a non-canonical encoding rather than reduce it.

### 7.2 Wake proof

```
{
  "kind":     "wake-v1",
  "circuit":  "hop" | "genesis",
  "instance": [ "<anchor hex>", "<nf_prev | cmx_0 hex>", "<nf hex>" ],
  "proof":    "<base64, the Halo 2 transcript bytes>"
}
```

**Erratum, 2026-09-25 (from the reference implementation).** The wake proof object MUST also carry

```
  "anchor_height": <integer>
```

the block height whose end-of-block note-commitment tree has `instance[0]` as its root. Every
oracle a verifier can use, a full node's `z_gettreestate` and lightwalletd's `GetTreeState`
alike, answers "what is the root at height h" and none answers "at what height is this root";
without the height, W2 cannot be evaluated at all. The value is a hint from the prover, who
knows it: the oracle still decides whether the root is real at that height, and the depth in
W2 is computed from it. `zmap-wake` writes and requires this field.

### 7.3 Lading

```
{
  "wake_lading": 1,
  "genesis":  { "txid": "<hex>", "action_index": n },
  "hops":     [ <genesis proof>, <hop proof>, … ]
}
```

- `hops[0].circuit` MUST be `"genesis"`; every later entry MUST be `"hop"`.
- `hops[j].instance[1]` MUST equal `hops[j-1].instance[2]` for `j ≥ 1` (the chain rule).
- The lading hash is `SHA-256` over the lading bytes **exactly as delivered**. Never
  re-serialise before hashing.
- A lading MUST NOT be published. The `(nf_prev, nf)` pairs in it link transactions.

### 7.4 Verifying-key identifier

```
vk_id = BLAKE2b-256( personal = "WAKE-v1-vk", input = "wake-v1" ‖ circuit_name ‖ I2BEOSP_32(k) ‖ pinned_vk )
```

where `pinned_vk` is the byte string of the verifying key's *pinned* form, the deterministic
debug rendering of `PinnedVerificationKey` that Halo 2 provides for exactly this purpose
(`VerifyingKey::pinned()`), UTF-8 encoded. This follows the precedent set by Zcash Coin Voting's
`vk_fingerprint_unchanged` test (`voting-circuits 0.12.1`, `delegation/prove.rs:271-290`), which
hashes `format!("{:?}", vk.pinned())` with BLAKE2b-256 and pins the result in a test so any
drift in the circuit's shape fails CI.

Rules:

- A proof carries no `vk_id`. The verifier's `kind` + `circuit` selects its own key.
- Implementations MUST publish the `vk_id` of each of their two circuits, and MUST carry a
  test that recomputes it from a fresh keygen and compares to the published constant.
  A changed `vk_id` means the circuit changed; the version MUST be bumped (§12).
- Two implementations agree on a circuit if and only if their `vk_id`s agree. A proof from one
  is meaningless to the other otherwise, and the failure is silent: verification simply fails.
- The pinned form, not the serialised key bytes, is hashed because Halo 2's key serialisation
  is not guaranteed stable across library versions while the pinned rendering is defined as
  the stable identity of a circuit's shape.

## 8. Verification procedure

Given a lading, the note in hand (specifically its `ρ`), and an oracle the verifier chooses:

| # | Check | Failure |
|---|---|---|
| W1 | `hops[0].circuit == "genesis"`; `cmx_0` in its instance equals the oracle's `cmx` at `genesis.(txid, action_index)` | `GenesisNotOnChain` |
| W2 | for each `j`: `hops[j].instance[0]` is a tree root at least `MIN_DEPTH` blocks below the oracle's tip | `AnchorUnknown(j)` / `AnchorTooShallow(j)` |
| W3 | for each `j`: the proof verifies under the key for its circuit | `BadProof(j)` |
| W4 | for each `j ≥ 1`: `hops[j].instance[1] == hops[j-1].instance[2]` | `ChainBreak(j)` |
| W5 | the note in hand has `ρ == hops[last].instance[2]` | `RhoMismatch` |

- `MIN_DEPTH` is 100. A proof against a shallower anchor is not wrong; it is not yet safe.
- Nullifier-set membership is **not** checked. Membership of `N_{j+1}` with `ρ = nf_j` implies
  `nf_j` was revealed, by consensus. Omitting the lookup removes one thing an oracle can lie about.
- A verifier MUST report *which* check failed. `GenesisNotOnChain` and `BadProof` are evidence
  of forgery; `AnchorTooShallow` and a missing lading are not.
- A verifier MUST NOT report success on a subset of checks.

### 8.1 Oracle requirements

The oracle answers two questions: *is this a root of the pool's commitment tree at or below
height h*, and *what is the extracted commitment at output (txid, index)*. A full node answers
both from its own state. A light client answers them from a server and MUST either verify tree
roots against the block-header chain (ZIP 221 history commitments) or report the result as
**unverified**, never as verified. A prover who also controls the verifier's server can
otherwise supply a fabricated root matching a fabricated proof.

## 9. Security considerations

- **Soundness is the circuit's.** Halo 2 removes the trusted setup, not the reviewer. §11.
- **`ρ` must be constrained inside the commitment.** A `ρ` supplied beside the commitment and
  merely equated to the instance proves nothing about the note.
- **Anchors are claims until the oracle confirms them.** The proof says "if this is a root, the
  note is under it". The verifier decides whether it is a root.
- **One successor is guaranteed; one *claimant* is not.** A holder can produce a valid proof for
  a note, then spend it. WAKE proves what a note is at the time of proving, and the oracle's
  nullifier set, if consulted, tells whether it is still unspent. Overlays that sell notes MUST
  settle that question themselves.
- **Reorgs.** A proof against a rolled-back anchor fails W2. Only the prover can re-prove, which
  needs the note's path; provers SHOULD prove before spending, while the path is held.
- **Privacy of a v1 lading.** The recipient of a lading learns the lineage's nullifiers and
  hence which transactions carried the note, not who made them or what else they contained.
  Nothing in a lading identifies an address, a value, or a key. Publishing a lading would let
  anyone link those transactions; hence §7.3's rule.
- **`nk` exposure.** `nk` is a witness and never appears in an instance. Implementations MUST
  ensure no gadget copies it to a public cell. Leaking `nk` lets anyone compute the nullifier
  of every note the holder owns.
- **Cross-implementation agreement.** Two implementations with different `vk_id`s (§7.4)
  built different circuits; a proof from one is meaningless to the other. Publish `vk_id`s and
  pin them in tests.

## 10. Limitations, stated so nobody assumes otherwise

- WAKE does not cross bundles or pools. The Orchard→Ironwood migration breaks a wake once; any
  future pool will break it again. Bridging requires either an overlay-level attestation
  (trusted) or a cross-bundle proof of transaction membership (ZIP 244 digests in-circuit;
  planned for v2).
- WAKE does not prove current ownership, non-spending, or that the holder will deliver the
  lading. Settlement is out of scope.
- WAKE does not compress. A lading grows by one proof per hop; v2's recursive form makes it
  constant-size and hides intermediate nullifiers from the recipient.
- WAKE does not know what a note *means*. The overlay designates genesis outputs and gives them
  names; WAKE only proves descent from them.

## 11. Review and publication gate

Before any implementation reports "verified" on the strength of a wake proof:

1. Negative tests for every case in `zecboat_wake_circuit.md` P3, each shown to fail against
   the real circuit and to pass against a deliberately broken one.
2. An equivalence test showing the witness path reproduces the note library's own commitment
   and nullifier for V2 and V3 notes.
3. A constraint listing, one line per gate, with the Orchard `circuit.rs` line each was taken
   from or the reason it is new.
4. External review of the circuit by someone who does Halo 2 for a living, answering:
   *"Can a prover satisfy WAKE_HOP with `ρ ≠ nf_prev`, or with `nf` not derived from the
   witnessed `nk`, or with `cm` not in the tree at `anchor`?"*
5. Published `vk_id`s and a mainnet test vector: one real hop on Zcash mainnet, lading and
   note `ρ` given, verifiable by anyone with a node.

## 12. Versioning

`kind` is `"wake-v1"`. Any change to the relation, the domains, the instance layout, `k`, or
the encodings is `"wake-v2"`. Verifiers MUST reject unknown kinds rather than guess.

Planned for v2: recursion (constant-size ladings, intermediate nullifiers hidden from the
recipient); cross-bundle hops via transaction-membership proofs; a fungible-split relation
binding an allocation root in the successor's `rseed`.

**Candidate for v1.5 (2026-09-25): `WAKE_HOPS_k`.** One proof over k consecutive notes,
enforcing every `ρ_{j+1} = nf_j` in-circuit and exposing only `cmx_0` (or `nf_prev` of the
first) and `nf_last`. For a chain of at most k hops the lading then discloses nothing the
recipient does not already hold; longer chains disclose one link per k hops. No recursion;
k = 5 fits `K = 12` by the Coin Voting delegation-circuit precedent (five note slots). This
is the practical answer to §9 "privacy of a v1 lading" until v2.

*2026-09-26 note:* as stated, `WAKE_HOPS_k` needs one prover to hold `nk` for all k notes, so
without recursion it covers only single-holder chains; the sizing (k = 5 at `K = 12`) is also
optimistic, since each slot carries a full Merkle path (~1,289 rows). The v1.5 candidate for
multi-holder chains is a committed-nullifier hop (`[anchor, C_prev, C_this]`, each holder
opens its own `C` to the next). Analysis and comparison: kept by the maintainers, available on request.

## 13. References

- Zcash Protocol Specification: §4.7.3 (Orchard note creation, `ρ`), §4.9 (Merkle path),
  §4.16 (nullifiers), §5.4.8.4 (`NoteCommit^Orchard`), §5.6.4.4 (FVK encoding).
- ZIP 2005 (Ironwood quantum recoverability; V3 `rcm` derivation).
- ZIP 221 (FlyClient history commitments), for light-client anchor verification.
- ZIP 244 (transaction digests), for the v2 cross-bundle hop.
- `orchard 0.15.3`: `src/circuit.rs`, `src/circuit/note_commit.rs`, `src/circuit/gadget.rs`,
  `src/note.rs`, `src/keys.rs`. Licence MIT OR Apache-2.0. The `unstable-voting-circuits`
  feature exposes `circuit::{note_commit, commit_ivk}`, `constants`, `RandomSeed::{psi,
  rcm_v2, rcm_v3}` and `FullViewingKey::nk()`.
- Zcash Coin Voting, `voting-circuits 0.12.1` and `zcash_voting 5.0.2` (MIT OR Apache-2.0):
  a shipped custom Halo 2 circuit over Orchard notes on the same crate and feature; the source
  of §6's witness derivation pattern and §7.4's fingerprint mechanism.
- ZMAP v0.5: §5.5, §9 check 7, §12.3, §15.
- Peter Todd, single-use seals; RGB and Taproot Assets, for the client-side-validation model
  WAKE follows and the on-chain ownership graph it does not expose.
