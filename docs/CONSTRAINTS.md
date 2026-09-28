# Wake v1 — constraint listing

For the external reviewer (`WAKE-v1.md` §11 item 3). One line per gate, lookup, and copy
constraint, with where it came from. Generated 2026-09-25 against `orchard 0.15.3`,
`halo2_gadgets 0.5.0`, `halo2_proofs 0.3.2`, `K = 11`.

The question this listing exists to answer, verbatim from §11:

> Can a prover satisfy `WAKE_HOP` with `ρ ≠ nf_prev`, or with `nf` not derived from the
> witnessed `nk`, or with `cm` not in the tree at `anchor`?

## 0. Shape, from the pinned verifying keys

`docs/pinned_vk_hop.txt` and `docs/pinned_vk_genesis.txt` are `format!("{:#?}", vk.pinned())`,
the stable identity of a circuit's shape, 900,319 bytes each.

| | value |
|---|---|
| `num_fixed_columns` | 28 |
| `num_advice_columns` | 10 |
| `num_instance_columns` | 1 (three rows: `[anchor, nf_prev \| cmx_0, nf]`) |
| `num_selectors` | 43 |
| lookups | 3 |
| `max_deg` | 9 |
| rows used at `K = 11` | 1,289 of 2,048 |

**`diff pinned_vk_hop.txt pinned_vk_genesis.txt` is two lines**: two permutation commitments.
Every gate, lookup, column and selector is identical between the two circuits. The only
difference is which cell is copy-constrained to instance row 1 (§3 below), which is exactly
the design: one added constraint, two circuits.

```
vk_id hop     = c10ee672500b17ea7c94376b6bc1ee988870b9354d1bd391ed1f1324c953707f
vk_id genesis = decb572630f885fd6a98266f5faea215193597eb5e83a6da8e6912bb083334e9
```

Pinned in `src/keys.rs` and checked by a test that is not ignored.

## 1. The relation (what the constraints must enforce)

```
WAKE_HOP      public   anchor, nf_prev, nf
              witness  g_d, pk_d, v, ρ, ψ, rcm, nk, path[32], pos

              (1) cm_old  = NoteCommit^Orchard_rcm(g_d, pk_d, v, ρ, ψ)
              (2) cm_old  ∈ tree(anchor) at pos via path
              (3) nf      = DeriveNullifier_nk(ρ, ψ, cm_old)
              (4) ρ       = nf_prev                                 [HOP]
                  Extract_P(cm_old) = cmx_0                          [GENESIS]
```

## 2. Synthesis, in order, with origin (`src/circuit.rs` → `orchard/src/circuit.rs`)

| Wake line | What | Orchard origin | Note |
|---|---|---|---|
| 458 | load the Sinsemilla generator table | 523 | unchanged |
| 466 | witness `psi_old` (advice[0]) | 531 | unchanged |
| 473 | witness `rho_old` (advice[0]) | 538 | **this is the cell of constraint (4)** |
| 480 | witness `cm_old` as a point | 545 | unchanged |
| 487 | witness `g_d_old` as a non-identity point | 552 | unchanged |
| — | witness `ak_P` | 560 | **deleted** (spend authority) |
| 496 | witness `nk` (advice[0]) | 567 | unchanged; never copied to any instance cell |
| 503 | witness `v_old` (advice[0]) | 574 | unchanged |
| — | witness `v_new` | 581 | **deleted** (output note) |
| 526 | `root = MerklePath(cm_old.extract_p())` | 591–603 | unchanged; two Merkle chips, `MerkleCrh` domain |
| 532 | `root == instance[ANCHOR]` (copy) | 855–864 via gate | **changed**: orchard has `v_old·(root − anchor) = 0` in `q_orchard`; Wake copy-constrains unconditionally |
| — | value commitment, `cv_net == instance` | 606–661 | **deleted** |
| 539 | `nf_old = DeriveNullifier(nk, rho_old, psi_old, cm_old)` | 664–674 | unchanged (`gadget::derive_nullifier`) |
| 552 | `nf_old == instance[NF]` (copy) | 677 | unchanged |
| — | spend authority `rk == instance` | 683–700 | **deleted** |
| — | `ivk = CommitIvk(ak, nk, rivk)`, `pk_d = [ivk] g_d` | 703–746 | **deleted**; `pk_d_old` is witnessed instead (line 560) |
| 568 | witness `rcm_old` as a fixed-base scalar | 750 | unchanged |
| 575 | `derived_cm_old = NoteCommit(g_d, pk_d, v, rho_old, psi_old, rcm_old)` | 757–770 | unchanged (`gadget::note_commit`), same chip config |
| 593 | `derived_cm_old == cm_old` (copy, both coordinates) | 773 | unchanged |
| — | `g_d_new`, `pk_d_new`, `cm_new`, `cmx == instance` | 776–836 | **deleted** |
| — | the "Orchard circuit checks" region and `q_orchard` | 839–884 | **deleted** |
| 604 | HOP: `rho_old.cell() == instance[LINK]` (copy) | — | **added**: the one Wake constraint |
| 605 | GENESIS: `cm_old.extract_p().cell() == instance[LINK]` (copy) | — | **added**: the one Wake constraint |
| — | cross-address checks | 935–1045 | **deleted** |

Why (4) holds on the right cell: `rho_old` at line 473 is one `AssignedCell`. The same cell
(cloned handles refer to the same cell) is passed to `derive_nullifier` (line 539) and to
`note_commit` (line 575), both of which copy-constrain it into their own regions, and to
`constrain_instance` (line 604). A prover cannot satisfy (1) and (3) with one ρ and (4) with
another: the permutation argument ties all three to the same value.

## 3. The four copy constraints Wake asserts directly

| # | Constraint | Where | Removed by (chapter 5) |
|---|---|---|---|
| C1 | `root == instance[0]` | circuit.rs:532 | `Sabotage::RootAnchor` |
| C2 | `nf_old == instance[2]` | circuit.rs:552 | `Sabotage::Nullifier` |
| C3 | `derived_cm_old == cm_old` | circuit.rs:593 | `Sabotage::CmEquality` |
| C4 | `rho_old == instance[1]` (HOP) / `Extract_P(cm_old) == instance[1]` (GENESIS) | circuit.rs:604–605 | `Sabotage::Link` |

`tests/negative.rs` shows, for each of ten attacks, that exactly one of C1–C4 catches it: the
attack passes with that constraint removed and fails with any other single constraint removed.

## 4. Gates, by chip, as configured in `Config::configure` (circuit.rs:165–304)

All from `halo2_gadgets 0.5.0` and `orchard 0.15.3`, unmodified. Line numbers are `create_gate`
calls in the crate sources (`~/.cargo/registry/src/*/`).

### EccChip (`ecc/chip.rs`, configured once, 10 advice, 8 Lagrange fixed columns)
| Gate | Source |
|---|---|
| witness point | `ecc/chip/witness_point.rs:58` |
| witness non-identity point | `ecc/chip/witness_point.rs:78` |
| complete addition | `ecc/chip/add.rs:79` |
| incomplete addition | `ecc/chip/add_incomplete.rs:58` |
| LSB check (variable-base mul) | `ecc/chip/mul.rs:132` |
| q_mul_1/2/3 == 1 checks (incomplete mul) | `ecc/chip/mul/incomplete.rs:173, 183, 213` |
| complete mul | `ecc/chip/mul/complete.rs:53` |
| overflow checks | `ecc/chip/mul/overflow.rs:51` |
| Running sum coordinates check (fixed-base) | `ecc/chip/mul_fixed.rs:116` |
| Canonicity checks (base-field-element fixed mul) | `ecc/chip/mul_fixed/base_field_elem.rs:65` |
| Full-width fixed-base scalar mul | `ecc/chip/mul_fixed/full_width.rs:37` |
| Short fixed-base mul gate | `ecc/chip/mul_fixed/short.rs:39` |

Used by Wake: witness point / non-identity point (`cm_old`, `g_d_old`, `pk_d_old`), complete
addition (`derive_nullifier`, `note_commit`), fixed-base base-field mul (`[prf+psi] NullifierK`),
full-width fixed mul (`[rcm] NoteCommitR` inside `note_commit`). Variable-base mul gates are
configured (the chip is shared) but no variable-base multiplication is synthesised: the only one
in orchard, `[ivk] g_d`, is deleted. `CircuitVersion::AnchoredBase` is used throughout.

### Poseidon Pow5Chip (`poseidon/pow5.rs`, width 3, rate 2, `P128Pow5T3`)
| Gate | Source |
|---|---|
| full round | `pow5.rs:94` |
| partial rounds | `pow5.rs:116` |
| pad-and-add | `pow5.rs:162` |

Used by: `PRF^nfOrchard_nk(ρ) = Poseidon(nk, ρ)` inside `derive_nullifier`.

### SinsemillaChip ×2 (`sinsemilla/chip.rs`; configs 1 and 2 on advice[..5] and advice[5..])
| Gate / lookup | Source |
|---|---|
| Initial y_Q | `sinsemilla/chip.rs:225` |
| Sinsemilla gate | `sinsemilla/chip.rs:243` |
| generator table lookup | `sinsemilla/chip/generator_table.rs:46` |

Config 1 serves `note_commit` and Merkle chip 1; config 2 serves Merkle chip 2 only (its
`NoteCommit_new` use is deleted).

### MerkleChip ×2 (`sinsemilla/merkle/chip.rs`)
| Gate | Source |
|---|---|
| Decomposition check | `merkle/chip.rs:136` |
| a' = b·swap + a·(1−swap) (CondSwap) | `utilities/cond_swap.rs:256` |

Domain `OrchardHashDomains::MerkleCrh`, depth 32, `pos` witnessed (tested: any position).

### LookupRangeCheckConfig (`utilities/lookup_range_check.rs`, advice[9], 10-bit table)
| Gate / lookup | Source |
|---|---|
| running-sum lookup | `lookup_range_check.rs:334` |
| Short lookup bitshift | `lookup_range_check.rs:370` |
| short range check (`utilities.rs`) | `utilities.rs:283` |

### NoteCommitChip ×1 (`orchard/src/circuit/note_commit.rs`; orchard configures it twice, Wake once)
| Gate | Source |
|---|---|
| NoteCommit MessagePiece b | `note_commit.rs:95` |
| NoteCommit MessagePiece d | `note_commit.rs:240` |
| NoteCommit MessagePiece e | `note_commit.rs:374` |
| NoteCommit MessagePiece g | `note_commit.rs:492` |
| NoteCommit MessagePiece h | `note_commit.rs:615` |
| NoteCommit input g_d (canonicity) | `note_commit.rs:738` |
| NoteCommit input pk_d (canonicity) | `note_commit.rs:855` |
| NoteCommit input value | `note_commit.rs:968` |
| NoteCommit input rho (canonicity) | `note_commit.rs:1049` |
| NoteCommit input psi (canonicity) | `note_commit.rs:1165` |
| y coordinate checks | `note_commit.rs:1287` |

These are the canonicity constraints that make constraint (1) bind `ρ` and `ψ` as field
elements, not as arbitrary bit strings. Wake keeps them unchanged.

### AddChip (`orchard/src/circuit/gadget/add_chip.rs`)
| Gate | Source |
|---|---|
| Field element addition: c = a + b | `add_chip.rs:50` |

Used by: `scalar = Poseidon(nk, ρ) + ψ` inside `derive_nullifier`.

### Deleted relative to the Action circuit (no gates from these exist in Wake)
- `q_orchard` "Orchard circuit checks" (`circuit.rs:331`): value balance, conditional root
  check, enable flags, cross-address reuse.
- `CommitIvkChip` (`circuit/commit_ivk.rs`): all its canonicity gates.
- The second `NoteCommitChip` config for the output note.

## 5. Lookups (3)

1. Sinsemilla generator table, config 1.
2. Sinsemilla generator table, config 2 (same table columns, second chip).
3. Range-check table (`table_idx`), used by `LookupRangeCheckConfig` and by the ECC and
   NoteCommit canonicity checks.

## 6. What is NOT constrained, on purpose (`WAKE-v1.md` §4.3)

- No spend authorisation: `ak`, `alpha`, `rk` absent. Wake never proves the right to spend.
- No `ivk` commitment: `pk_d` is a free witness. A prover can put any `pk_d` in; the
  commitment then simply is the commitment of that note, and (2) requires it to be in the tree.
- No value commitment.
- `nk` is a witness only. It is copied into the Poseidon region and nowhere else.

## 7. How to regenerate every number above

```sh
cargo test --test audit_dump -- --ignored --nocapture      # pinned VKs + vk_ids
cargo test --test positive circuit_cost_recorded -- --nocapture   # CircuitCost
diff docs/pinned_vk_hop.txt docs/pinned_vk_genesis.txt      # two lines
cargo test --test negative                                   # C1–C4 each catch their case
grep -nE 'constrain_instance|constrain_equal' src/circuit.rs
```

The layout diagram (`halo2_proofs::dev::CircuitLayout`) needs the `dev-graph` feature and
`plotters`, which were not available offline when this was written; render it with
`cargo test --features dev-graph` once online.
