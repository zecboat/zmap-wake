# Contributing to zmap-wake

Thank you for looking. This crate makes and checks proofs that a shielded note descends from
an issuer's original note. A missing constraint here is a forgery, so the guidelines below lean
towards caution rather than velocity.

**Status: draft circuits, no external review** (`docs/WAKE-v1.md` §11). Until that review has
happened, nothing built on this crate may report "verified" on the strength of a Wake proof,
and this file will not be the place that changes it.

---

## Reporting a soundness or security issue

**Do not open a public issue for a way to make a proof pass that should fail.**

Email **speed [at] zecboat.com** with `SECURITY` in the subject. You will get a reply; please
allow a reasonable window to fix the problem before publishing.

Worth reporting even if you are not certain it is exploitable:

- A constraint listed in `docs/CONSTRAINTS.md` that the circuit does not actually enforce
- A difference between the circuit and `docs/diff_vs_orchard_circuit.md`
- A lading, knot or pin that verifies when its claimed note, nullifier or anchor is wrong
- A verifier path that treats "the server did not answer" as "checked"
- Key material or a wallet file reachable somewhere it should not be

## Reporting a bug

Open an issue with what you did, what you expected, what happened, `rustc --version`, the
oracle you used (zebrad or a light server, and which) and the relevant output.

**Never attach a wallet file, a seed phrase, a viewing key of a real wallet, or the lading of a
real asset.** A lading discloses which transactions carried a unit (`docs/WAKE-v1.md` §9). The
published test vectors in `docs/test_vector/` are throwaway collections for exactly this reason;
use those, or mint your own throwaway.

---

## Code

### Style

Follow the [`librustzcash` style guides](https://github.com/zcash/librustzcash): `cargo fmt`,
`cargo clippy --all-targets` clean, and match the surrounding code rather than your own
preference. Comments carry the reasoning, not a restatement of the code; **if you change
something a comment justifies, update the comment in the same commit.**

### Things that are frozen

- **The circuits and their verifying keys.** `docs/pinned_vk_genesis.txt` and
  `docs/pinned_vk_hop.txt` are the `vk_id`s a wallet pins. A change to a circuit changes them,
  and every proof made before it stops verifying. A circuit change is a new circuit version
  with new pinned ids, documented in `docs/CONSTRAINTS.md` and
  `docs/diff_vs_orchard_circuit.md` in the same pull request. It is not a patch.
- **Knotline v1** (`docs/KNOTLINE-v1.md`). Its wire tags, address derivation and knot packing
  are pinned by the test `knotline::tests::v1_format_is_frozen`, and transactions on the main
  network already carry it. Never edit that test's expected values. A change is a new version
  byte, and readers keep reading v1 forever.
- **The lading format** (`lading`, `docs/WAKE-v1.md` §7.3). The hash is over the raw bytes and the
  canonical form is normative; a byte that moves breaks the `consignment_hash` in every memo
  already on chain.

### Things that will be rejected

- **A proof that passes with a constraint removed.** Every negative test under `tests/` builds
  the circuit with one named constraint deleted (the `sabotage` feature) and shows the proof
  then fails. A new constraint comes with its negative test, or it is not a constraint.
- **`sabotage` anywhere but this crate's own tests.** Never enable it in a build that proves or
  verifies for real.
- **Treating a failure as a pass.** A server that does not know a transaction has not checked
  it. A missing anchor is not a deep anchor. A trust level is reported, never upgraded.
- **Claiming more than was checked.** Any string or flag that implies a check the code does not
  perform, including the word "verified" before §11.
- **Code that opens a live wallet.** `wallet_path` refuses `.AppVault` paths on purpose; the
  mainnet tests take copies through environment variables and are `#[ignore]`d. Keep both.
- **Hardcoded paths, addresses or credentials.** Everything comes from arguments, environment
  variables or configuration.

### Testing

```sh
cargo test                                   # everything but the mainnet tests; ~2.5 min, keygen included
cargo test --lib                             # unit tests only, seconds
cargo test --lib --features lightwalletd     # adds the light-server oracle's tests
cargo clippy --all-targets
```

The mainnet tests are run by hand against a wallet **copy** and a node, as the README says.
Never run anything here against a wallet holding real funds or real assets.

---

## Pull requests

- **One change per pull request.** A refactor bundled with a fix makes both harder to review.
- **Say what you tested and how.** For anything touching `circuit`, `verify`, `lading` or
  `knotline`, that means which tests you added and whether the pinned `vk_id`s changed.
- **Spec and code move together.** A behaviour the specification describes changes in
  `docs/WAKE-v1.md` or `docs/KNOTLINE-v1.md` in the same pull request, with the "corrected"
  note the documents already use.
- **If you found a defect while doing something else, mention it** even if you did not fix it.

---

## Implementing something compatible

The specifications are published so that anyone can build a compatible prover, verifier or
wallet without this code: `docs/WAKE-v1.md`, `docs/KNOTLINE-v1.md`, and ZMAP at
<https://zecboat.com/protocol>. If you implement them and something is wrong or
underspecified, **that is a defect in the specification**: please report it.

## Reviewing the circuits

`docs/REVIEW_PACKAGE.md` is the entry point for a reviewer: what to read in which order, the
constraint list, the diff against Orchard's Action circuit, the trust model and the published
test vectors. A review finding is the most valuable contribution this repository can receive.
