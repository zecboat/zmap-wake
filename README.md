# zmap-wake

Proofs of note lineage on Zcash: the reference implementation of `../WAKE-v1.md`, used by
`../ZMAP-v0.5.md` §9 check 7. Separate exploratory project; see `../README.md` and the
build boxes in `../wake_chapters.md`.

**Status: DRAFT. No external review. A missing constraint here is a forgery.** Nothing that
depends on this crate may report "verified" before `WAKE-v1.md` §11 has happened.

## Layout

| Module | Chapter | What |
|---|---|---|
| `witness` | 3 | private inputs from a note and a viewing key; independent recomputation of `cm`, `nf` |
| `wallet_path`, `wallet_notes` | 3, 7, 9 | notes and Merkle paths from a wallet **copy**; `.AppVault` paths are refused |
| `circuit` | 4 | `WAKE_HOP` / `WAKE_GENESIS`, orchard's Action circuit by deletion (`docs/diff_vs_orchard_circuit.md`) |
| `keys`, `prove`, `verify` | 4 | cached keys, pinned `vk_id`s, proving, verifying |
| `lading` | 6 | the delivered format; hash over raw bytes; `anchor_height` per entry |
| `oracle`, `oracle_lightwalletd` | 6 | `ChainOracle`; zebrad (JSON-RPC) and lightwalletd (gRPC, feature `lightwalletd`, untested) |
| `verify::verify_chain` | 6 | W1–W5 with named failures and the oracle's trust level |
| `pin`, `attest`, `manifest` | 9 | the §7.3 on-chain pin, the bridge attestation, `ik` + `genesis[]` |
| `testing` | – | fixtures; not for production |
| `src/bin/wake-issuer.rs` | 9 | the issuer-side CLI |

## Build and test

```sh
cargo test                       # everything but the mainnet test; ~2.5 min, keygen included
cargo test --lib                 # unit tests only, seconds
cargo check --features lightwalletd
cargo clippy --all-targets
```

The `sabotage` feature (chapter 5) exists only for this crate's own tests: it lets a test
build a circuit with one named constraint removed, so every negative test proves it would
catch that constraint's absence. The pinned `vk_id` test shows the knob changes nothing
while unused. Never enable it in a build that proves or verifies for real.

## Mainnet

`tests/mainnet_wake_test_001.rs` checks a complete real chain, Wake Test #001 (genesis and two
hops between throwaway wallets), against a local zebrad. Anyone with a node can run the first
test; the second rebuilds every proof from copies of the two wallets:

```sh
cargo test --release --test mainnet_wake_test_001 wake_test_001_published -- --ignored --nocapture
WAKE_TESTA_COPY=<copy> WAKE_TESTB_COPY=<copy> \
  cargo test --release --test mainnet_wake_test_001 wake_test_001_rebuilt -- --ignored --nocapture
```

Wallet copies are never published and never committed. Copy `wallet.db`
with the wallet closed, or `sqlite3 wallet.db ".backup copy.db"`. Never point anything here
at a live wallet; the crate refuses any path containing `.AppVault`.

## The issuer CLI

```
wake-issuer genesis        --wallet <mint copy.db> --txid <hex> --index <n> [--unit <u>] --out <file>
wake-issuer manifest add   --manifest <in.json> --out <out.json> [--ik <hex>] --unit <u:txid:index> ...
wake-issuer manifest check --manifest <file>
wake-issuer pin memo       --manifest <file> [--generation <g>]
wake-issuer pin sidecar    --generation <g> --txid <hex> --index <n> --ock <hex> --out <file>
wake-issuer pin verify     --manifest <file> --pin <sidecar.json> --address <UA|hex>
wake-issuer pin check-served --manifest-url <U> --pin-url <U> --address <UA|hex>
wake-issuer attest sign    --key <seed.hex> --cmx <hex> --asset-id <hex> --unit <u> --height <h> --out <file>
wake-issuer attest verify  --file <attestation.json> [--pubkey <hex>]
```

`--zebrad <url>` defaults to `http://127.0.0.1:8232`. Nothing here builds or sends a
transaction: `pin memo` prints the memo for the issuance wallet to send, and `genesis`
needs only the mint wallet's viewing key.

## Dependencies

Pinned to the exact versions in the Zecboat wallet's `Cargo.lock`: `orchard =0.15.3` with
`unstable-voting-circuits`, `halo2_proofs =0.3.2`, `halo2_gadgets =0.5.0`,
`pasta_curves =0.5.1`, `zcash_client_sqlite =0.22.0-rc.4` with `zcash_client_backend
=0.24.0-rc.4` (both must be pinned together). `cargo tree -d` shows one version of each.

## Specification, trust model, licence

- `docs/WAKE-v1.md`: the specification (draft for external review).
- `docs/TRUST_MODEL.md`: who is trusted for what, and what each result means.
- `docs/REVIEW_PACKAGE.md`: where a reviewer starts.
- Build with the toolchain in `rust-toolchain.toml`.
- Licensed under either of MIT (`LICENSE-MIT`) or Apache-2.0 (`LICENSE-APACHE`), at your option.
