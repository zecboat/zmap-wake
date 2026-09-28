//! Print the Ironwood Actions of a raw transaction: `txinfo <hex file or hex>`.
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;
fn main() -> anyhow::Result<()> {
    let arg = std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: txinfo <hex file or hex>"))?;
    let hex = std::fs::read_to_string(&arg).unwrap_or(arg);
    let bytes = zmap_wake::pin::decode_hex(hex.trim())?;
    let tx = Transaction::read(&bytes[..], BranchId::Nu6_3)?;
    let txid: TxId = tx.txid();
    println!("txid {txid}  version {:?}  {} bytes", tx.version(), bytes.len());
    if let Some(b) = tx.ironwood_bundle() {
        for (i, a) in b.actions().iter().enumerate() {
            println!("  ironwood action {i}: nf {} cmx {}", zmap_wake::oracle::hex(&a.nullifier().to_bytes()), zmap_wake::oracle::hex(&a.cmx().to_bytes()));
        }
    }
    if let Some(b) = tx.orchard_bundle() {
        println!("  orchard actions: {}", b.actions().len());
    }
    Ok(())
}
