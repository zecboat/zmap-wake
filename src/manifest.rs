//! Manifest additions for v0.5 (`ZMAP-v0.5.md` §7): `ik` and `genesis[]`.
//!
//! The manifest schema itself belongs to the issuer tooling, not to this crate.
//! This module treats the manifest as a JSON object, adds or reads the two v0.5
//! fields, and checks `genesis[]` against an oracle. Adding fields changes the
//! bytes, so the result is a new generation the issuer signs and pins.

use anyhow::{anyhow, bail, Context, Result};
use orchard::note::ExtractedNoteCommitment;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::oracle::{decode_hex_32, ChainOracle};

/// One line of `genesis[]`: the mint output of one unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisEntry {
    pub unit: u32,
    /// Display-order hex.
    pub txid: String,
    pub action_index: u32,
}

impl GenesisEntry {
    /// Parse `unit:txid:action_index`.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            bail!("expected unit:txid:action_index, got {s:?}");
        }
        let unit = parts[0].parse().context("unit")?;
        decode_hex_32(parts[1]).context("txid")?;
        let action_index = parts[2].parse().context("action_index")?;
        Ok(GenesisEntry {
            unit,
            txid: parts[1].to_lowercase(),
            action_index,
        })
    }
}

fn object(manifest_json: &[u8]) -> Result<Map<String, Value>> {
    match serde_json::from_slice::<Value>(manifest_json).context("manifest is not JSON")? {
        Value::Object(m) => Ok(m),
        _ => bail!("manifest is not a JSON object"),
    }
}

/// The manifest's `generation` field.
pub fn generation(manifest_json: &[u8]) -> Result<u32> {
    let m = object(manifest_json)?;
    m.get("generation")
        .and_then(Value::as_u64)
        .map(|g| g as u32)
        .ok_or_else(|| anyhow!("manifest has no integer `generation`"))
}

/// The manifest's `genesis[]`, empty if absent.
pub fn read_genesis(manifest_json: &[u8]) -> Result<Vec<GenesisEntry>> {
    let m = object(manifest_json)?;
    match m.get("genesis") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(v) => serde_json::from_value(v.clone()).context("genesis[] entries"),
    }
}

/// The manifest's `ik`, if present.
pub fn read_ik(manifest_json: &[u8]) -> Result<Option<String>> {
    let m = object(manifest_json)?;
    Ok(m.get("ik").and_then(Value::as_str).map(str::to_string))
}

/// Add or replace `ik` and `genesis[]`. Returns the new manifest bytes, pretty
/// printed. Every other field is carried over untouched in value, though the
/// serialisation is new: this is a new generation and must be signed and pinned.
pub fn add_genesis(
    manifest_json: &[u8],
    ik_hex: Option<&str>,
    entries: &[GenesisEntry],
) -> Result<Vec<u8>> {
    let mut m = object(manifest_json)?;
    if let Some(ik) = ik_hex {
        let bytes = crate::pin::decode_hex(ik).context("ik hex")?;
        if bytes.len() != 32 {
            bail!("ik must be a 32-byte x-only public key, got {} bytes", bytes.len());
        }
        m.insert("ik".into(), Value::String(ik.to_lowercase()));
    }
    let mut units: Vec<u32> = entries.iter().map(|e| e.unit).collect();
    units.sort_unstable();
    units.dedup();
    if units.len() != entries.len() {
        bail!("duplicate unit in genesis[]");
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.unit);
    m.insert("genesis".into(), serde_json::to_value(&sorted)?);
    let mut out = serde_json::to_vec_pretty(&Value::Object(m))?;
    out.push(b'\n');
    Ok(out)
}

/// Check every `genesis[]` entry against the oracle: the output exists and its
/// `cmx` is readable. Returns, per unit, the on-chain `cmx` or the reason it
/// could not be confirmed.
pub fn check_genesis(
    entries: &[GenesisEntry],
    oracle: &dyn ChainOracle,
) -> Vec<(u32, Result<ExtractedNoteCommitment, String>)> {
    entries
        .iter()
        .map(|e| {
            let r = decode_hex_32(&e.txid)
                .map_err(|x| x.to_string())
                .and_then(|txid| {
                    oracle
                        .cmx_at(&txid, e.action_index)
                        .map_err(|x| x.to_string())?
                        .ok_or_else(|| "no such output on the node".to_string())
                });
            (e.unit, r)
        })
        .collect()
}

/// `total_units` MUST equal `len(genesis[])` under v0.5 (§13).
pub fn check_finalization(manifest_json: &[u8]) -> Result<Option<(u64, usize)>> {
    let m = object(manifest_json)?;
    let total = m
        .get("finalization")
        .and_then(|f| f.get("total_units"))
        .or_else(|| m.get("total_units"))
        .and_then(Value::as_u64);
    let n = read_genesis(manifest_json)?.len();
    Ok(total.map(|t| (t, n)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &[u8] = br#"{"schema":"zecboat-proof-of-issuance/1","generation":2,"name":"WKT"}"#;

    #[test]
    fn add_and_read_back() {
        let e = vec![
            GenesisEntry::parse(&format!("2:{}:1", "ab".repeat(32))).unwrap(),
            GenesisEntry::parse(&format!("1:{}:0", "cd".repeat(32))).unwrap(),
        ];
        let out = add_genesis(M, Some(&"11".repeat(32)), &e).unwrap();
        assert_eq!(generation(&out).unwrap(), 2);
        assert_eq!(read_ik(&out).unwrap().as_deref(), Some("11".repeat(32).as_str()));
        let back = read_genesis(&out).unwrap();
        assert_eq!(back[0].unit, 1);
        assert_eq!(back[1].unit, 2);
        // the original fields survive
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["name"], "WKT");
        assert_eq!(v["schema"], "zecboat-proof-of-issuance/1");
    }

    #[test]
    fn duplicates_and_bad_ik_are_rejected() {
        let e = vec![
            GenesisEntry::parse(&format!("1:{}:0", "ab".repeat(32))).unwrap(),
            GenesisEntry::parse(&format!("1:{}:1", "ab".repeat(32))).unwrap(),
        ];
        assert!(add_genesis(M, None, &e).is_err());
        assert!(add_genesis(M, Some("abcd"), &[]).is_err());
        assert!(GenesisEntry::parse("1:zz:0").is_err());
    }

    #[test]
    fn absent_genesis_is_empty_not_error() {
        assert!(read_genesis(M).unwrap().is_empty());
        assert_eq!(read_ik(M).unwrap(), None);
    }
}
