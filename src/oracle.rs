//! Chain oracles (`WAKE-v1.md` §8.1): the verifier's chosen source for
//! "is this a root" and "what is the cmx at this output".
//!
//! An oracle answers from chain state the verifier trusts. A full node answers
//! from its own state. A light client answers from a server and MUST either
//! verify tree roots against the block-header chain (ZIP 221) or report the
//! result as *unverified*, never as verified.
//!
//! Provided here: [`ChainOracle`], the trait `verify_chain` consumes, and
//! [`ZebradOracle`], a zebrad (zcashd-compatible) JSON-RPC implementation. A plain
//! `http://` address, the normal case of a node on this machine, is asked directly;
//! only an `https://` address still shells out to `curl`. With the `lightwalletd`
//! feature, [`LightwalletdOracle`]
//! speaks gRPC to a lightwalletd or Zaino; it reports [`OracleTrust::ServerAsserted`]
//! because it does not check roots against block headers.

use std::cell::RefCell;
use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use incrementalmerkletree::frontier::NonEmptyFrontier;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{Anchor, MerkleHashOrchard};
use serde_json::{json, Value};
use zcash_client_backend::proto::service::TreeState;

/// Anchors shallower than this are not wrong, they are not yet safe (`WAKE-v1.md` §8).
pub const MIN_DEPTH: u32 = 100;

/// What the oracle says about a claimed anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorStatus {
    /// The root is the Ironwood tree root at the end of the claimed height,
    /// and that height is `depth` blocks below the oracle's tip.
    Known { depth: u32 },
    /// The root is not the tree root at the claimed height.
    Unknown,
}

/// How far an oracle's answers can be trusted (`WAKE-v1.md` §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleTrust {
    /// The oracle answers from chain state it validated itself (a full node).
    FullNode,
    /// The oracle relays a server's answers and has NOT checked tree roots against
    /// block headers. A verdict built on it MUST be reported as *unverified*.
    ServerAsserted,
}

/// The two questions a verifier asks the chain.
pub trait ChainOracle {
    /// Whether this oracle's answers are self-validated. Defaults to the weaker claim.
    fn trust(&self) -> OracleTrust {
        OracleTrust::ServerAsserted
    }

    /// Is `root` the Ironwood note-commitment-tree root at the end of block `height`,
    /// and how far below the tip is that block?
    fn anchor_at(&self, root: &Anchor, height: u32) -> Result<AnchorStatus>;

    /// The extracted commitment of the Ironwood output at `(txid, action_index)`,
    /// or `None` if the transaction is not mined or has no such Action.
    /// `txid` is in display (byte-reversed) order.
    fn cmx_at(&self, txid: &[u8; 32], action_index: u32) -> Result<Option<ExtractedNoteCommitment>>;
}

/// One Ironwood Action as the node reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodAction {
    /// The revealed nullifier of the spend. Zebrad encodes it as the field element's
    /// canonical bytes, not reversed (confirmed on mainnet 2026-09-25, chapter 7).
    pub nullifier: [u8; 32],
    /// The extracted commitment of the output, same encoding.
    pub cmx: [u8; 32],
}

/// The Ironwood note-commitment tree at the end of a block.
#[derive(Clone, Debug)]
pub struct IronwoodTreeState {
    pub height: u32,
    /// The tree's root after this block.
    pub root: Anchor,
    /// The tree's frontier after this block, ready for path regeneration.
    pub frontier: NonEmptyFrontier<MerkleHashOrchard>,
}

/// A zebrad (or zcashd-compatible) JSON-RPC endpoint, with a per-height cache of tree states.
#[derive(Debug)]
pub struct ZebradOracle {
    url: String,
    tree_cache: RefCell<HashMap<u32, IronwoodTreeState>>,
}

impl ZebradOracle {
    /// `url` is the RPC listen address, e.g. `http://127.0.0.1:8232`.
    pub fn new(url: impl Into<String>) -> Self {
        ZebradOracle {
            url: url.into(),
            tree_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Raw JSON-RPC call. Returns the `result` value or the node's error.
    pub fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
        // http:// only, over the crate's own TCP client. The former curl path honoured
        // proxies and ~/.curlrc and would connect to a userinfo host (audit 2026-10-08,
        // WAKE F-2); a node reached over TLS is somebody else's node in any case.
        if !self.url.starts_with("http://") {
            bail!("{}: a node is reached over plain http:// on this machine only", self.url);
        }
        let stdout = http_post_json(&self.url, &body)?;
        let v: Value = serde_json::from_slice(&stdout)
            .with_context(|| format!("parse RPC response to {method}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            bail!("{method}: node error {err}");
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result"))
    }

    /// The node's current block height.
    pub fn tip_height(&self) -> Result<u32> {
        let v = self.rpc("getblockcount", json!([]))?;
        v.as_u64()
            .map(|h| h as u32)
            .ok_or_else(|| anyhow!("getblockcount: not a number"))
    }

    /// The Ironwood tree state at the end of block `height` (`z_gettreestate`), cached.
    pub fn ironwood_tree_state(&self, height: u32) -> Result<IronwoodTreeState> {
        if let Some(ts) = self.tree_cache.borrow().get(&height) {
            return Ok(ts.clone());
        }
        let v = self.rpc("z_gettreestate", json!([height.to_string()]))?;
        let iw = v
            .get("ironwood")
            .ok_or_else(|| anyhow!("z_gettreestate: no ironwood field at {height}"))?;
        let final_state = iw
            .pointer("/commitments/finalState")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("z_gettreestate: no ironwood finalState"))?;
        let final_root = iw
            .pointer("/commitments/finalRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("z_gettreestate: no ironwood finalRoot"))?;

        let state = TreeState {
            ironwood_tree: final_state.to_string(),
            ..Default::default()
        };
        let tree = state
            .ironwood_tree()
            .context("parse ironwood finalState as a CommitmentTree")?;
        let root: Anchor = tree.root().into();
        let frontier = tree
            .to_frontier()
            .take()
            .ok_or_else(|| anyhow!("empty ironwood tree at {height}"))?;

        // The node's finalRoot must agree with the parsed tree; if it does not, the
        // encoding we assumed is wrong and no path built from this frontier can verify.
        let reported = decode_hex_32(final_root)?;
        if root.to_bytes() != reported && root.to_bytes() != reversed(reported) {
            bail!("ironwood finalRoot at {height} does not match the parsed tree root");
        }
        let ts = IronwoodTreeState {
            height,
            root,
            frontier,
        };
        self.tree_cache.borrow_mut().insert(height, ts.clone());
        Ok(ts)
    }

    /// `getrawtransaction` with the one answer that means "not on chain" told apart from every
    /// other failure. `None` only when a node THIS wallet runs says the transaction does not
    /// exist (zebrad error code -5); a node that is warming up, rate-limiting, answering in an
    /// unexpected shape, or that is not ours, is an error, never "not on chain". Before this
    /// (audit 2026-10-08, WAKE F-3) any node error became `GenesisNotOnChain`, a forgery verdict.
    fn get_mined_transaction(&self, txid_hex: &str) -> Result<Option<Value>> {
        match self.rpc("getrawtransaction", json!([txid_hex, 1])) {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                let msg = e.to_string();
                let no_such_tx = msg.contains("node error") && msg.contains("\"code\":-5");
                if no_such_tx && self.trust() == OracleTrust::FullNode {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// The raw bytes of a mined transaction and its height; `None` if not known as mined.
    /// `txid_hex` in display order.
    pub fn raw_transaction(&self, txid_hex: &str) -> Result<Option<(u32, Vec<u8>)>> {
        let Some(v) = self.get_mined_transaction(txid_hex)? else { return Ok(None) };
        let Some(height) = v.get("height").and_then(Value::as_u64) else {
            return Ok(None);
        };
        let hex = v.get("hex").and_then(Value::as_str).ok_or_else(|| anyhow!("getrawtransaction: no hex"))?;
        let raw = decode_hex(hex).context("getrawtransaction: hex")?;
        // The answer is checked against the id asked for, as the light-server path does
        // (audit 2026-10-08, Knotline G): a node reached over a network is somebody's server.
        let branch = zcash_protocol::consensus::BranchId::for_height(
            &zcash_protocol::consensus::MainNetwork,
            zcash_protocol::consensus::BlockHeight::from_u32(height as u32),
        );
        let tx = zcash_primitives::transaction::Transaction::read(&raw[..], branch).context("parse transaction")?;
        let asked = decode_hex_32(txid_hex)?;
        if tx.txid().as_ref() != &reversed(asked) {
            bail!("the node answered with a different transaction than the one asked for");
        }
        Ok(Some((height as u32, raw)))
    }

    /// The Ironwood Actions of a mined transaction, and the height it was mined at.
    /// `None` if the node does not know the transaction as mined.
    pub fn ironwood_actions(&self, txid_hex: &str) -> Result<Option<(u32, Vec<IronwoodAction>)>> {
        let Some(v) = self.get_mined_transaction(txid_hex)? else { return Ok(None) };
        let Some(height) = v.get("height").and_then(Value::as_u64) else {
            return Ok(None);
        };
        let acts = v
            .pointer("/ironwood/actions")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| anyhow!("getrawtransaction: no /ironwood/actions in the node's answer"))?;
        let mut out = Vec::with_capacity(acts.len());
        for a in &acts {
            let nf = a
                .get("nullifier")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("action without nullifier"))?;
            let cmx = a
                .get("cmx")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("action without cmx"))?;
            out.push(IronwoodAction {
                nullifier: decode_hex_32(nf)?,
                cmx: decode_hex_32(cmx)?,
            });
        }
        Ok(Some((height as u32, out)))
    }
}

/// POST a JSON body to a plain `http://host[:port][/path]` address and return the response
/// body. Small on purpose: one request, `Connection: close`, no redirects. It exists so that a
/// wallet asking a node on its own machine does not depend on an external program.
fn http_post_json(url: &str, body: &str) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let rest = url.strip_prefix("http://").ok_or_else(|| anyhow!("{url}: not an http:// address"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let with_port = if hostport.rsplit_once(':').map(|(_, p)| p.parse::<u16>().is_ok()).unwrap_or(false) {
        hostport.to_string()
    } else {
        format!("{hostport}:80")
    };
    let mut last = None;
    let mut stream = None;
    // A URL that claims to be local is connected to loopback only: `localhost` is whatever the
    // resolver says, and the trust decision was made on the name (audit 2026-10-08, WAKE F-2).
    let local = is_local_url(url);
    for addr in with_port.to_socket_addrs().with_context(|| format!("{url}: cannot resolve the address"))? {
        if local && !addr.ip().is_loopback() {
            continue;
        }
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| match last {
        Some(e) => anyhow!("no node answered at {url} ({e})"),
        None => anyhow!("no node answered at {url}"),
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    // `x:x`, as the curl call sent: zebrad ignores it unless cookie authentication is on.
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nAuthorization: Basic eDp4\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).with_context(|| format!("{url}: send"))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).with_context(|| format!("{url}: read"))?;

    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("{url}: not an HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let payload = &raw[split + 4..];
    let status = head.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("").to_string();
    if status == "401" || status == "403" {
        bail!("the node at {url} refused the request (HTTP {status}); it may require cookie authentication");
    }
    let chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    if !chunked {
        return Ok(payload.to_vec());
    }
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let line_end = payload[i..].windows(2).position(|w| w == b"\r\n").ok_or_else(|| anyhow!("{url}: bad chunked response"))? + i;
        let size_text = String::from_utf8_lossy(&payload[i..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| anyhow!("{url}: bad chunk size"))?;
        if size == 0 {
            return Ok(out);
        }
        let start = line_end + 2;
        let end = start.checked_add(size).filter(|e| *e <= payload.len()).ok_or_else(|| anyhow!("{url}: truncated chunk"))?;
        out.extend_from_slice(&payload[start..end]);
        i = end + 2;
        if i > payload.len() {
            bail!("{url}: truncated chunked response");
        }
    }
}

/// Whether `url` points at this machine: an IP literal in 127.0.0.0/8, `::1`, the v4-mapped
/// form of either, or the literal `localhost`; `http://` only; no userinfo.
///
/// WAKE-v1 §8.1: anchors count as self-validated only when the oracle is a node the verifier
/// runs. A zebrad reached over the network is someone else's word, however it is configured.
/// The first version was a string test (`starts_with("127.")`) and passed
/// `https://127.0.0.1@attacker.example/` and `127.evil.example` (audit 2026-10-08, WAKE F-2,
/// Zecboat D). What this still cannot see: a tunnel or proxy on loopback, or another process
/// squatting the port while no zebrad runs; those are stated limits, not detected ones.
pub fn is_local_url(url: &str) -> bool {
    local_host_of(url).is_some()
}

/// The host part of a local node URL, or `None` if the URL is not one (see [`is_local_url`]).
fn local_host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.contains('@') || hostport.is_empty() {
        return None;
    }
    let host = if let Some(h) = hostport.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return Some("localhost".into());
    }
    let ip: std::net::IpAddr = host.parse().ok()?;
    let loopback = match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false),
    };
    loopback.then(|| host.to_string())
}

impl ChainOracle for ZebradOracle {
    /// Full-node trust only for a zebrad on this machine (review M3, 2026-10-02): before, any
    /// URL in `ZECBOAT_ZEBRAD_RPC` yielded the strongest badge.
    fn trust(&self) -> OracleTrust {
        if is_local_url(&self.url) {
            OracleTrust::FullNode
        } else {
            OracleTrust::ServerAsserted
        }
    }

    fn anchor_at(&self, root: &Anchor, height: u32) -> Result<AnchorStatus> {
        let tip = self.tip_height()?;
        if height > tip {
            return Ok(AnchorStatus::Unknown);
        }
        let ts = self.ironwood_tree_state(height)?;
        if ts.root == *root {
            Ok(AnchorStatus::Known { depth: tip - height })
        } else {
            Ok(AnchorStatus::Unknown)
        }
    }

    fn cmx_at(&self, txid: &[u8; 32], action_index: u32) -> Result<Option<ExtractedNoteCommitment>> {
        let Some((_, actions)) = self.ironwood_actions(&hex(txid))? else {
            return Ok(None);
        };
        let Some(a) = actions.get(action_index as usize) else {
            return Ok(None);
        };
        let cmx: Option<ExtractedNoteCommitment> = ExtractedNoteCommitment::from_bytes(&a.cmx).into();
        Ok(cmx)
    }
}

#[cfg(feature = "lightwalletd")]
pub use crate::oracle_lightwalletd::LightwalletdOracle;

/// Decode exactly 32 bytes of hex: 64 ASCII characters `[0-9a-fA-F]`, nothing else. Slicing a
/// `str` by byte index panicked on non-ASCII input (audit 2026-10-08, WAKE F-6); this decodes
/// bytes and never slices text.
pub fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    let v = decode_hex(s.trim())?;
    let n = v.len();
    v.try_into().map_err(|_| anyhow!("expected 64 hex chars, got {}", 2 * n))
}

/// Decode a hex string of any even length; ASCII `[0-9a-fA-F]` only.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let b = s.as_bytes();
    if !s.is_ascii() || b.len() % 2 != 0 {
        bail!("not an even-length ASCII hex string");
    }
    let nib = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => bail!("not a hex digit: {:?}", c as char),
        }
    };
    b.chunks(2).map(|p| Ok(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The same 32 bytes in the other byte order (txids are displayed reversed).
pub fn reversed(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}

#[cfg(test)]
mod trust_tests {
    use super::*;

    #[test]
    fn only_a_node_on_this_machine_is_a_full_node() {
        for u in ["http://127.0.0.1:8232", "http://localhost:8232", "http://[::1]:8232", "http://127.5.6.7/", "http://[::ffff:127.0.0.1]:8232"] {
            assert!(is_local_url(u), "{u}");
        }
        // The bypasses of the first string test (audit 2026-10-08): userinfo, a DNS name that
        // starts with "127.", a name under localhost, https (nothing local is reached over TLS).
        for u in [
            "http://192.168.1.10:8232", "https://zec.rocks:443", "http://zebrad.lan:8232", "http://1270.0.0.1:8232",
            "https://127.0.0.1@attacker.example/", "http://127.0.0.1@attacker.example:8232", "http://127.evil.example:8232",
            "http://127.0.0.1.attacker.example:8232", "http://localhost.attacker.example:8232", "https://127.5.6.7/", "http://@127.0.0.1:8232",
        ] {
            assert!(!is_local_url(u), "{u}");
        }
    }

    #[test]
    fn hex_decoding_refuses_non_ascii_and_odd_input_without_panicking() {
        assert!(decode_hex_32("€").is_err());
        assert!(decode_hex_32(&"€".repeat(32)).is_err());
        assert!(decode_hex_32(&"+f".repeat(32)).is_err());
        assert!(decode_hex_32(&"0".repeat(63)).is_err());
        assert_eq!(decode_hex_32(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        assert!(decode_hex("abc").is_err());
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serve one canned response on a loopback port and hand back what the client sent.
    fn serve_once(response: &'static [u8]) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            // Read the head, then exactly Content-Length bytes of body.
            loop {
                let n = s.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
                if let Some(i) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&seen[..i]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map(|v| v.trim().parse().unwrap())
                        .unwrap_or(0);
                    if seen.len() >= i + 4 + len || n == 0 {
                        break;
                    }
                }
            }
            s.write_all(response).unwrap();
            String::from_utf8_lossy(&seen).to_string()
        });
        (url, handle)
    }

    #[test]
    fn a_plain_response_is_read_and_the_request_is_well_formed() {
        let (url, h) = serve_once(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 39\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":3507000}");
        let tip = ZebradOracle::new(url).tip_height().unwrap();
        assert_eq!(tip, 3_507_000);
        let sent = h.join().unwrap();
        assert!(sent.starts_with("POST / HTTP/1.1\r\n"), "{sent}");
        assert!(sent.contains("\"method\":\"getblockcount\""), "{sent}");
        assert!(sent.contains("Connection: close"), "{sent}");
    }

    #[test]
    fn a_chunked_response_is_reassembled() {
        let (url, h) = serve_once(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n14\r\n{\"jsonrpc\":\"2.0\",\"id\r\n13\r\n\":1,\"result\":12345}\r\n0\r\n\r\n");
        assert_eq!(ZebradOracle::new(url).tip_height().unwrap(), 12_345);
        h.join().unwrap();
    }

    #[test]
    fn a_node_error_is_reported_as_the_nodes_error() {
        let (url, h) = serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 74\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-5,\"message\":\"No such transaction\"}}");
        let e = ZebradOracle::new(url).rpc("getrawtransaction", json!(["00", 1])).unwrap_err().to_string();
        assert!(e.contains("node error"), "{e}");
        h.join().unwrap();
    }

    #[test]
    fn a_refused_request_says_so() {
        let (url, h) = serve_once(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n");
        let e = ZebradOracle::new(url).tip_height().unwrap_err().to_string();
        assert!(e.contains("refused the request"), "{e}");
        h.join().unwrap();
    }

    #[test]
    fn no_node_is_said_in_plain_words() {
        // Bind, read the port, drop the listener: nothing answers there now.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = ZebradOracle::new(format!("http://127.0.0.1:{port}")).tip_height().unwrap_err().to_string();
        assert!(e.starts_with("no node answered at http://127.0.0.1:"), "{e}");
    }
}
