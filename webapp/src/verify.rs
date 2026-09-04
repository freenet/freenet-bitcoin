//! Turning a claim's evidence into something a person can read.
//!
//! Every confirmed payment arrives with the transaction, a Merkle branch and a
//! run of block headers, and the browser re-checks all of it. What is shown is
//! the result of that check — not a restatement of what the bridge asserted.
//!
//! Be careful what that is worth. The check establishes that the evidence is
//! internally consistent and that the named output really pays this script
//! this amount, so a bridge cannot misreport what a real transaction paid.
//! It does **not** establish that the block is on Bitcoin: nothing here
//! anchors a header to the real chain, so that stays the bridge's word. The
//! checks below are phrased to claim only what they check.

use freenet_bitcoin_common::spv::{verify_spv_proof, SpvProof};
use freenet_bitcoin_common::{BitcoinAddressParameters, Claim, ClaimBody, OutPoint, Txid};

/// One checked fact, phrased for a reader.
#[derive(Clone, PartialEq, Debug)]
pub struct Check {
    pub ok: bool,
    pub headline: &'static str,
    pub detail: String,
}

/// What re-verifying one confirmed payment established.
#[derive(Clone, PartialEq, Debug)]
pub struct Verification {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub block_height: u32,
    pub checks: Vec<Check>,
    /// Length of the header run the evidence carries, checked for
    /// self-consistency — not a confirmation count against Bitcoin, since
    /// nothing places that run on the real chain.
    pub proven_depth: u32,
}

impl Verification {
    pub fn all_ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

/// Re-verify a confirmed-payment claim from scratch.
///
/// Deliberately re-derives rather than trusting the claim's own assertions:
/// the txid is recomputed from the transaction bytes, the script and amount
/// are read out of the parsed output, and the headers are hashed. A claim that
/// merely *says* it paid you is not evidence of anything.
///
/// What comes back is a self-consistency result. Which blocks are on Bitcoin
/// is not checked here and cannot be — see the module docs.
pub fn verify_claim(params: &BitcoinAddressParameters, body: &ClaimBody) -> Option<Verification> {
    let Claim::ConfirmedOutput {
        outpoint,
        value_sats,
        anchor,
        spv,
    } = &body.claim
    else {
        return None;
    };

    let result = verify_spv_proof(
        spv,
        &outpoint.txid,
        outpoint.vout,
        &params.script_pubkey,
        *value_sats,
        &anchor.hash,
        params.pow_floor,
    );

    let checks = match &result {
        Ok(v) => vec![
            Check {
                ok: true,
                headline: "The transaction really pays this address",
                detail: format!(
                    "Its id is the hash of its own bytes, so the amount and destination \
                     cannot be changed without changing the id. Output {} pays {} \
                     to this script.",
                    outpoint.vout,
                    fmt_sats(*value_sats)
                ),
            },
            Check {
                ok: true,
                headline: "It is in the block it claims to be in",
                detail: format!(
                    "A Merkle branch folds the transaction id up to block {}'s own \
                     summary of its contents.",
                    anchor.height
                ),
            },
            Check {
                ok: true,
                headline: "Each block header carries the work it claims",
                detail: format!(
                    "{} block header{} hashed and checked against the difficulty each \
                     one claims, chained by parent hash. This does not show the blocks \
                     are on Bitcoin \u{2014} that is the bridge's word.",
                    v.depth,
                    if v.depth == 1 { "" } else { "s" }
                ),
            },
        ],
        Err(e) => vec![Check {
            ok: false,
            headline: "This evidence does not check out",
            detail: e.to_string(),
        }],
    };

    Some(Verification {
        outpoint: *outpoint,
        value_sats: *value_sats,
        block_height: anchor.height,
        proven_depth: result.map(|v| v.depth).unwrap_or(0),
        checks,
    })
}

/// Size of the evidence carried, so a reader can see the cost of proving it.
pub fn evidence_bytes(spv: &SpvProof) -> usize {
    spv.raw_tx.len() + spv.merkle_branch.len() * 32 + 80 * (1 + spv.following_headers.len())
}

/// Render sats the way wallets do, without inventing precision.
pub fn fmt_sats(sats: u64) -> String {
    if sats >= 100_000_000 {
        let btc = sats as f64 / 100_000_000.0;
        format!("{btc:.8} BTC")
    } else {
        let s = sats.to_string();
        let mut out = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                out.push(',');
            }
            out.push(c);
        }
        format!("{} sats", out.chars().rev().collect::<String>())
    }
}

/// Explorer-style txid, reversed from internal byte order.
pub fn fmt_txid(t: &Txid) -> String {
    t.to_display_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sats_format_readably_and_switch_to_btc_at_one_coin() {
        assert_eq!(fmt_sats(999), "999 sats");
        assert_eq!(fmt_sats(50_000), "50,000 sats");
        assert_eq!(fmt_sats(1_234_567), "1,234,567 sats");
        assert_eq!(fmt_sats(100_000_000), "1.00000000 BTC");
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// fmt_sats carries its own unit, so no caller should append another.
    /// This shipped once as "99,972,850 sats sats".
    #[test]
    fn formatted_amounts_are_not_double_united() {
        let s = fmt_sats(99_972_850);
        assert_eq!(s.matches("sats").count(), 1, "got: {s}");
        let btc = fmt_sats(5_186_616_686);
        assert!(!btc.contains("sats"), "got: {btc}");
    }
}
