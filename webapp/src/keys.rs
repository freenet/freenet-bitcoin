//! Deriving contract addresses locally, with no lookup of any kind.
//!
//! # Why this app embeds the contracts it reads
//!
//! A Freenet webapp is served under a Content-Security-Policy whose
//! `connect-src` is its own gateway and nothing else. It cannot fetch a
//! bridge's HTTP status endpoint to ask which contract to read — the browser
//! refuses the request. That is the sandbox working correctly: a Freenet app
//! reaches the world through its node.
//!
//! The alternative usually reached for is a compiled-in contract id, and it
//! rots: a contract's key is `BLAKE3(BLAKE3(wasm) || params)`, so any rebuild
//! moves it and every read then comes back empty — indistinguishable from "this
//! address has no activity". The failure is silent, which is the worst kind.
//!
//! So this app embeds the contract WASM itself and computes the key. The code
//! hash is derived from bytes shipped alongside the UI, so it cannot disagree
//! with them: if the contracts change, this app is rebuilt with them and the
//! derivation follows automatically. Nothing to update by hand, nothing to go
//! stale, and no network round trip before the first render.
//!
//! The one thing that IS configuration is which bridge to believe — and that
//! should be explicit, because it is a trust decision rather than an address.
//!
//! # Embedding is half the answer
//!
//! It guarantees this build's derivation matches this build's bytes. It
//! guarantees nothing about the *bridge's* bytes, and a bridge running a
//! different generation is writing to different addresses. That half is
//! handled at runtime by [`crate::generation`], which reads the code hash the
//! bridge signs for itself; the functions here take a code hash so the app can
//! derive from what the bridge says rather than from what it happens to ship.

use freenet_bitcoin_common::{
    to_cbor, BitcoinAddressParameters, BitcoinNetwork, BitcoinTipParameters, BridgeId,
};
use freenet_migrate::contract::contract_id_from_code_hash;
use freenet_stdlib::prelude::{ContractInstanceId, Parameters};

/// The contract WASM this build talks to, embedded so the code hash is a fact
/// about this bundle rather than a claim about a deployment.
pub const ADDRESS_CONTRACT_WASM: &[u8] =
    include_bytes!("../contracts/bitcoin_address_contract.wasm");
pub const TIP_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/bitcoin_tip_contract.wasm");

/// The address contract generation this build ships.
pub fn embedded_address_code_hash() -> [u8; 32] {
    freenet_bitcoin_generation::code_hash(ADDRESS_CONTRACT_WASM)
}

/// The tip contract generation this build ships.
pub fn embedded_tip_code_hash() -> [u8; 32] {
    freenet_bitcoin_generation::code_hash(TIP_CONTRACT_WASM)
}

/// Contract instance holding the public chain tip for a network, at a given
/// contract generation.
///
/// `code_hash` is what makes this a *generation*: the same parameters under a
/// different code hash are a different, unrelated contract holding nothing.
pub fn tip_contract_id_at(
    code_hash: &[u8; 32],
    network: BitcoinNetwork,
    trusted: &[BridgeId],
) -> Result<ContractInstanceId, String> {
    let params = BitcoinTipParameters {
        network,
        trusted_bridges: trusted.to_vec(),
    };
    Ok(contract_id_from_code_hash(
        code_hash,
        &Parameters::from(to_cbor(&params)?),
    ))
}

/// Contract instance holding observations for one output script, at a given
/// contract generation.
pub fn address_contract_id_at(
    code_hash: &[u8; 32],
    network: BitcoinNetwork,
    script_pubkey: &[u8],
    trusted: &[BridgeId],
) -> Result<ContractInstanceId, String> {
    let params = address_params(network, script_pubkey, trusted);
    Ok(contract_id_from_code_hash(
        code_hash,
        &Parameters::from(to_cbor(&params)?),
    ))
}

/// The parameters an address contract is instantiated with.
///
/// Exposed because a reader needs the *same* parameters to verify the claims
/// it reads back — verification is against these, not against whatever the
/// claim asserts about itself.
pub fn address_params(
    network: BitcoinNetwork,
    script_pubkey: &[u8],
    trusted: &[BridgeId],
) -> BitcoinAddressParameters {
    BitcoinAddressParameters {
        network,
        script_pubkey: script_pubkey.to_vec(),
        trusted_bridges: trusted.to_vec(),
        // Derived from the network, never configured: a weaker floor would
        // accept a cheaper forged header chain.
        pow_floor: network.default_pow_floor(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> BridgeId {
        BridgeId::from_bs58("4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL").unwrap()
    }

    /// Pinned so a re-key is visible here rather than as an address that
    /// silently reads empty forever.
    ///
    /// The vectors are recomputed deliberately when the contracts re-key, and
    /// the outgoing code hash goes into `legacy/` at the same time so the
    /// migration walk can still reach the state left behind. They track what
    /// THIS bundle derives; whether a bridge has published that generation yet
    /// is a separate question this test cannot see.
    ///
    /// Last moved on 2026-09-04 by `--remap-path-prefix`, which took the
    /// build machine's own paths out of the binary.
    ///
    /// This test is what found that. On the first CI run after it actually
    /// executed, it failed -- because the runner's build and nova's build were
    /// two different contracts. Dependency panic locations are absolute, so
    /// `/home/ian/.cargo/...` was compiled into every contract this project
    /// had ever shipped, and nobody else could reproduce what was deployed.
    /// A vector that only passes on one machine is not a pin, it is a local
    /// coincidence; these now hold everywhere.
    ///
    /// Recompute with `cargo make code-hashes-clean`, never a bare
    /// `cargo build`. A stale `target/` silently changes the answer -- a
    /// `cargo clean -p` of the workspace crates still reuses dependency
    /// artifacts, and under fat LTO those produce a different module -- and a
    /// build that skips `scripts/build-contracts.sh` bakes the machine back
    /// in.
    #[test]
    fn derivation_matches_the_embedded_contracts() {
        let tip = tip_contract_id_at(
            &embedded_tip_code_hash(),
            BitcoinNetwork::Signet,
            &[bridge()],
        )
        .unwrap();
        assert_eq!(
            tip.to_string(),
            "FXFgLKfuMm3NPtzWg3Ghgt5otv4Yo7N4CWGDvHpVeZMm",
            "tip contract id drifted; rebuild the embedded WASM, record the \
             outgoing hash in legacy/, and update this vector deliberately"
        );

        let script = hex::decode("0014360a3ba02d9603554f7746bf90e7c10d107d2cca").unwrap();
        let addr = address_contract_id_at(
            &embedded_address_code_hash(),
            BitcoinNetwork::Signet,
            &script,
            &[bridge()],
        )
        .unwrap();
        // Moved from 5Q1Dj2P6J4YgctzByLVfWg5yVkW5GsVMZfFZj9SXTuqx by the fold
        // tie-break fix in freenet-bitcoin-common, which re-keys the address
        // contract cd2ae741... -> c2273660... The outgoing generation is
        // recorded as A8 in legacy/address_contract.toml, so the bridge's
        // migration probe carries its state forward.
        //
        // The old id is still the LIVE one until the rebuilt WASM is deployed:
        // this vector pins what THIS BUNDLE derives, which is the whole point
        // of it, and a bundle built from this branch derives the new address.
        assert_eq!(
            addr.to_string(),
            "4KgYWMvGJtYdTAPAvXUUQWGd5Jv7KLsaaA2tQwFH2E6F",
            "address contract id drifted; same procedure as above"
        );
    }

    /// The generations `legacy/` records as SUPERSEDED, verbatim.
    ///
    /// Included as text rather than parsed: the check is "does this hash
    /// appear in that file", and a TOML parser in the webapp would be a
    /// dependency shipped to every browser to answer a question a substring
    /// search answers exactly.
    const SUPERSEDED_ADDRESS: &str = include_str!("../../legacy/address_contract.toml");
    const SUPERSEDED_TIP: &str = include_str!("../../legacy/tip_contract.toml");

    /// The bundle must not embed a generation the project has already
    /// retired.
    ///
    /// This is the failure the pinned vectors above cannot see. They check
    /// that the derivation matches the embedded bytes, which is true no matter
    /// how old those bytes are: a bundle built against a stale `target/`
    /// derives perfectly consistent addresses for a contract nobody publishes
    /// to any more. That happened — `webapp/contracts/` held a generation
    /// recorded in `legacy/` as superseded, and everything was self-consistent
    /// and wrong.
    ///
    /// Unlike the pinned vectors, this needs no maintenance on a re-key: the
    /// current generation is never written into `legacy/`, so a correct build
    /// passes by construction and only a stale one fails.
    #[test]
    fn embedded_contracts_are_not_a_superseded_generation() {
        for (what, hash, legacy) in [
            ("address", embedded_address_code_hash(), SUPERSEDED_ADDRESS),
            ("tip", embedded_tip_code_hash(), SUPERSEDED_TIP),
        ] {
            let hex = hex::encode(hash);
            assert!(
                !legacy.contains(&hex),
                "the embedded {what} contract is generation {hex}, which legacy/ records as \
                 SUPERSEDED. This bundle would derive addresses nobody publishes to, and the \
                 page would look exactly like an address with no activity. Rebuild the \
                 contracts (cargo make sync-webapp-contracts) before building the webapp."
            );
        }
    }

    #[test]
    fn a_different_trusted_bridge_is_a_different_contract() {
        // Trust is part of the address, not a filter applied after reading:
        // two apps trusting different bridges genuinely read different state.
        let other = BridgeId([9u8; 32]);
        let h = embedded_tip_code_hash();
        assert_ne!(
            tip_contract_id_at(&h, BitcoinNetwork::Signet, &[bridge()]).unwrap(),
            tip_contract_id_at(&h, BitcoinNetwork::Signet, &[other]).unwrap()
        );
    }

    #[test]
    fn networks_do_not_collide() {
        let script = hex::decode("0014360a3ba02d9603554f7746bf90e7c10d107d2cca").unwrap();
        let h = embedded_address_code_hash();
        assert_ne!(
            address_contract_id_at(&h, BitcoinNetwork::Signet, &script, &[bridge()]).unwrap(),
            address_contract_id_at(&h, BitcoinNetwork::Bitcoin, &script, &[bridge()]).unwrap()
        );
    }
}
