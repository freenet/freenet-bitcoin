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

use freenet_bitcoin_common::{
    to_cbor, BitcoinAddressParameters, BitcoinNetwork, BitcoinTipParameters, BridgeId,
};
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, ContractKey, Parameters};

/// The contract WASM this build talks to, embedded so the code hash is a fact
/// about this bundle rather than a claim about a deployment.
pub const ADDRESS_CONTRACT_WASM: &[u8] =
    include_bytes!("../contracts/bitcoin_address_contract.wasm");
pub const TIP_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/bitcoin_tip_contract.wasm");

/// Contract instance holding the public chain tip for a network.
pub fn tip_contract_id(
    network: BitcoinNetwork,
    trusted: &[BridgeId],
) -> Result<ContractInstanceId, String> {
    let params = BitcoinTipParameters {
        network,
        trusted_bridges: trusted.to_vec(),
    };
    let key = ContractKey::from_params_and_code(
        Parameters::from(to_cbor(&params)?),
        &ContractCode::from(TIP_CONTRACT_WASM.to_vec()),
    );
    Ok(*key.id())
}

/// Contract instance holding observations for one output script.
pub fn address_contract_id(
    network: BitcoinNetwork,
    script_pubkey: &[u8],
    trusted: &[BridgeId],
) -> Result<ContractInstanceId, String> {
    let params = address_params(network, script_pubkey, trusted);
    let key = ContractKey::from_params_and_code(
        Parameters::from(to_cbor(&params)?),
        &ContractCode::from(ADDRESS_CONTRACT_WASM.to_vec()),
    );
    Ok(*key.id())
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

pub fn tip_params(network: BitcoinNetwork, trusted: &[BridgeId]) -> BitcoinTipParameters {
    BitcoinTipParameters {
        network,
        trusted_bridges: trusted.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> BridgeId {
        BridgeId::from_bs58("4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL").unwrap()
    }

    /// Pinned against ids the deployed bridge independently reports. If a
    /// contract rebuild changes these, the assertion fires here rather than
    /// showing users an empty address forever.
    #[test]
    fn derivation_matches_the_deployed_bridge() {
        let tip = tip_contract_id(BitcoinNetwork::Signet, &[bridge()]).unwrap();
        assert_eq!(
            tip.to_string(),
            "B24HMUFasG3Yd1EJxfzb3qTPos1tLMiKo5gYiKwaihqT",
            "tip contract id drifted from the deployed contracts; rebuild the \
             embedded WASM and update this vector deliberately"
        );

        let script = hex::decode("0014360a3ba02d9603554f7746bf90e7c10d107d2cca").unwrap();
        let addr = address_contract_id(BitcoinNetwork::Signet, &script, &[bridge()]).unwrap();
        assert_eq!(
            addr.to_string(),
            "3Scd7J3ukmszib7qeHUBzSCXZuM4zF1cZqRbexLNs8nf"
        );
    }

    #[test]
    fn a_different_trusted_bridge_is_a_different_contract() {
        // Trust is part of the address, not a filter applied after reading:
        // two apps trusting different bridges genuinely read different state.
        let other = BridgeId([9u8; 32]);
        assert_ne!(
            tip_contract_id(BitcoinNetwork::Signet, &[bridge()]).unwrap(),
            tip_contract_id(BitcoinNetwork::Signet, &[other]).unwrap()
        );
    }

    #[test]
    fn networks_do_not_collide() {
        let script = hex::decode("0014360a3ba02d9603554f7746bf90e7c10d107d2cca").unwrap();
        assert_ne!(
            address_contract_id(BitcoinNetwork::Signet, &script, &[bridge()]).unwrap(),
            address_contract_id(BitcoinNetwork::Bitcoin, &script, &[bridge()]).unwrap()
        );
    }
}
