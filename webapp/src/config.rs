//! Which bridges this build believes, and what to show before you ask.

use freenet_bitcoin_common::{BitcoinNetwork, BridgeId};

/// Bridges whose signed observations this build accepts, per network.
///
/// This is the app's entire trust configuration, and it is deliberately
/// explicit rather than discovered: believing a different bridge is a
/// different security posture, not a routing detail. It is also part of a
/// contract's address, so changing it genuinely changes which state you read.
///
/// Anyone may run a bridge. Pointing this at your own is the supported answer
/// to not wanting a third party to know which addresses you look up.
pub fn trusted_bridges(network: BitcoinNetwork) -> Vec<BridgeId> {
    let b58 = match network {
        // The Freenet.org bridge on nova, observing signet.
        BitcoinNetwork::Signet => Some("4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL"),
        // No mainnet bridge is published yet: its node is still in initial
        // block download, and publishing observations during IBD would be
        // misleading because an absence of payments means nothing.
        BitcoinNetwork::Bitcoin => None,
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => None,
    };
    b58.and_then(|s| BridgeId::from_bs58(s).ok())
        .into_iter()
        .collect()
}

/// Networks offered in the UI, in display order.
pub fn networks() -> Vec<BitcoinNetwork> {
    vec![BitcoinNetwork::Signet, BitcoinNetwork::Bitcoin]
}

pub fn default_network() -> BitcoinNetwork {
    BitcoinNetwork::Signet
}

/// An address worth showing before the visitor has looked anything up.
///
/// Public by construction and nobody's private interest: it is chosen by
/// whoever built this app, not observed from a user. Showing real, moving data
/// on the first screen is the difference between "here is a feature" and "here
/// is the thing working".
pub struct DemoAddress {
    pub address: &'static str,
    pub label: &'static str,
    pub why: &'static str,
}

pub fn demo_address(network: BitcoinNetwork) -> Option<DemoAddress> {
    match network {
        BitcoinNetwork::Signet => Some(DemoAddress {
            address: "tb1qxc9rhgpdjcp42nmhg6lepe7pp5g86tx25vlv8h",
            label: "A busy signet address",
            why: "Receives a few payments per block, so there is almost always \
                  something recent to look at. Nobody involved has heard of Freenet.",
        }),
        _ => None,
    }
}
