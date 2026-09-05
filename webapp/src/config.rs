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
        // The same bridge, observing mainnet. Its node finished initial block
        // download on 2026-09-04; before that it published nothing, because
        // during IBD an absence of payments means nothing.
        //
        // It watches no addresses, deliberately (`always_watch = []` in the
        // operator's config): the chain tip is public data about nobody, while
        // observations about a specific mainnet address are a real person's
        // money published to a permanent, replicated network. So mainnet shows
        // a live tip and recent blocks and no payments, and that is correct
        // rather than broken.
        BitcoinNetwork::Bitcoin => Some("4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL"),
        BitcoinNetwork::Testnet4 | BitcoinNetwork::Regtest => None,
    };
    b58.and_then(|s| BridgeId::from_bs58(s).ok())
        .into_iter()
        .collect()
}

pub fn default_network() -> BitcoinNetwork {
    BitcoinNetwork::Signet
}

/// Networks this build can show anything about, in the order to offer them.
///
/// Derived from [`trusted_bridges`] rather than listed separately, so a
/// network can never appear in the switcher with nothing behind it.
pub fn available_networks() -> Vec<BitcoinNetwork> {
    [
        BitcoinNetwork::Signet,
        BitcoinNetwork::Bitcoin,
        BitcoinNetwork::Testnet4,
        BitcoinNetwork::Regtest,
    ]
    .into_iter()
    .filter(|n| !trusted_bridges(*n).is_empty())
    .collect()
}

/// What a visitor needs to know about this network before drawing conclusions
/// from an empty screen.
///
/// Mainnet is the case that matters. The bridge watches no mainnet address on
/// purpose, so mainnet has a live chain tip and no payments — and "no
/// payments" is the same thing a broken deployment shows. Saying why turns an
/// ambiguous blank into a stated policy.
pub fn network_note(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Bitcoin => Some(
            "This bridge publishes mainnet's chain tip and recent blocks, and watches no \
             mainnet address. Observations about a specific address are somebody's real \
             money published to a permanent, replicated network, so which addresses to \
             watch is an operator's decision rather than a default. Look one up below and \
             it will show as unscanned until an operator chooses to synchronise it.",
        ),
        BitcoinNetwork::Signet => Some(
            "Signet is a Bitcoin test network. Its coins are worthless and its blocks are \
             cheap to produce, which is exactly why the bridge is willing to watch a busy \
             third-party address on it.",
        ),
        _ => None,
    }
}

/// An address worth showing before the visitor has looked anything up.
///
/// Public by construction and nobody's private interest: it is chosen by
/// whoever built this app, not observed from a user. Showing real, moving data
/// on the first screen is the difference between "here is a feature" and "here
/// is the thing working".
pub struct DemoAddress {
    pub address: &'static str,
    pub why: &'static str,
}

pub fn demo_address(network: BitcoinNetwork) -> Option<DemoAddress> {
    match network {
        BitcoinNetwork::Signet => Some(DemoAddress {
            address: "tb1qxc9rhgpdjcp42nmhg6lepe7pp5g86tx25vlv8h",
            why: "Receives a few payments per block, so there is almost always \
                  something recent to look at. Nobody involved has heard of Freenet.",
        }),
        _ => None,
    }
}
