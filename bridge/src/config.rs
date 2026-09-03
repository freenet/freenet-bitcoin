//! Bridge configuration.

use std::path::PathBuf;

use freenet_bitcoin_common::BitcoinNetwork;
use serde::{Deserialize, Serialize};

/// Which service-authorization policy this operator runs.
///
/// This is the whole of "may this caller ask me to do work". It is an
/// **operator** choice and appears nowhere in the Bitcoin contracts: another
/// operator running `Open` produces observations that are byte-compatible with
/// Freenet.org's, and every application keeps working.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum AuthPolicy {
    /// Serve anybody who asks. Right for a bridge you run for yourself.
    #[default]
    Open,
    /// Serve holders of a valid Ghost Key — an anonymous certificate proving a
    /// donation to Freenet. This is Freenet.org's policy, and the reason a
    /// Ghost Key buys something concrete.
    GhostKey {
        /// Reject certificates whose chain does not reach this master key.
        /// `None` uses the key compiled into `ghostkey_lib`.
        #[serde(default)]
        master_verifying_key_b64: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetworkConfig {
    pub network: BitcoinNetwork,
    /// Bitcoin Core RPC endpoint. Loopback only in any sane deployment.
    pub rpc_url: String,
    /// Path to Bitcoin Core's `.cookie`. Preferred over a password: it rotates
    /// on restart and never sits in a config file.
    pub rpc_cookie_path: Option<PathBuf>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    /// Confirmation depth at which the bridge re-publishes a payment claim
    /// carrying enough headers to prove that depth on its own.
    #[serde(default = "default_deep_confirmations")]
    pub deep_confirmations: u32,
    /// How far back to walk when looking for a reorg fork point.
    #[serde(default = "default_reorg_depth")]
    pub max_reorg_depth: u32,
    /// Scripts this bridge always synchronizes, regardless of who asks.
    ///
    /// This is how the public demo data gets published: a curated, explicitly
    /// public address whose activity anybody can see without authenticating.
    /// It is not a watch list — nobody's interest is recorded by it.
    #[serde(default)]
    pub always_watch: Vec<String>,
    /// How many blocks of history to backfill for `always_watch` scripts.
    ///
    /// Bounded because a pruned node has not kept the early chain, and because
    /// an unbounded backfill on a busy address would fill the contract's claim
    /// cap with ancient history rather than recent activity.
    #[serde(default = "default_demo_backfill")]
    pub demo_backfill_blocks: u32,
}

fn default_demo_backfill() -> u32 {
    144
}

fn default_deep_confirmations() -> u32 {
    6
}

fn default_reorg_depth() -> u32 {
    100
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BridgeConfig {
    /// Where the bridge's Ed25519 signing key lives.
    ///
    /// This key authenticates Bitcoin observations. It is NOT a Bitcoin key
    /// and holds no funds; compromising it lets an attacker sign false
    /// assertions, which the SPV evidence in each claim then refutes — that is
    /// exactly why the evidence is there.
    pub signing_key_path: PathBuf,
    pub database_path: PathBuf,
    /// Address the HTTP service listens on. Put a reverse proxy in front for
    /// TLS; this should not face the internet directly.
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub auth: AuthPolicy,
    /// Freenet node WebSocket URL used to publish contract updates.
    #[serde(default = "default_freenet_ws")]
    pub freenet_ws: String,
    /// Directory holding the compiled contract WASM, so the bridge can compute
    /// contract keys and PUT the contracts themselves.
    pub contract_dir: PathBuf,
    pub networks: Vec<NetworkConfig>,
}

fn default_listen() -> String {
    "127.0.0.1:8431".to_string()
}

fn default_freenet_ws() -> String {
    // 7509 is the gateway's websocket port. Older docs say 50509; that is stale.
    "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native".to_string()
}

impl BridgeConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: BridgeConfig = toml::from_str(&text)?;
        if cfg.networks.is_empty() {
            anyhow::bail!("configuration lists no networks; the bridge would do nothing");
        }
        Ok(cfg)
    }

    pub fn network(&self, n: BitcoinNetwork) -> Option<&NetworkConfig> {
        self.networks.iter().find(|c| c.network == n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_config_parses_and_defaults_to_open_access() {
        // Defaulting to Open matters: the generic bridge must be usable by
        // anyone without adopting Freenet.org's donation policy.
        let cfg: BridgeConfig = toml::from_str(
            r#"
            signing_key_path = "/var/lib/btcbridge/key"
            database_path = "/var/lib/btcbridge/bridge.sqlite"
            contract_dir = "/var/lib/btcbridge/contracts"

            [[networks]]
            network = "Signet"
            rpc_url = "http://127.0.0.1:38332"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.auth, AuthPolicy::Open);
        assert_eq!(cfg.networks[0].deep_confirmations, 6);
        assert_eq!(cfg.listen, "127.0.0.1:8431");
    }

    #[test]
    fn ghost_key_policy_parses() {
        let cfg: BridgeConfig = toml::from_str(
            r#"
            signing_key_path = "/k"
            database_path = "/d"
            contract_dir = "/c"
            auth = { mode = "ghost_key" }

            [[networks]]
            network = "Bitcoin"
            rpc_url = "http://127.0.0.1:8332"
            "#,
        )
        .unwrap();
        assert!(matches!(cfg.auth, AuthPolicy::GhostKey { .. }));
    }

    #[test]
    fn a_config_with_no_networks_is_rejected_rather_than_silently_idle() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(
            &p,
            "signing_key_path=\"/k\"\ndatabase_path=\"/d\"\ncontract_dir=\"/c\"\nnetworks=[]\n",
        )
        .unwrap();
        assert!(BridgeConfig::load(&p).is_err());
    }
}
