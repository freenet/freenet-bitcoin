//! Bridge configuration.

use std::path::PathBuf;

use freenet_bitcoin_common::BitcoinNetwork;
use serde::{Deserialize, Serialize};

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
    /// The deepest confirmation any application using this bridge can prove.
    ///
    /// A verifier bounds a payment's depth by what the signing bridge asserted
    /// inside the claim, precisely so a submitter cannot pair a stale claim
    /// with a fresh chain tip (see `OutpointStatus::confirmations_at`). So the
    /// bridge re-publishes a confirmed payment as the chain buries it, on a
    /// doubling ladder up to this value, and an application asking for more
    /// confirmations than this will wait forever.
    ///
    /// 6 is the conventional mainnet figure and the conventional application
    /// default. Raise it if applications pointed at this bridge ask for more;
    /// the cost is `log2` extra claims per output, which the address
    /// contract's byte budget absorbs comfortably.
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
    /// Freenet node WebSocket URL used to publish contract updates.
    #[serde(default = "default_freenet_ws")]
    pub freenet_ws: String,
    /// Directory holding the compiled contract WASM, so the bridge can compute
    /// contract keys and PUT the contracts themselves.
    pub contract_dir: PathBuf,
    pub networks: Vec<NetworkConfig>,
}

fn default_freenet_ws() -> String {
    // 7509 is the gateway's websocket port. Older docs say 50509; that is stale.
    "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native".to_string()
}

impl BridgeConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let mut cfg: BridgeConfig = toml::from_str(&text)?;
        if cfg.networks.is_empty() {
            anyhow::bail!("configuration lists no networks; the bridge would do nothing");
        }
        // The bridge keeps the blocks from `BLOCKS_KEPT` below where it has
        // scanned upwards. Neither of these refuses the configuration: a
        // bridge that will not start observes nothing, and every payment mined
        // while it is down is missed, which is worse than either fault here.
        //
        // The block that ends a watch is `deep_confirmations - 1` below the
        // scan position, so a depth past `BLOCKS_KEPT + 1` names a block the
        // bridge no longer holds and no watch ends. That costs updates, not
        // payments, so it is reported and left alone rather than lowered: the
        // depth is the operator's judgement about how buried a payment must be
        // before this bridge will report it.
        let kept = crate::store::Store::BLOCKS_KEPT;
        for n in &mut cfg.networks {
            if n.deep_confirmations > kept + 1 {
                tracing::error!(
                    network = ?n.network,
                    deep_confirmations = n.deep_confirmations,
                    "deep_confirmations reaches past the {kept} blocks kept below the scan \
                     position, so no watch will end; lower it or watches last for ever"
                );
            }
            // A backfill past them rewinds at every start to a block the
            // bridge no longer holds. `Store::rewind_checkpoint_to` stops at
            // the oldest it does hold, so this only says so plainly; a demo
            // window is a display choice, and narrowing it costs nothing.
            if n.demo_backfill_blocks > kept {
                tracing::error!(
                    network = ?n.network,
                    demo_backfill_blocks = n.demo_backfill_blocks,
                    "demo_backfill_blocks reaches past the {kept} blocks kept below the scan \
                     position; using {kept}"
                );
                n.demo_backfill_blocks = kept;
            }
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
    fn a_minimal_config_parses() {
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
        assert_eq!(cfg.networks[0].deep_confirmations, 6);
    }

    /// A depth past the blocks the bridge keeps ends no watch, and a backfill
    /// past them rewinds to a block it no longer holds, which reads as a
    /// reorg. Neither refuses the configuration: the depth is reported and
    /// left alone, the backfill narrowed.
    #[test]
    fn a_depth_past_the_blocks_kept_is_reported_and_a_wide_backfill_narrowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.toml");
        let cfg = |extra: &str| {
            format!(
                r#"
                signing_key_path = "/k"
                database_path = "/d"
                contract_dir = "/c"

                [[networks]]
                network = "Signet"
                rpc_url = "http://127.0.0.1:38332"
                {extra}
                "#
            )
        };
        let kept = crate::store::Store::BLOCKS_KEPT;
        // A depth past the blocks kept is reported, not refused: a bridge that
        // will not start misses every payment mined while it is down.
        std::fs::write(&path, cfg(&format!("deep_confirmations = {}", kept + 2))).unwrap();
        let loaded = BridgeConfig::load(&path).expect("a deep config still starts the bridge");
        assert_eq!(
            loaded.networks[0].deep_confirmations,
            kept + 2,
            "left alone"
        );
        // A backfill past them is narrowed, since it only chooses how much
        // history the demo window shows.
        std::fs::write(&path, cfg(&format!("demo_backfill_blocks = {}", kept + 1))).unwrap();
        let loaded = BridgeConfig::load(&path).expect("a wide demo window still starts it");
        assert_eq!(loaded.networks[0].demo_backfill_blocks, kept);
        std::fs::write(&path, cfg(&format!("demo_backfill_blocks = {kept}"))).unwrap();
        let loaded = BridgeConfig::load(&path).unwrap();
        assert_eq!(
            loaded.networks[0].demo_backfill_blocks, kept,
            "the widest kept"
        );
    }

    /// The bridge used to serve HTTP, configured by `listen` and `auth`. A
    /// config file still carrying them must keep loading after an upgrade:
    /// refusing it would stop the bridge on restart over two settings that no
    /// longer do anything.
    #[test]
    fn a_config_written_for_the_old_http_service_still_parses() {
        let cfg: BridgeConfig = toml::from_str(
            r#"
            signing_key_path = "/k"
            database_path = "/d"
            contract_dir = "/c"
            listen = "127.0.0.1:8431"
            auth = { mode = "ghost_key" }

            [[networks]]
            network = "Bitcoin"
            rpc_url = "http://127.0.0.1:8332"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.networks[0].network, BitcoinNetwork::Bitcoin);
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
