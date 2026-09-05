//! `bitcoin-freenet-bridge` — synchronizes Bitcoin observations into Freenet.
//!
//! Two concurrent jobs:
//!
//! * an **observation loop** per network, following the chain and publishing
//!   signed observations into per-script Freenet contracts, and
//! * a **request service**, where clients ask this operator to synchronize a
//!   script (subject to whatever authorization policy the operator runs).
//!
//! Those are separate on purpose. The observations are public and generic, and
//! carry the evidence a reader needs to check what they say about a
//! transaction; who is allowed to ask for them is one operator's business and
//! never touches the Freenet wire.
//!
//! An observation is not self-validating, though. A reader who checks the
//! evidence learns that a real transaction paid that script that amount; which
//! blocks are on Bitcoin is this bridge's assertion, and readers trust it for
//! that. See `freenet_bitcoin_common::spv`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoin::Address;
use clap::Parser;
use freenet_bitcoin_common::BitcoinNetwork;

use bitcoin_freenet_bridge::{
    chain::ChainClient,
    config::BridgeConfig,
    freenet::FreenetPublisher,
    observer::{ClaimsByScript, Observer},
    service::{router, ServiceState},
    signer::Signer,
    store::{Store, WatchedScript},
};

#[derive(Parser)]
#[command(name = "bitcoin-freenet-bridge", version)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/bitcoin-freenet-bridge.toml")]
    config: std::path::PathBuf,
    /// Print the bridge's public signing key and exit.
    ///
    /// This is the id applications must trust in order to accept this
    /// bridge's observations, so it needs to be readable without starting
    /// the daemon.
    #[arg(long)]
    print_bridge_id: bool,
    /// Check the configuration and exit without connecting to anything.
    #[arg(long)]
    check: bool,
    /// Read an address's observations back OUT of Freenet and print what they
    /// establish.
    ///
    /// This is the honest end-to-end check. "The PUT returned Ok" only says
    /// the local node accepted the write; this says the data is retrievable
    /// and that its Bitcoin evidence verifies. Those are different claims and
    /// only the second means the integration works.
    #[arg(long, value_name = "ADDRESS")]
    verify: Option<String>,
    /// Network for --verify.
    #[arg(long, default_value = "signet")]
    network: String,
    /// With --verify: ask whether the observations in Freenet would satisfy an
    /// invoice for this many sats at this many confirmations.
    ///
    /// This is the join between the two halves. --verify alone shows Bitcoin
    /// data reached Freenet; this shows that data DECIDING something, using
    /// exactly the function an application contract calls.
    #[arg(long, value_name = "SATS")]
    prove_payment_of: Option<u64>,
    /// Confirmations required by --prove-payment-of.
    #[arg(long, default_value_t = 2)]
    confirmations: u32,
    /// Print which contract generation this bridge publishes to, and what its
    /// generation pointers currently say, then exit.
    ///
    /// This is the check to run after installing new contract WASM. It shows
    /// the code hash on disk beside the record readers will resolve, so a
    /// mismatch is a line of output rather than an application that renders
    /// an empty page.
    #[arg(long)]
    print_generation: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bitcoin_freenet_bridge=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = BridgeConfig::load(&cli.config)?;

    if cli.print_bridge_id {
        let signer = Signer::load_or_create(&cfg.signing_key_path)?;
        println!("{}", signer.bridge_id().to_bs58());
        return Ok(());
    }
    if cli.check {
        println!("configuration OK: {} network(s)", cfg.networks.len());
        return Ok(());
    }

    if cli.print_generation {
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(print_generation(cfg));
    }

    if let Some(address) = cli.verify.clone() {
        let network: BitcoinNetwork = cli
            .network
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(verify_address(
                cfg,
                network,
                &address,
                cli.prove_payment_of,
                cli.confirmations,
            ));
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cfg))
}

async fn run(cfg: BridgeConfig) -> Result<()> {
    let signer = Signer::load_or_create(&cfg.signing_key_path)?;
    tracing::info!(bridge_id = %signer.bridge_id().to_bs58(), "bridge starting");

    // Opened here purely to seed the operator's public demo scripts before
    // anything else starts; the observer and the service each open their own.
    let store = Store::open(&cfg.database_path)?;

    // Seed the operator's public demo scripts. These are explicitly public
    // data -- a curated address whose activity anybody may see -- and are NOT
    // anybody's private watch. Marked so a user cannot unwatch them.
    //
    // They are seeded with a backfill window rather than from height 0: a
    // pruned node has not kept the early chain, so asking for it would fail,
    // and a demo only needs recent activity to be convincing.
    for net_cfg in &cfg.networks {
        let backfill_from = ChainClient::connect(net_cfg)
            .ok()
            .and_then(|c| c.tip().ok())
            .map(|t| t.height.saturating_sub(net_cfg.demo_backfill_blocks))
            .unwrap_or(0);
        for addr_str in &net_cfg.always_watch {
            match parse_address(addr_str, net_cfg.network) {
                Ok(spk) => {
                    store.add_watch(
                        &WatchedScript {
                            network: net_cfg.network,
                            script_pubkey: spk,
                            scan_from_height: backfill_from,
                            is_public_demo: true,
                        },
                        0,
                    )?;
                    store.rewind_checkpoint_to(net_cfg.network, backfill_from)?;
                    tracing::info!(network = ?net_cfg.network, address = %addr_str, "public demo address registered");
                }
                Err(e) => {
                    // Loud, but not fatal: a typo in a demo address must not
                    // stop the bridge doing its actual job.
                    tracing::error!(address = %addr_str, "ignoring unparseable always_watch address: {e}");
                }
            }
        }
    }

    let mut observers = Vec::new();
    for net_cfg in &cfg.networks {
        match Observer::new(net_cfg.clone()) {
            Ok(o) => {
                tracing::info!(network = ?net_cfg.network, "connected to Bitcoin Core");
                observers.push(o);
            }
            Err(e) => {
                // One unreachable node must not take down the others.
                tracing::error!(network = ?net_cfg.network, "cannot reach Bitcoin Core: {e}");
            }
        }
    }
    if observers.is_empty() {
        anyhow::bail!("no Bitcoin Core instance is reachable; nothing to do");
    }

    let address_wasm = std::fs::read(cfg.contract_dir.join("bitcoin_address_contract.wasm"))
        .with_context(|| {
            format!(
                "reading bitcoin_address_contract.wasm from {}",
                cfg.contract_dir.display()
            )
        })?;
    let tip_wasm =
        std::fs::read(cfg.contract_dir.join("bitcoin_tip_contract.wasm")).with_context(|| {
            format!(
                "reading bitcoin_tip_contract.wasm from {}",
                cfg.contract_dir.display()
            )
        })?;

    let publisher = match FreenetPublisher::connect(&cfg.freenet_ws, address_wasm, tip_wasm).await {
        Ok(p) => Some(Arc::new(p)),
        Err(e) => {
            // The bridge still serves status and still observes the chain; it
            // just cannot publish yet. Failing hard here would make a node
            // restart take the bridge down with it.
            tracing::error!("cannot reach the Freenet node ({e}); will retry");
            None
        }
    };
    let address_code_hash = publisher.as_ref().map(|p| p.address_code_hash());

    // If the contract WASM changed since last run, every instance has moved to
    // a new key and the "already published" record refers to contracts nobody
    // reads. Discard it, or the successor contracts come up empty and stay
    // that way -- indistinguishable from an address with no activity.
    if let Some(h) = address_code_hash {
        match store.set_publish_generation(&h) {
            Ok(true) => tracing::warn!(
                code_hash = %hex::encode(h),
                "contract WASM changed since last run; re-publishing all observations \
                 to the new contract keys"
            ),
            Ok(false) => {}
            Err(e) => tracing::error!("could not record publish generation: {e}"),
        }
    }

    // Refill the tip contract's recent-block window on every start.
    //
    // The observation loop publishes a tip entry only for blocks it NEWLY
    // scans, so a tip contract that is empty stays empty until the next block
    // and then holds exactly one. That is invisible on signet, where blocks
    // arrive in seconds, and it is a ten-minute blank screen followed by a
    // one-row table on mainnet -- for the contract whose entire job is to make
    // the first screen useful with no watched addresses.
    //
    // Empty is the normal state after a re-key, because the successor contract
    // is a different instance that nobody has written to. Rather than detect
    // that, this rewinds unconditionally: the window is bounded by
    // `demo_backfill_blocks`, rescanning is idempotent (claims are keyed by
    // digest, and the tip state is a pruned map merged by height), and the
    // signet demo-address seeding above already rewinds on every start for the
    // same reason. A condition here would be one more thing to get wrong for
    // no saving worth having.
    for net_cfg in &cfg.networks {
        let Ok(client) = ChainClient::connect(net_cfg) else {
            continue;
        };
        let Ok(tip) = client.tip() else { continue };
        let from = tip.height.saturating_sub(net_cfg.demo_backfill_blocks);
        match store.rewind_checkpoint_to(net_cfg.network, from) {
            Ok(()) => tracing::info!(
                network = ?net_cfg.network,
                from,
                "rewound the chain cursor so the tip contract's recent-block window refills"
            ),
            Err(e) => tracing::error!(network = ?net_cfg.network, "cannot rewind: {e}"),
        }
    }

    // Compute each network's tip-contract instance id and publish it via
    // /v1/status.
    //
    // A client cannot derive this for itself: BitcoinTipParameters includes
    // `trusted_bridges`, which is per-deployment, not a fixed per-network
    // constant. Without the bridge publishing it, an application would have to
    // hardcode a contract id -- and a hardcoded id goes stale silently on the
    // next re-key, with every read coming back looking like "no data yet".
    let mut tip_contract_ids: HashMap<BitcoinNetwork, String> = HashMap::new();
    if let Some(p) = publisher.as_ref() {
        for net_cfg in &cfg.networks {
            let params = freenet_bitcoin_common::BitcoinTipParameters {
                network: net_cfg.network,
                trusted_bridges: vec![signer.bridge_id()],
            };
            match p.tip_key(&params) {
                Ok(k) => {
                    tracing::info!(
                        network = ?net_cfg.network,
                        contract = %k.id(),
                        "tip contract id published via /v1/status"
                    );
                    tip_contract_ids.insert(net_cfg.network, k.id().to_string());
                }
                Err(e) => tracing::warn!("cannot derive tip contract id: {e}"),
            }
        }
    }

    // Tell readers which contract generation this bridge writes to, BEFORE
    // the observation loop starts filling it.
    //
    // Order matters in one direction only. Published first, a reader lands on
    // the generation the data is about to appear in and sees it arrive.
    // Published last, every reader spends the gap on the previous generation,
    // which the bridge has already stopped writing to -- and a reader cannot
    // tell that from "no payments yet", which is the whole failure being
    // removed here.
    if let Some(p) = publisher.as_ref() {
        for result in bitcoin_freenet_bridge::generation::publish_pointers(p, &signer, &store).await
        {
            if let Err(e) = result {
                // Not fatal: the bridge's real job is unaffected. What is lost
                // is a reader's ability to notice a re-key, so say so plainly
                // rather than at debug level.
                tracing::error!(
                    "could not publish a generation pointer ({e}); readers built against                      different contract WASM will see an empty page with no error"
                );
            }
        }
    }

    let state = Arc::new(ServiceState {
        cfg: cfg.clone(),
        signer: Signer::load_or_create(&cfg.signing_key_path)?,
        observers,
        store: std::sync::Mutex::new(Store::open(&cfg.database_path)?),
        address_code_hash,
        tip_contract_ids,
    });

    let listen = cfg.listen.clone();
    let app = router(state.clone());
    let http = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("cannot bind {listen}: {e}");
                return;
            }
        };
        tracing::info!(%listen, "request service listening");
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("http server stopped: {e}");
        }
    });

    // The observation loop runs on its own OS thread with its own SQLite
    // connection and its own current-thread runtime.
    //
    // rusqlite's Connection is deliberately not Sync, and the alternative --
    // holding a lock across every await in the loop -- would serialize the
    // HTTP handler behind a multi-block catch-up scan. Thread-confining the
    // connection is also how SQLite prefers to be used.
    let observe_cfg = cfg.clone();
    let db_path = cfg.database_path.clone();
    let observe = std::thread::Builder::new()
        .name("observer".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("cannot build observer runtime: {e}");
                    return;
                }
            };
            let store = match Store::open(&db_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("observer cannot open the database: {e}");
                    return;
                }
            };
            rt.block_on(observation_loop(observe_cfg, signer, store, publisher));
        })
        .context("spawning the observer thread")?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
        _ = http => tracing::warn!("http server exited"),
    }
    drop(observe);
    Ok(())
}

/// Follow the chain and publish what we see.
///
/// Deliberately single-threaded per network and restart-safe: everything it
/// needs to resume is in the checkpoint, and republishing is a no-op, so a
/// crash costs a rescan rather than correctness.
async fn observation_loop(
    cfg: BridgeConfig,
    signer: Signer,
    store: Store,
    publisher: Option<Arc<FreenetPublisher>>,
) {
    let mut observers: Vec<Observer> = Vec::new();
    for net_cfg in &cfg.networks {
        if let Ok(o) = Observer::new(net_cfg.clone()) {
            observers.push(o);
        }
    }

    loop {
        for obs in &observers {
            if let Err(e) = observe_once(obs, &signer, &store, publisher.as_deref()).await {
                tracing::error!(network = ?obs.network(), "observation round failed: {e}");
            }
        }
        // A short sleep rather than a tight loop. `wait_for_new_block` inside
        // `observe_once` does the real waiting; this only paces the retry when
        // something failed.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn observe_once(
    obs: &Observer,
    signer: &Signer,
    store: &Store,
    publisher: Option<&FreenetPublisher>,
) -> Result<()> {
    // While the node is still doing initial block download, an absence of
    // payments means nothing, so publishing "scanned to height N" would be an
    // actively misleading claim. Say nothing until the node is caught up.
    if obs.chain.in_initial_block_download()? {
        let tip = obs.chain.tip()?;
        tracing::info!(
            network = ?obs.network(),
            height = tip.height,
            "still in initial block download; not publishing observations yet"
        );
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        return Ok(());
    }

    let tip = obs.chain.tip()?;
    let watched: Vec<Vec<u8>> = store
        .watched(obs.network())?
        .into_iter()
        .map(|w| w.script_pubkey)
        .collect();

    let mut claims: ClaimsByScript = HashMap::new();

    // Reorg first: a reorg invalidates the range we were about to scan.
    //
    // This yields retraction CANDIDATES rather than signed retractions,
    // because the rescan below usually puts the orphaned transactions straight
    // back on the chain in the replacement blocks. Signing a retraction now
    // and a re-confirmation moments later would have the bridge assert both
    // about one outpoint at one identical `as_of`. See
    // `Observer::retraction_claims`.
    let mut reorg = obs.handle_reorg(store)?;
    if reorg.resume_from == 0 {
        // First run: start from the current tip rather than scanning the whole
        // chain. History for a newly-watched script is a separate concern (see
        // `scantxoutset` in the deployment notes) and a full rescan on a pruned
        // node is not possible anyway.
        reorg.resume_from = tip.height;
    }
    let next = reorg.resume_from;

    // A tip entry for EVERY block scanned, not only the last.
    //
    // The tip contract's whole job is to show a recent-block window, and it
    // holds only what it is sent. Publishing the last block of a round means a
    // contract that starts empty -- which is the normal state after a re-key,
    // since the successor is a different instance -- refills one row per round
    // however many blocks were actually scanned. That is a one-row table on
    // the first screen of an app whose point is that the first screen works.
    //
    // Bounded by construction: the state prunes to TIP_RETAIN, the round
    // scans at most 50 blocks, and an entry is about 150 bytes.
    let mut tip_entries = Vec::new();
    // Outpoints this round's rescan confirmed, so a reorged output that was
    // re-mined is not also retracted at the same `as_of`.
    let mut reconfirmed = std::collections::HashSet::new();
    // Bound the work per round so a long catch-up cannot starve the service --
    // but widen the bound when this round is going to retract something, so it
    // reaches the tip it will stamp those retractions with rather than leaving
    // blocks for the next round to contradict them from. See `scan_ceiling`.
    let ceiling = reorg.scan_ceiling(tip.height, obs.cfg.max_reorg_depth);
    for height in next..=ceiling {
        let hash = obs.chain.block_hash_at(height)?;
        let block = obs.chain.scan_block(&hash, &watched)?;
        obs.claims_from_block(store, signer, &block, &tip, &mut claims, &mut reconfirmed)?;
        tip_entries.push(obs.tip_entry(signer, &block)?);
        store.set_checkpoint(obs.network(), &block.anchor)?;
    }

    // Now that the rescan has said what is actually on the chain, retract only
    // what it did not find.
    obs.retraction_claims(signer, &tip, &reorg.orphaned, &reconfirmed, &mut claims)?;

    // Re-publish payments that have now reached the configured depth, this
    // time with headers proving it.
    obs.deep_claims(store, signer, &tip, &mut claims)?;

    // A scan watermark per watched script, so a reader can tell "nothing
    // received" from "nobody has looked".
    //
    // Stamped with how far this round ACTUALLY scanned, never with the chain
    // tip. Those differ whenever the bridge is catching up, and claiming the
    // tip would assert coverage the bridge does not have -- turning the one
    // signal that distinguishes "looked, found nothing" from "has not looked"
    // into a lie in exactly the case where the distinction matters.
    let scanned_anchor = match store.checkpoint(obs.network())? {
        Some(cp) => cp,
        // No checkpoint yet means nothing has been scanned. Fall back to the
        // tip only because there is nothing else to say, and the IBD guard
        // above already prevents publishing during catch-up from a cold start.
        None => tip,
    };
    for script in &watched {
        let wm = obs.scan_watermark(signer, script, &scanned_anchor)?;
        claims.entry(script.clone()).or_default().push(wm);
    }

    store.prune_blocks(obs.network(), tip.height, 1000)?;

    let Some(publisher) = publisher else {
        tracing::debug!("no Freenet connection; observations recorded but not published");
        return Ok(());
    };

    for (script, script_claims) in claims {
        let params = obs.address_params(&script, signer.bridge_id());

        // Recover a predecessor generation BEFORE this instance is first
        // written to in this run. Doing it after the first publish would mean
        // probing state we had just written ourselves, and the recovery would
        // never find anything -- silently, and looking healthy.
        let code_hash = publisher.address_code_hash();
        let instance_key = script.clone();
        let already = store
            .migration_done(&instance_key, &code_hash)
            .unwrap_or(false);
        if !already {
            let local = freenet_bitcoin_common::address_state::BitcoinAddressStateV1::default();
            let (merged, note) = publisher.migrate_address_forward(&params, local).await;
            let definitive = note.starts_with("recovered") || note.starts_with("every predecessor");
            if !merged.claims.claims.is_empty() {
                match publisher.publish_state(&params, &merged).await {
                    Ok(_) => tracing::info!(script = %hex::encode(&script), "{note}"),
                    Err(e) => tracing::error!("forward PUT after migration failed: {e}"),
                }
            } else {
                tracing::debug!(script = %hex::encode(&script), "{note}");
            }
            // Only a definitive answer may be recorded. An indeterminate walk
            // leaves no marker so the next run probes again.
            if definitive {
                let _ = store.set_migration_done(&instance_key, &code_hash, &note);
            }
        }

        // Skip claims we have already published. Re-publishing is harmless --
        // the contract's state is a digest-keyed set -- but it is wasted
        // bandwidth on every round.
        let fresh: Vec<_> = script_claims
            .into_iter()
            .filter(|c| {
                store
                    .mark_published(obs.network(), &script, &c.digest())
                    .unwrap_or(true)
            })
            .collect();
        if fresh.is_empty() {
            continue;
        }
        match publisher.publish_claims(&params, &fresh).await {
            Ok(key) => tracing::info!(
                contract = %key.id(),
                claims = fresh.len(),
                "published Bitcoin observations"
            ),
            Err(e) => tracing::error!("publishing observations failed: {e}"),
        }
    }

    if !tip_entries.is_empty() {
        let params = obs.tip_params(signer.bridge_id());
        match publisher.publish_tip(&params, &tip_entries).await {
            Ok(key) => tracing::debug!(
                contract = %key.id(),
                blocks = tip_entries.len(),
                "published chain tip"
            ),
            Err(e) => tracing::error!("publishing chain tip failed: {e}"),
        }
    }
    Ok(())
}

/// Parse a human-readable Bitcoin address into canonical `scriptPubKey` bytes.
///
/// The script, not the address string, is the identity used everywhere else:
/// several address encodings can denote the same script, and only the script
/// appears on chain.
fn parse_address(s: &str, network: BitcoinNetwork) -> Result<Vec<u8>> {
    let btc_net = match network {
        BitcoinNetwork::Bitcoin => bitcoin::Network::Bitcoin,
        BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet4,
        BitcoinNetwork::Signet => bitcoin::Network::Signet,
        BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
    };
    let addr = s
        .trim()
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .with_context(|| format!("{s} is not a Bitcoin address"))?
        .require_network(btc_net)
        .with_context(|| format!("{s} is not valid on {}", network.as_str()))?;
    Ok(addr.script_pubkey().as_bytes().to_vec())
}

/// Read an address contract back out of Freenet and report what its claims
/// check out to.
///
/// Deliberately re-verifies every claim from scratch rather than trusting the
/// bridge's own record, so the output describes what a third party reading the
/// contract would conclude -- given the same trust in this bridge's chain
/// state, which the check does not remove.
/// Print the contract generation this bridge publishes to, and what its
/// pointers currently say.
///
/// The operator-facing half of the same mechanism the webapp uses at runtime.
/// After installing new contract WASM, this is the one command that answers
/// "will readers find it" without opening a browser.
async fn print_generation(cfg: BridgeConfig) -> Result<()> {
    use freenet_bitcoin_generation::{code_hash_b58, Artifact};

    let signer = Signer::load_or_create(&cfg.signing_key_path)?;
    let bridge = signer.bridge_id();
    println!("bridge   : {}", bridge.to_bs58());

    let address_wasm = std::fs::read(cfg.contract_dir.join("bitcoin_address_contract.wasm"))?;
    let tip_wasm = std::fs::read(cfg.contract_dir.join("bitcoin_tip_contract.wasm"))?;
    println!(
        "installed: {}  bitcoin_address_contract.wasm",
        code_hash_b58(&freenet_bitcoin_generation::code_hash(&address_wasm))
    );
    println!(
        "installed: {}  bitcoin_tip_contract.wasm",
        code_hash_b58(&freenet_bitcoin_generation::code_hash(&tip_wasm))
    );

    for artifact in Artifact::ALL {
        match freenet_bitcoin_generation::pointer_id(&bridge, artifact) {
            Ok(id) => println!("pointer  : {id}  ({})", artifact.label()),
            Err(e) => println!("pointer  : UNDERIVABLE ({}): {e}", artifact.label()),
        }
    }

    let publisher = FreenetPublisher::connect(&cfg.freenet_ws, address_wasm, tip_wasm).await?;
    let store = Store::open(&cfg.database_path)?;
    let mut disagreed = false;
    for result in
        bitcoin_freenet_bridge::generation::publish_pointers(&publisher, &signer, &store).await
    {
        match result {
            Ok(state) => println!(
                "published: {} v{}  ({}){}",
                code_hash_b58(&state.code_hash),
                state.version,
                state.artifact.label(),
                if state.advanced { "  ADVANCED" } else { "" }
            ),
            Err(e) => {
                disagreed = true;
                println!("published: FAILED: {e}");
            }
        }
    }
    if disagreed {
        anyhow::bail!("at least one generation pointer could not be published");
    }
    Ok(())
}

async fn verify_address(
    cfg: BridgeConfig,
    network: BitcoinNetwork,
    address: &str,
    prove_payment_of: Option<u64>,
    required_confirmations: u32,
) -> Result<()> {
    use freenet_bitcoin_common::address_state::BitcoinAddressStateV1;
    use freenet_bitcoin_common::tip_state::BitcoinTipStateV1;
    use freenet_bitcoin_common::{
        from_cbor, BitcoinAddressParameters, BitcoinTipParameters, OutpointStatus,
    };

    let signer = Signer::load_or_create(&cfg.signing_key_path)?;
    let script = parse_address(address, network)?;

    let address_wasm = std::fs::read(cfg.contract_dir.join("bitcoin_address_contract.wasm"))?;
    let tip_wasm = std::fs::read(cfg.contract_dir.join("bitcoin_tip_contract.wasm"))?;
    let publisher = FreenetPublisher::connect(&cfg.freenet_ws, address_wasm, tip_wasm).await?;

    let params = BitcoinAddressParameters {
        network,
        script_pubkey: script.clone(),
        trusted_bridges: vec![signer.bridge_id()],
        pow_floor: network.default_pow_floor(),
    };
    let key = publisher.address_key(&params)?;
    println!("address  : {address}");
    println!("network  : {}", network.as_str());
    println!("script   : {}", hex::encode(&script));
    println!("contract : {}", key.id());

    let bytes = publisher.get_state(key).await?;
    println!("state    : {} bytes retrieved from Freenet", bytes.len());

    let state: BitcoinAddressStateV1 =
        from_cbor(&bytes).map_err(|e| anyhow::anyhow!("decoding contract state: {e}"))?;

    for claim in state.claims.claims.values() {
        claim
            .verify(&params)
            .map_err(|e| anyhow::anyhow!("a claim in the retrieved state does not verify: {e}"))?;
    }

    match state.scanned_to() {
        Some(h) => println!("scanned  : up to height {h}"),
        None => println!("scanned  : NOT YET -- no bridge has reported on this script"),
    }

    let tip_params = BitcoinTipParameters {
        network,
        trusted_bridges: vec![signer.bridge_id()],
    };
    let tip_height = match publisher.tip_key(&tip_params) {
        Ok(tk) => match publisher.get_state(tk).await {
            Ok(b) => from_cbor::<BitcoinTipStateV1>(&b)
                .ok()
                .and_then(|t| t.tip_height()),
            Err(_) => None,
        },
        Err(_) => None,
    };
    if let Some(h) = tip_height {
        println!("tip      : height {h} (from the public tip contract)");
    }

    let statuses = state.claims.outpoint_statuses();
    if statuses.is_empty() {
        println!("payments : none observed");
    } else {
        println!("payments :");
        for (op, status) in &statuses {
            let line = match status {
                OutpointStatus::Confirmed {
                    value_sats, anchor, ..
                } => {
                    // The depth a verifier would accept, not the raw tip
                    // difference -- see `OutpointStatus::confirmations_at`.
                    let confs = tip_height.map(|t| status.confirmations_at(t)).unwrap_or(0);
                    format!(
                        "{value_sats} sats  confirmed in block {} ({confs} conf)",
                        anchor.height
                    )
                }
                OutpointStatus::Unconfirmed { value_sats } => {
                    format!("{value_sats} sats  in mempool")
                }
                OutpointStatus::Retracted => "reorganized off the chain".to_string(),
            };
            println!(
                "           {}:{}  {line}",
                op.txid.to_display_string(),
                op.vout
            );
        }
        if let Some(t) = tip_height {
            println!(
                "confirmed: {} sats at >=1 confirmation",
                state.claims.confirmed_value_sats(t, 1)
            );
        }
    }

    println!();
    println!("Every claim above was re-verified against its own Bitcoin evidence");
    println!("(raw transaction, Merkle branch, and block-header proof-of-work),");
    println!("not merely against the bridge's signature.");

    // The join: would this data settle an invoice? `payment_evidence` is the
    // same function an application contract calls, so this is not a
    // reimplementation of the decision -- it IS the decision.
    if let Some(want_sats) = prove_payment_of {
        let Some(tip_h) = tip_height else {
            println!("\ncannot judge payment: no chain tip available");
            return Ok(());
        };
        println!();
        println!(
            "--- would this settle an invoice for {want_sats} sats at {required_confirmations} conf? ---"
        );
        match state
            .claims
            .payment_evidence(want_sats, tip_h, required_confirmations)
        {
            Some(proof) => {
                // Re-verify the returned evidence from scratch, the way a
                // consuming contract would, rather than trusting the fold that
                // produced it.
                for c in &proof {
                    c.verify(&params).map_err(|e| {
                        anyhow::anyhow!("evidence returned by the fold does not verify: {e}")
                    })?;
                }
                println!("YES -- settled.");
                println!(
                    "{} signed claim(s) constitute the proof; an order carrying them",
                    proof.len()
                );
                println!("would transition AwaitingPayment -> Paid, and any peer could check it.");
                let confirmed = state
                    .claims
                    .confirmed_value_sats(tip_h, required_confirmations);
                println!("confirmed value at that depth: {confirmed} sats");
            }
            None => {
                let confirmed = state
                    .claims
                    .confirmed_value_sats(tip_h, required_confirmations);
                println!("NO -- not settled.");
                println!(
                    "only {confirmed} sats are confirmed to {required_confirmations} confirmations; {want_sats} required."
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// `observe_once` must take its ceiling from the reorg outcome.
    ///
    /// The behaviour lives in `ReorgOutcome::scan_ceiling`, which is tested
    /// directly -- but `observe_once` needs a live bitcoind, so nothing
    /// executes its call to it. Deleting that call, or going back to computing
    /// a ceiling inline, left all 142 tests green. This is a source pin
    /// precisely because the wiring is the part that cannot be run here; it is
    /// weaker than a behavioural test and is not a substitute for one.
    #[test]
    fn observe_once_takes_its_ceiling_from_the_reorg_outcome() {
        let src = include_str!("main.rs");
        // The needles are assembled from fragments on purpose. `include_str!`
        // pulls in THIS test too, so a needle written as one literal matches
        // its own source and the pin passes whatever the call site says --
        // which is how the first version of this test was itself inert.
        let calls_it = concat!("reorg.scan", "_ceiling(tip.height");
        let inline_ceiling = concat!("tip.height", ".min(next");
        assert!(
            src.contains(calls_it),
            "observe_once no longer asks the ReorgOutcome for its ceiling, so a \
             round that retracts may not scan as far as the tip it stamps those \
             retractions with"
        );
        assert!(
            !src.contains(inline_ceiling),
            "the ceiling is being computed inline again, bypassing the widening \
             that a retracting round depends on"
        );
    }

    use super::*;

    #[test]
    fn addresses_parse_to_canonical_script_bytes() {
        // A well-known mainnet P2PKH address (Bitcoin's genesis coinbase).
        let spk = parse_address(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(spk.len(), 25);
        assert_eq!(spk[0], 0x76);
        assert_eq!(spk[1], 0xa9);
        assert_eq!(spk[24], 0xac);
    }

    #[test]
    fn an_address_from_the_wrong_network_is_rejected() {
        // Accepting one would make the bridge watch a script that can never be
        // paid on the network it is actually following.
        assert!(
            parse_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", BitcoinNetwork::Signet).is_err()
        );
    }

    #[test]
    fn a_bech32_address_parses_to_a_witness_program() {
        let spk = parse_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            BitcoinNetwork::Bitcoin,
        )
        .unwrap();
        assert_eq!(spk[0], 0x00, "v0 witness program");
        assert_eq!(spk[1], 0x14, "20-byte push");
        assert_eq!(spk.len(), 22);
    }

    #[test]
    fn garbage_is_rejected_rather_than_silently_watched() {
        assert!(parse_address("not-an-address", BitcoinNetwork::Bitcoin).is_err());
        assert!(parse_address("", BitcoinNetwork::Bitcoin).is_err());
    }
}
