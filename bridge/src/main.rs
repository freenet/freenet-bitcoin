//! `bitcoin-freenet-bridge` — synchronizes Bitcoin observations into Freenet.
//!
//! Two concurrent jobs:
//!
//! * an **observation loop** per network, following the chain and publishing
//!   signed observations into per-script Freenet contracts, and
//! * an **inbox worker**, reading the bridge's request inbox contract, where
//!   Ghost Key holders ask it to synchronize a script (see `inbox`).
//!
//! Both reach the world only through Freenet contracts. The observations are
//! public and generic, and carry the evidence a reader needs to check what they
//! say about a transaction. The requests are sealed to this bridge: the network
//! learns which Ghost Key asked and when, never which script.
//!
//! An observation is not self-validating, though. A reader who checks the
//! evidence learns that a real transaction paid that script that amount; which
//! blocks are on Bitcoin is this bridge's assertion, and readers trust it for
//! that. See `freenet_bitcoin_common::spv`.

use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoin::Address;
use clap::Parser;
use freenet_bitcoin_common::BitcoinNetwork;

use bitcoin_freenet_bridge::{
    chain::ChainClient,
    config::BridgeConfig,
    freenet::{ContractWasm, FreenetPublisher},
    inbox::InboxWorker,
    observer::{scan_set, Observer, RoundClaims},
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
    // anything else starts; the observer and the inbox worker each open their
    // own.
    let store = Store::open(&cfg.database_path)?;

    // Seed the operator's public demo scripts. These are explicitly public
    // data -- a curated address whose activity anybody may see -- and are NOT
    // anybody's private watch. Marked so a user cannot unwatch them.
    //
    // They are seeded with a backfill window rather than from height 0: a
    // pruned node has not kept the early chain, so asking for it would fail,
    // and a demo only needs recent activity to be convincing.
    for net_cfg in &cfg.networks {
        if net_cfg.always_watch.is_empty() {
            continue;
        }
        // A tip that cannot be read seeds nothing. `add_watch` keeps the
        // lowest `scan_from_height` ever asked for, so seeding at 0 once, from
        // a node still loading its block index, would ask for the whole chain
        // ever after; and the rewind that follows would go as far back as the
        // blocks kept allow. The next start seeds it.
        let Some(tip) = ChainClient::connect(net_cfg)
            .ok()
            .and_then(|c| c.tip().ok())
        else {
            tracing::warn!(network = ?net_cfg.network, "cannot read the tip, so this network's demo addresses are not seeded this time");
            continue;
        };
        let backfill_from = tip.height.saturating_sub(net_cfg.demo_backfill_blocks);
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

    let wasm = ContractWasm::load(&cfg.contract_dir)?;

    // Not dialled here. `FreenetPublisher` connects on demand and reconnects
    // under a backoff, so a node that is slow or not yet up at startup costs a
    // few failed rounds rather than a process that publishes nothing until
    // somebody restarts it.
    let publisher = Arc::new(FreenetPublisher::new(&cfg.freenet_ws, &wasm));
    let address_code_hash = publisher.address_code_hash();

    // If the contract WASM changed since last run, every instance has moved to
    // a new key and the "already published" record refers to contracts nobody
    // reads. Discard it, or the successor contracts come up empty and stay
    // that way -- indistinguishable from an address with no activity.
    {
        let h = &address_code_hash;
        match store.set_publish_generation(h) {
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

    // Log each network's tip-contract instance id, so an operator can check
    // what readers will look for. Readers derive it themselves: the tip
    // generation pointer names the code hash, and `BitcoinTipParameters` is
    // the network plus the bridges they already trust.
    {
        let p = publisher.as_ref();
        for net_cfg in &cfg.networks {
            let params = freenet_bitcoin_common::BitcoinTipParameters {
                network: net_cfg.network,
                trusted_bridges: vec![signer.bridge_id()],
            };
            match p.tip_key(&params) {
                Ok(k) => {
                    tracing::info!(network = ?net_cfg.network, contract = %k.id(), "tip contract")
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
    let pointers_ok = publish_pointers_logged(publisher.as_ref(), &signer, &store).await;

    // The inbox worker gets its own OS thread, runtime, SQLite connection and
    // Freenet connection, for the same reasons as the observer below.
    let inbox = InboxWorker::new(&cfg, signer.key().clone(), wasm.inbox.clone());
    std::thread::Builder::new()
        .name("inbox".into())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(inbox.run()),
                Err(e) => tracing::error!("cannot build the inbox runtime: {e}"),
            }
        })
        .context("spawning the inbox thread")?;

    // The observation loop runs on its own OS thread with its own SQLite
    // connection and its own current-thread runtime.
    //
    // rusqlite's Connection is deliberately not Sync, and the alternative --
    // holding a lock across every await in the loop -- would serialize the
    // inbox worker behind a multi-block catch-up scan. Thread-confining the
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
            rt.block_on(observation_loop(
                observe_cfg,
                signer,
                store,
                publisher,
                pointers_ok,
            ));
        })
        .context("spawning the observer thread")?;

    tokio::signal::ctrl_c()
        .await
        .context("waiting for a shutdown signal")?;
    tracing::info!("shutting down");
    drop(observe);
    Ok(())
}

/// How often generation pointers are re-asserted once they published cleanly.
const POINTER_REASSERT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How soon to try again after a pointer failed to publish.
const POINTER_RETRY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// How long until pointers are published again, given whether the last
/// attempt published all of them.
fn pointer_wait(all_published: bool) -> std::time::Duration {
    if all_published {
        POINTER_REASSERT
    } else {
        POINTER_RETRY
    }
}

#[cfg(test)]
mod pointer_tests {
    use super::*;

    #[test]
    fn a_failed_pointer_is_retried_sooner_than_a_healthy_one_is_reasserted() {
        assert_eq!(pointer_wait(false), std::time::Duration::from_secs(5 * 60));
        assert_eq!(pointer_wait(true), std::time::Duration::from_secs(30 * 60));
    }
}

/// Publish every generation pointer, logging each failure. True when all
/// published.
///
/// A failure is not fatal: the bridge's real job is unaffected. What is lost is
/// a reader's ability to notice a re-key, or to find the inbox at all, so it is
/// said plainly rather than at debug level.
async fn publish_pointers_logged(
    publisher: &FreenetPublisher,
    signer: &Signer,
    store: &Store,
) -> bool {
    let mut ok = true;
    for result in
        bitcoin_freenet_bridge::generation::publish_pointers(publisher, signer, store).await
    {
        if let Err(e) = result {
            ok = false;
            tracing::error!(
                "could not publish a generation pointer ({e}); readers built against different \
                 contract WASM will see an empty page with no error, and senders cannot find the \
                 request inbox"
            );
        }
    }
    ok
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
    publisher: Arc<FreenetPublisher>,
    pointers_ok: bool,
) {
    let mut observers: Vec<Observer> = Vec::new();
    for net_cfg in &cfg.networks {
        if let Ok(o) = Observer::new(net_cfg.clone()) {
            observers.push(o);
        }
    }

    // Generation pointers are re-asserted for the life of the process, not
    // only at startup. A pointer that failed to publish would otherwise stay
    // missing until a restart, and a reader resolving through it finds no
    // inbox, or reads an old generation of the other contracts. Republishing
    // an unchanged record is harmless.
    let mut pointers_due = std::time::Instant::now() + pointer_wait(pointers_ok);
    let mut walks = bitcoin_freenet_bridge::migrate::WalkClock::default();
    // Per network, how many rounds in a row its checkpoint has been held back.
    let mut held_rounds: std::collections::HashMap<BitcoinNetwork, u32> =
        std::collections::HashMap::new();

    loop {
        for obs in &observers {
            if let Err(e) = observe_once(
                obs,
                &signer,
                &store,
                publisher.as_ref(),
                &mut walks,
                &mut held_rounds,
            )
            .await
            {
                tracing::error!(network = ?obs.network(), "observation round failed: {e}");
            }
        }
        if std::time::Instant::now() >= pointers_due {
            let ok = publish_pointers_logged(publisher.as_ref(), &signer, &store).await;
            pointers_due = std::time::Instant::now() + pointer_wait(ok);
        }
        // A short sleep rather than a tight loop. Once the observer has caught
        // up, a round returns almost at once, so this is the polling interval:
        // each network's tip is checked about every 2 seconds.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn observe_once(
    obs: &Observer,
    signer: &Signer,
    store: &Store,
    publisher: &FreenetPublisher,
    walks: &mut bitcoin_freenet_bridge::migrate::WalkClock,
    held_rounds: &mut std::collections::HashMap<BitcoinNetwork, u32>,
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

    // Payments in doubt are read before `handle_reorg` changes anything, so
    // failing to read them cannot strand this round's retractions (see #11);
    // this round's own orphans are added once it has found them.
    let mut in_doubt = store.scripts_with_unconfirmed_outputs(obs.network())?;

    let mut round = RoundClaims::default();

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
    // Blocks are scanned for the scripts of payments in doubt too, watched or
    // not, including this round's orphans; the watermarks below stay with
    // `watched`. See `scan_set`.
    in_doubt.extend(reorg.orphaned.iter().map(|(script, _)| script.clone()));
    let scan = scan_set(&watched, &in_doubt);

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
    // Bound the work per round so a long catch-up cannot hold up the other
    // networks, which this loop scans one after another --
    // but widen the bound when this round is going to retract something, so it
    // reaches the tip it will stamp those retractions with rather than leaving
    // blocks for the next round to contradict them from. See `scan_ceiling`.
    let ceiling = reorg.scan_ceiling(tip.height, obs.cfg.max_reorg_depth);
    // The checkpoint is held back while this round has something to publish.
    //
    // It used to advance inside this loop, before anything was published, and
    // `resume_from` is the checkpoint plus one -- so a block whose claims
    // failed to publish was never scanned again and its payment was never
    // attested by anyone. That is this bridge's own incident: a payment
    // confirmed while the observer could not reach the node. While the round
    // has produced no claims there is nothing a later failure could lose, so
    // the checkpoint advances as before and a long catch-up over empty blocks
    // still makes progress.
    let mut deferred_checkpoint: Option<freenet_bitcoin_common::BlockAnchor> = None;
    for height in next..=ceiling {
        let hash = obs.chain.block_hash_at(height)?;
        let block = obs.chain.scan_block(&hash, &scan)?;
        obs.claims_from_block(store, signer, &block, &tip, &watched, &mut round)?;
        tip_entries.push(obs.tip_entry(signer, &block)?);
        if round.is_empty() {
            store.set_checkpoint(obs.network(), &block.anchor)?;
            deferred_checkpoint = None;
        } else {
            deferred_checkpoint = Some(block.anchor);
        }
    }

    // Now that the rescan has said what is actually on the chain, retract only
    // what it did not find.
    obs.retraction_claims(signer, &tip, &reorg.orphaned, &mut round)?;

    // Re-publish payments that have now reached the configured depth, this
    // time with headers proving it.
    obs.deep_claims(store, signer, &tip, &mut round)?;

    // A scan watermark per watched script, so a reader can tell "nothing
    // received" from "nobody has looked".
    //
    // Stamped with how far this round ACTUALLY scanned, never with the chain
    // tip. Those differ whenever the bridge is catching up, and claiming the
    // tip would assert coverage the bridge does not have -- turning the one
    // signal that distinguishes "looked, found nothing" from "has not looked"
    // into a lie in exactly the case where the distinction matters.
    // Taken from the block this round scanned to, not from the checkpoint:
    // when the round has claims the checkpoint is not committed until they are
    // published, so reading it here would stamp the watermark one round behind
    // what was actually scanned, which is the understatement this comment
    // exists to rule out.
    let scanned_anchor = match deferred_checkpoint {
        Some(anchor) => anchor,
        None => match store.checkpoint(obs.network())? {
            Some(cp) => cp,
            // No checkpoint yet means nothing has been scanned. Fall back to
            // the tip only because there is nothing else to say, and the IBD
            // guard above already prevents publishing during catch-up from a
            // cold start.
            None => tip,
        },
    };
    for script in &watched {
        let wm = obs.scan_watermark(signer, script, &scanned_anchor)?;
        round.record(script, &freenet_bitcoin_common::Claim::ScannedTo, wm);
    }

    store.prune_blocks(obs.network(), Store::BLOCKS_KEPT)?;

    // Set when the node could not be reached, so the scanned window is kept
    // for the next round rather than skipped over.
    let mut node_unreachable = false;
    for (script, script_claims) in round.into_by_script() {
        let params = obs.address_params(&script, signer.bridge_id());

        // The walk reads predecessor keys only, never this instance's own, so
        // it does not matter that claims may already have been published to it
        // this run. `WalkClock` relies on that: it holds the first walk back
        // for ten minutes while publishing carries on.
        let code_hash = publisher.address_code_hash();
        // Keyed by the contract instance, which derives from the address
        // parameters and so is already per network: the same p2wpkh script is
        // the same bytes on signet and mainnet, and a seal recorded against
        // the bare script stopped the other network's migration ever running.
        let instance_key = match publisher.address_key(&params) {
            Ok(key) => key.id().as_bytes().to_vec(),
            Err(e) => {
                tracing::error!("cannot derive the address contract's key: {e}");
                continue;
            }
        };
        let already = store
            .migration_done(&instance_key, &code_hash)
            .unwrap_or(false);
        if !already && walks.due(&instance_key, std::time::Instant::now()) {
            use bitcoin_freenet_bridge::migrate::{agreement, count_walk};
            let local = freenet_bitcoin_common::address_state::BitcoinAddressStateV1::default();
            let (merged, note, found) = publisher.migrate_address_forward(&params, local).await;
            // Published whenever the walk recovered anything, complete or
            // not: a fold that reached some predecessors and not others holds
            // real claims, and dropping them because the walk was incomplete
            // would lose exactly what the migration exists to carry. Skipped
            // only when it is byte-for-byte what was last published for this
            // address, since a predecessor holds its state indefinitely and
            // the same merge would otherwise be re-sent on every walk. The
            // trade: re-sending it also re-asserted a state the network had
            // accepted and then dropped, and that repair is now only made
            // after a restart, which clears the memo.
            let published = if !found.has_state() {
                tracing::debug!(script = %hex::encode(&script), "{note}");
                false
            } else if state_digest(&merged)
                .is_some_and(|digest| !walks.publish_is_new(&instance_key, digest))
            {
                tracing::debug!(script = %hex::encode(&script), "{note} (already published)");
                true
            } else {
                match publisher.publish_state(&params, &merged).await {
                    Ok(_) => {
                        if let Some(digest) = state_digest(&merged) {
                            walks.published_forward(&instance_key, digest);
                        }
                        tracing::info!(script = %hex::encode(&script), "{note}");
                        true
                    }
                    Err(e) => {
                        tracing::error!("forward PUT after migration failed: {e:#}");
                        false
                    }
                }
            };
            let counted = agreement(found, published);
            walks.walked(&instance_key, counted, std::time::Instant::now());
            match now_ms() {
                Some(now) => {
                    let before = store
                        .migration_agreement(&instance_key, &code_hash)
                        .unwrap_or_default();
                    let (after, seal) = count_walk(before, counted, now);
                    if after != before {
                        if let Err(e) =
                            store.set_migration_agreement(&instance_key, &code_hash, after)
                        {
                            tracing::warn!("recording a migration walk failed: {e}");
                        }
                    }
                    if seal {
                        match store.set_migration_done(&instance_key, &code_hash, &note) {
                            Ok(()) => walks.forget(&instance_key),
                            // Left unsealed rather than treated as sealed,
                            // which costs GETs and not evidence: the count is
                            // persisted, so the next spaced walk seals again.
                            Err(e) => {
                                tracing::warn!("recording a finished migration failed: {e}")
                            }
                        }
                    }
                }
                // Nothing is counted against a clock this broken, rather than
                // counting everything against the epoch.
                None => tracing::warn!(
                    "the system clock reads before 1970, so migration walks cannot be dated"
                ),
            }
        }

        // Skip claims we have already published. Re-publishing is harmless --
        // the contract's state is a digest-keyed set -- but it is wasted
        // bandwidth on every round.
        let fresh: Vec<_> = script_claims
            .into_iter()
            .filter(|c| {
                !store
                    .is_published(obs.network(), &script, &c.digest())
                    .unwrap_or(false)
            })
            .collect();
        if fresh.is_empty() {
            continue;
        }
        let published = publisher.publish_claims(&params, &fresh).await;
        mark_claims_if_published(store, obs.network(), &script, &fresh, &published);
        match published {
            Ok(key) => tracing::info!(
                contract = %key.id(),
                claims = fresh.len(),
                "published Bitcoin observations"
            ),
            Err(e) if bitcoin_freenet_bridge::freenet::link_unusable(&e) => {
                node_unreachable = true;
                // The remaining scripts are abandoned, because the next one
                // fails the same way: with the node unreachable each would
                // otherwise pay its own connect and request timeouts, per
                // script, on every round. Claims stay unmarked so they are
                // retried. The tip publish below still gets its one attempt: a
                // signed tip is what lets a buyer prove how deep a payment is,
                // and against an armed backoff it fails fast.
                tracing::error!("the node could not be reached, abandoning the round: {e:#}");
                break;
            }
            Err(e) => {
                // Anything else says something about THIS script's claims --
                // a claim this bridge will not publish, or one the contract
                // refused -- and nothing about the next script's, so the round
                // carries on.
                tracing::error!(script = %hex::encode(&script), "publishing observations failed, will retry: {e:#}");
            }
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
            Err(e) => {
                node_unreachable |= bitcoin_freenet_bridge::freenet::link_unusable(&e);
                tracing::error!("publishing chain tip failed: {e:#}");
            }
        }
    }

    match deferred_checkpoint {
        // Kept, so the next round scans these blocks again and re-signs the
        // `claims_from_block` claims that did not get out. Re-publishing what
        // did is harmless: the state is a digest-keyed set and `is_published`
        // skips it. Retractions and deep rungs are NOT covered, because the
        // state they are derived from is consumed before this point (#24).
        Some(anchor) if node_unreachable => {
            let held = held_rounds.entry(obs.network()).or_insert(0);
            *held += 1;
            if *held <= bitcoin_freenet_bridge::migrate::MAX_HELD_ROUNDS {
                tracing::warn!(
                    network = ?obs.network(),
                    held_rounds = *held,
                    through = anchor.height,
                    "the node could not be reached, so the blocks just scanned are kept"
                );
            } else {
                // Given up on, so one address whose publish always fails
                // cannot freeze the observer here for the life of the
                // process. See `MAX_HELD_ROUNDS`.
                tracing::error!(
                    network = ?obs.network(),
                    held_rounds = *held,
                    from = next,
                    through = anchor.height,
                    "the node has been unreachable for every one of the last {} rounds; \
                     moving past these blocks, so a first-sight claim in them is published \
                     only when the deep-confirmation ladder re-asserts it, at depth 2",
                    bitcoin_freenet_bridge::migrate::MAX_HELD_ROUNDS
                );
                store.set_checkpoint(obs.network(), &anchor)?;
                *held = 0;
            }
        }
        Some(anchor) => {
            store.set_checkpoint(obs.network(), &anchor)?;
            held_rounds.remove(&obs.network());
        }
        None => {
            held_rounds.remove(&obs.network());
        }
    }
    Ok(())
}

/// Record `fresh` as published, but only if it was.
///
/// Split out from the publish so the ordering can be tested without a node:
/// marked before the publish, a claim whose publish failed was never sent
/// again, so a confirmed payment that no retry and no restart would publish
/// was lost for good.
fn mark_claims_if_published(
    store: &Store,
    network: BitcoinNetwork,
    script: &[u8],
    fresh: &[freenet_bitcoin_common::SignedClaim],
    published: &Result<freenet_stdlib::prelude::ContractKey>,
) {
    if published.is_err() {
        return;
    }
    for claim in fresh {
        if let Err(e) = store.mark_published(network, script, &claim.digest()) {
            tracing::warn!("recording a published claim failed: {e}");
        }
    }
}

/// Wall-clock milliseconds, for evidence that has to outlive the process.
///
/// `None` for a clock reading before 1970, rather than 0: dating every walk to
/// the epoch would make them all look spaced apart, and `Store::open` already
/// refuses such a clock rather than silently granting nothing.
fn now_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// A digest of a state, to tell an unchanged forward PUT from a new one.
///
/// `None` for a state that will not encode, rather than a digest of nothing:
/// every unencodable state would otherwise share one digest and be taken for
/// the same state.
fn state_digest(
    state: &freenet_bitcoin_common::address_state::BitcoinAddressStateV1,
) -> Option<[u8; 32]> {
    let bytes = freenet_bitcoin_common::to_cbor(state).ok()?;
    Some(*blake3::hash(&bytes).as_bytes())
}

/// Parse a human-readable Bitcoin address into canonical `scriptPubKey` bytes.
///
/// The script, not the address string, is the identity used everywhere else:
/// several address encodings can denote the same script, and only the script
/// appears on chain.
fn parse_address(s: &str, network: BitcoinNetwork) -> Result<Vec<u8>> {
    // The same mapping the chain check uses, so an address and the node it is
    // watched on can never be read as two different networks.
    let btc_net = bitcoin_freenet_bridge::chain::bitcoin_network(network);
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

    let wasm = ContractWasm::load(&cfg.contract_dir)?;
    for (bytes, file) in [
        (&wasm.address, "bitcoin_address_contract.wasm"),
        (&wasm.tip, "bitcoin_tip_contract.wasm"),
        (&wasm.inbox, "bitcoin_inbox_contract.wasm"),
    ] {
        println!(
            "installed: {}  {file}",
            code_hash_b58(&freenet_bitcoin_generation::code_hash(bytes))
        );
    }

    for artifact in Artifact::ALL {
        match freenet_bitcoin_generation::pointer_id(&bridge, artifact) {
            Ok(id) => println!("pointer  : {id}  ({})", artifact.label()),
            Err(e) => println!("pointer  : UNDERIVABLE ({}): {e}", artifact.label()),
        }
    }

    let publisher = FreenetPublisher::new(&cfg.freenet_ws, &wasm);
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

    let wasm = ContractWasm::load(&cfg.contract_dir)?;
    let publisher = FreenetPublisher::new(&cfg.freenet_ws, &wasm);

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
mod migration_wiring_pins {
    /// **The migration step's wiring, which no test here can execute.**
    ///
    /// `observe_once` needs a live bitcoind, so the decisions it strings
    /// together are only reachable from source. Every piece is unit-tested on
    /// its own (`Found::has_state`, `agreement`, `count_walk`, `WalkClock`),
    /// and round 2 of review still found a bug in the WIRING: the publish was
    /// gated on the agreement verdict rather than on what the walk found, so a
    /// partial recovery was dropped while every unit test stayed green.
    ///
    /// Needles are split with `concat!` because `include_str!("main.rs")`
    /// pulls in this test too, so a needle written as one literal is satisfied
    /// by its own source text. `observe_once_takes_its_ceiling_from_the_reorg_outcome`
    /// gives the full account of that trap.
    #[test]
    fn the_seal_is_decided_by_spaced_agreement_and_the_publish_by_what_was_found() {
        let src = include_str!("main.rs");
        for (needle, why) in [
            (
                concat!("if !already && walks.due(", "&instance_key"),
                "an unsealed address is no longer walked on the walk clock, so \
                 every round re-sends its predecessor GETs",
            ),
            (
                concat!("let published = if !found.", "has_state() {"),
                "the forward PUT is no longer gated on what the walk FOUND, so \
                 a partial recovery is dropped instead of published",
            ),
            (
                concat!("let counted = agree", "ment(found, published);"),
                "the agreement verdict no longer accounts for whether the \
                 forward PUT succeeded",
            ),
            (
                concat!("let (after, seal) = count_", "walk(before, counted, now);"),
                "the seal is no longer decided by count_walk, so one walk can \
                 record a migration as finished",
            ),
            (
                concat!("migrate::MAX_HELD", "_ROUNDS {"),
                "the checkpoint hold is no longer bounded, so one address whose \
                 publish always fails freezes the whole network's observer",
            ),
            (
                concat!("if round.is_", "empty() {"),
                "the checkpoint no longer waits on a round with claims to \
                 publish, so a payment whose publish failed is never rescanned",
            ),
            (
                concat!(
                    "store.set_migration_done(",
                    "&instance_key, &code_hash, &note)"
                ),
                "the seal is no longer recorded against the contract instance \
                 id, which is what keeps signet's seal off mainnet",
            ),
        ] {
            assert!(src.contains(needle), "{why}");
        }
    }
}

#[cfg(test)]
mod publish_marking_tests {
    use super::*;
    use freenet_bitcoin_common::spv::testing as spv_testing;
    use freenet_bitcoin_common::{
        BitcoinAddressParameters, BlockAnchor, Claim, ClaimBody, OutPoint, SignedClaim,
    };

    fn claim(signer: &Signer, params: &BitcoinAddressParameters, seed: u8) -> SignedClaim {
        let (spv, txid, block) =
            spv_testing::payment_proof(&params.script_pubkey, 1_000, 1, [seed; 32]);
        SignedClaim::sign(
            signer.key(),
            &ClaimBody {
                script_id: params.script_id(),
                network: params.network,
                as_of: BlockAnchor {
                    height: 100,
                    hash: block,
                },
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: 1_000,
                    anchor: BlockAnchor {
                        height: 99,
                        hash: block,
                    },
                    spv,
                },
            },
        )
        .unwrap()
    }

    /// **A claim whose publish failed is not recorded as published.**
    ///
    /// It used to be: the mark ran while the claims were being selected, so a
    /// publish that failed left a confirmed payment recorded as sent and it
    /// was never sent again, across restarts. That is the loss this PR exists
    /// to close, and `observe_once` needs a live bitcoind, so the ordering is
    /// tested here rather than through it.
    #[test]
    fn a_claim_is_recorded_as_published_only_when_the_publish_succeeded() {
        let dir = tempfile::tempdir().unwrap();
        let signer = Signer::load_or_create(&dir.path().join("key.pem")).unwrap();
        let store = Store::open_in_memory().unwrap();
        let net = BitcoinNetwork::Signet;
        let params = BitcoinAddressParameters {
            network: net,
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            trusted_bridges: vec![signer.bridge_id()],
            pow_floor: net.default_pow_floor(),
        };
        let script = params.script_pubkey.clone();
        let fresh = vec![claim(&signer, &params, 1), claim(&signer, &params, 2)];

        let failed: Result<freenet_stdlib::prelude::ContractKey> =
            Err(anyhow::anyhow!("timed out waiting for the node's reply"));
        mark_claims_if_published(&store, net, &script, &fresh, &failed);
        for claim in &fresh {
            assert!(
                !store.is_published(net, &script, &claim.digest()).unwrap(),
                "a claim that was not published must be sent again"
            );
        }

        let key = freenet_stdlib::prelude::ContractKey::from_params_and_code(
            freenet_stdlib::prelude::Parameters::from(vec![1u8]),
            freenet_stdlib::prelude::ContractCode::from(vec![0u8, 1, 2]),
        );
        mark_claims_if_published(&store, net, &script, &fresh, &Ok(key));
        for claim in &fresh {
            assert!(
                store.is_published(net, &script, &claim.digest()).unwrap(),
                "a published claim is not sent again"
            );
        }
    }
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
    /// `observe_once` scans blocks for the scripts in doubt as well as the
    /// watched ones, and lets the claims step publish only for the watched.
    /// Both halves are unit-tested (`scan_set`, `claims_from_block`), but only
    /// this pins the wiring, which round one of #10 got wrong while the unit
    /// tests stayed green. The needles are split as the test below explains.
    #[test]
    fn observe_once_scans_the_scripts_in_doubt_and_claims_only_for_the_watched() {
        let src = include_str!("main.rs");
        for (needle, why) in [
            (
                concat!("scripts_with_unconfirmed", "_outputs(obs.network())"),
                "the payments in doubt are no longer read",
            ),
            (
                concat!("scan_set(&watched, ", "&in_doubt)"),
                "the scan set no longer includes the scripts in doubt",
            ),
            (
                concat!("scan_block(&hash, ", "&scan)"),
                "blocks are no longer scanned with the scan set",
            ),
            (
                concat!("&tip, &watch", "ed, &mut round)"),
                "claims are no longer limited to the watched scripts",
            ),
            (
                concat!("prune_blocks(obs.network(), ", "Store::BLOCKS_KEPT)"),
                "blocks are no longer pruned, or no longer to the window watch \
                 expiry reads the deciding block from",
            ),
            (
                concat!("let Some(tip) = ChainClient::conn", "ect(net_cfg)"),
                "a demo address is seeded again without a tip, so a node still \
                 loading its block index makes it ask for the whole chain",
            ),
        ] {
            assert!(src.contains(needle), "{why}");
        }
    }

    #[test]
    fn observe_once_takes_its_ceiling_from_the_reorg_outcome() {
        let src = include_str!("main.rs");

        // READ THIS BEFORE COPYING THIS PATTERN.
        //
        // `include_str!("main.rs")` pulls in the whole file INCLUDING this
        // test, so any needle written as a single string literal appears in
        // the haystack by virtue of being written here at all. Both assertions
        // below are then decided by their own source text rather than by the
        // code they are meant to pin, and each fails in the direction that
        // hides the problem:
        //
        //   * the POSITIVE assertion (`contains`) passes whatever the call
        //     site says, because its literal is in the file -- so the pin
        //     stays green when the call is deleted, which is the one thing it
        //     exists to catch;
        //   * the NEGATIVE assertion (`!contains`) fails while the call site
        //     is CORRECT, because its literal is in the file -- a red check
        //     with no defect behind it.
        //
        // Both of those happened here, in a test whose entire purpose was to
        // catch a guard that did nothing. Splitting each needle across
        // `concat!` fragments fixes it: the joined string exists only at
        // runtime, and no fragment appears contiguously in the source, so the
        // haystack contains the needle only if the CODE does.
        //
        // The fragments must be split inside the meaningful token, not at a
        // convenient boundary -- `concat!("reorg.", "scan_ceiling(")` would
        // still leave `scan_ceiling(` in the file and match a mention of it in
        // any comment, including this one.
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
