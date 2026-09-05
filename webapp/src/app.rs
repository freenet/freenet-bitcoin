//! The page.

use dioxus::prelude::*;
use freenet_bitcoin_common::BitcoinNetwork;
use freenet_bitcoin_generation::Artifact;

use crate::generation::{Generations, Notice};
use crate::state::{AddressView, Derivation, PaymentRow, RowStatus, APP};
use crate::verify::{fmt_sats, Verification};
use crate::{address, config, keys, node, state};

/// Which contract generation the bridge says it publishes to.
///
/// Kept out of [`APP`] because the resolver it holds is neither `Clone` nor
/// cheap, and `App` is cloned freely; what the rest of the app needs from it
/// is two 32-byte hashes, which live in [`Derivation`].
pub static GENERATIONS: GlobalSignal<Generations> = GlobalSignal::new(Generations::default);

/// How long to wait for a generation pointer before saying it did not answer.
///
/// The page cannot start reading contracts until it knows which generation to
/// read, so this is a hard bound on time-to-first-paint in the failure case.
/// It resolves in well under a second when the node is healthy.
const POINTER_TIMEOUT_MS: i32 = 10_000;

/// How long the tip contract may stay silent before the page says so.
///
/// Silence here is the exact symptom this whole mechanism exists to explain:
/// an empty contract and a contract nobody publishes to look identical. Once
/// the page has waited longer than a plausible fetch, it says which contract
/// it is waiting on and which generation that came from, instead of spinning.
const TIP_PATIENCE_MS: i32 = 25_000;

#[component]
pub fn App() -> Element {
    // Connect once, then pump host responses into state for the page's life.
    use_future(move || async move {
        match node::connect().await {
            Ok(mut rx) => {
                // Nothing is read until the page knows WHICH contracts to
                // read. Fetching first and re-deriving afterwards would leave
                // a subscription standing on a contract nobody writes to.
                advance_generations();
                use futures::StreamExt;
                while let Some(msg) = rx.next().await {
                    handle_incoming(msg);
                }
            }
            Err(e) => {
                *node::CONNECTION.write() = node::Connection::Failed(e.clone());
                APP.write().error = Some(e);
            }
        }
    });

    rsx! {
        div { class: "page",
            Header {}
            GenerationNotices {}
            ChainPanel {}
            LookupPanel {}
            Results {}
            Footer {}
        }
    }
}

#[component]
fn Header() -> Element {
    let conn = node::CONNECTION.read().clone();
    rsx! {
        header { class: "head",
            div {
                h1 { "Bitcoin on Freenet" }
                p { class: "sub",
                    "Bitcoin payments, published to Freenet by a bridge and "
                    b { "re-checked in your browser" }
                    " against the transaction itself. Nothing here asks you to take the bridge's word for it."
                }
            }
            span { class: "conn conn-{conn.label()}", "{conn.label()}" }
        }
    }
}

#[component]
fn ChainPanel() -> Element {
    let app = APP.read();
    let network = app.network;
    let silent = app.tip_silent;
    let tip_id = app.tip_id().map(|i| i.to_string());
    let generation = freenet_bitcoin_generation::short(&app.derivation.tip_code_hash);
    let Some(tip) = app.tip.clone() else {
        drop(app);
        return rsx! {
            section { class: "card",
                div { class: "card-head",
                    h2 { "The chain" }
                    NetworkTabs {}
                }
                if config::trusted_bridges(network).is_empty() {
                    p { class: "muted",
                        "No bridge publishes for this network yet, so there is nothing to show."
                    }
                } else if silent {
                    // The failure mode in words. An empty contract and a
                    // contract nobody publishes to are byte-identical, so the
                    // page names what it asked for and lets the reader check.
                    p { class: "err",
                        "Nothing has come back from the tip contract. It is empty, or nobody is \
                         publishing to it."
                    }
                    p { class: "muted",
                        "Asked for contract "
                        span { class: "mono", "{tip_id.clone().unwrap_or_default()}" }
                        ", derived from contract generation "
                        span { class: "mono", "{generation}" }
                        "."
                    }
                } else {
                    p { class: "muted", "Waiting for the tip contract…" }
                }
            }
        };
    };

    let age = crate::app::relative_time(tip.last_block_time);
    rsx! {
        section { class: "card",
            div { class: "card-head",
                h2 { "The chain" }
                NetworkTabs {}
            }
            div { class: "stats",
                Stat { label: "Tip height", value: "{tip.height}" }
                Stat { label: "Last block", value: "{age}" }
                Stat { label: "Attested by", value: short_bridge(&tip) }
            }
            table { class: "blocks",
                thead { tr { th { "Block" } th { "Transactions" } th { "Seen" } } }
                tbody {
                    for b in tip.recent.iter() {
                        tr { key: "{b.anchor.height}",
                            td { class: "mono", "#{b.anchor.height}" }
                            td { "{b.tx_count}" }
                            td { class: "muted", "{crate::app::relative_time(b.block_time)}" }
                        }
                    }
                }
            }
        }
    }
}

/// What the page says when it cannot vouch for what it is showing.
///
/// Renders nothing when the bridge's generation and this build's agree, which
/// is the healthy case. A page that warns when everything is fine teaches
/// people to scroll past the warning that matters.
#[component]
fn GenerationNotices() -> Element {
    let unreadable = APP.read().unreadable.clone();
    let notices: Vec<Notice> = GENERATIONS.read().notices(unreadable.as_deref());
    if notices.is_empty() {
        return rsx! { div {} };
    }
    rsx! {
        for n in notices {
            div { key: "{n.headline}", class: "{n.severity.css()}",
                strong { "{n.headline}" }
                p { "{n.detail}" }
            }
        }
    }
}

/// Which network the page is showing, and how to change it.
///
/// Rendered even before a tip arrives: a visitor who lands on a network that
/// is not answering must be able to get back to one that is.
#[component]
fn NetworkTabs() -> Element {
    let current = APP.read().network;
    let networks = config::available_networks();
    if networks.len() < 2 {
        return rsx! { span { class: "pill", "{current.as_str()}" } };
    }
    rsx! {
        div { class: "tabs",
            for n in networks {
                button {
                    key: "{n.as_str()}",
                    class: if n == current { "tab tab-on" } else { "tab" },
                    onclick: move |_| switch_network(n),
                    "{n.as_str()}"
                }
            }
        }
    }
}

/// Start again on a different network.
///
/// Everything on screen was derived for the old one — the tip, the addresses,
/// the generation the bridge for that network publishes to — so all of it is
/// dropped rather than filtered. A stale row surviving a switch would be a
/// claim about the wrong chain.
fn switch_network(network: BitcoinNetwork) {
    {
        let mut app = APP.write();
        if app.network == network {
            return;
        }
        app.network = network;
        app.tip = None;
        app.tip_silent = false;
        app.addresses.clear();
        app.lookups.clear();
        app.queued_lookups.clear();
        app.pending = None;
        app.error = None;
        app.unreadable = None;
        app.derivation = Derivation::default();
    }
    *GENERATIONS.write() = Generations::for_network(network);
    advance_generations();
}

#[component]
fn Stat(label: String, value: String) -> Element {
    rsx! {
        div { class: "stat",
            span { class: "stat-label", "{label}" }
            span { class: "stat-value", "{value}" }
        }
    }
}

#[component]
fn LookupPanel() -> Element {
    let mut entry = use_signal(String::new);
    let app = APP.read();
    let network = app.network;
    let pending = app.pending.clone();
    drop(app);

    let submit = move || {
        let raw = entry().trim().to_string();
        if raw.is_empty() {
            return;
        }
        match address::to_script_pubkey(&raw, network) {
            Ok(script) => {
                APP.write().error = None;
                start_lookup(raw, script, network, false);
            }
            Err(e) => APP.write().error = Some(e),
        }
    };

    rsx! {
        section { class: "card",
            h2 { "Look up an address" }
            p { class: "muted",
                "Any Bitcoin address on this network. You are asking Freenet what it \
                 knows — no account, no key, and nothing recorded about the fact that you asked."
            }
            if let Some(note) = config::network_note(network) {
                p { class: "muted", "{note}" }
            }
            div { class: "row",
                input {
                    class: "addr-input",
                    placeholder: "tb1q…",
                    value: "{entry}",
                    oninput: move |e| entry.set(e.value()),
                    onkeydown: move |e| if e.key() == Key::Enter { submit() },
                }
                button { class: "go", onclick: move |_| submit(), "Look up" }
            }
            if let Some(p) = pending {
                p { class: "muted", "Asking the network about {p}…" }
            }
            if let Some(err) = APP.read().error.clone() {
                p { class: "err", "{err}" }
            }
        }
    }
}

#[component]
fn Results() -> Element {
    let app = APP.read();
    let mut views: Vec<AddressView> = app.addresses.values().cloned().collect();
    drop(app);
    // The curated example sits last, so anything the visitor asked for is on top.
    views.sort_by_key(|v| v.is_demo);

    if views.is_empty() {
        return rsx! { div {} };
    }
    rsx! {
        for v in views {
            AddressCard { key: "{v.address}", view: v }
        }
    }
}

#[component]
fn AddressCard(view: AddressView) -> Element {
    let scanned = match view.scanned_to {
        // The distinction the whole watermark exists for.
        None => "No bridge has reported on this address yet".to_string(),
        Some(h) => format!("Scanned to block {h}"),
    };
    rsx! {
        section { class: "card",
            div { class: "card-head",
                h2 { class: "mono addr", "{view.address}" }
                if view.is_demo {
                    span { class: "pill", "example" }
                }
            }
            if let Some(note) = view.demo_note.clone() {
                p { class: "muted", "{note}" }
            }
            div { class: "stats",
                Stat { label: "Confirmed", value: fmt_sats(view.confirmed_sats) }
                Stat { label: "Pending", value: fmt_sats(view.pending_sats) }
                Stat { label: "Coverage", value: scanned }
            }

            if view.payments.is_empty() {
                p { class: "muted",
                    if view.scanned_to.is_some() {
                        "A bridge has looked and found no payments to this address."
                    } else {
                        "Nothing to show until a bridge synchronises this address."
                    }
                }
            }
            for p in view.payments.iter() {
                PaymentCard { key: "{p.txid}-{p.vout}", row: p.clone() }
            }
        }
    }
}

#[component]
fn PaymentCard(row: PaymentRow) -> Element {
    let (status_class, status_text) = match &row.status {
        RowStatus::Confirmed {
            height,
            confirmations,
        } => (
            "ok",
            format!(
                "in block {height} · {confirmations} confirmation{}",
                if *confirmations == 1 { "" } else { "s" }
            ),
        ),
        RowStatus::Unconfirmed => ("pending", "seen, not yet in a block".to_string()),
        // A payment that was reorged away. Shown rather than hidden: silently
        // dropping it would misrepresent the address's history.
        RowStatus::Reorged => ("bad", "reorganised off the chain".to_string()),
    };

    rsx! {
        article { class: "payment",
            div { class: "payment-head",
                span { class: "amount", "{fmt_sats(row.value_sats)}" }
                span { class: "status status-{status_class}", "{status_text}" }
            }
            div { class: "mono txid", "{row.txid}:{row.vout}" }
            if row.evidence_bytes > 0 {
                div { class: "muted",
                    "Proven by {row.evidence_bytes} bytes of evidence carried through Freenet."
                }
            }
            if let Some(v) = row.verification.clone() {
                VerificationBlock { v }
            }
        }
    }
}

#[component]
fn VerificationBlock(v: Verification) -> Element {
    let depth_note = format!(
        "{} header{} of work carried",
        v.proven_depth,
        if v.proven_depth == 1 { "" } else { "s" }
    );
    rsx! {
        div { class: if v.all_ok() { "verify verify-ok" } else { "verify verify-bad" },
            div { class: "verify-head",
                if v.all_ok() {
                    span { "Evidence checked in your browser" }
                } else {
                    span { "This evidence did not check out" }
                }
                span { class: "muted", "{depth_note}" }
            }
            ul {
                for c in v.checks.iter() {
                    li { key: "{c.headline}", class: if c.ok { "chk ok" } else { "chk bad" },
                        strong { "{c.headline}" }
                        span { class: "muted", "{c.detail}" }
                    }
                }
            }
        }
    }
}

#[component]
fn Footer() -> Element {
    rsx! {
        footer { class: "foot",
            p {
                "Every claim carries its transaction and block headers, and this page \
                 re-checks them, so a bridge cannot change an amount or redirect a payment \
                 \u{2014} the transaction commits to both. The bridge is still trusted for \
                 which blocks are on Bitcoin, and for how deep a payment is buried; nothing \
                 here checks either against the network. Anyone can run one, and an \
                 application can name more than one."
            }
            p { class: "muted",
                "Signet is a Bitcoin test network. Its coins have no value and its blocks are \
                 cheap to produce, so treat a green tick here as a demonstration of the \
                 mechanism, not of mainnet-grade security."
            }
        }
    }
}

// ---------------------------------------------------------------------------

fn short_bridge(tip: &state::TipView) -> String {
    match tip.attested_by.first() {
        Some(b) => {
            let s = b.to_bs58();
            format!("{}…{}", &s[..6], &s[s.len() - 4..])
        }
        None => "nobody".to_string(),
    }
}

/// Human-readable age from a Bitcoin block timestamp.
///
/// Reads the browser clock, which a UI may do freely — unlike a contract,
/// whose verdict has to be a pure function of its inputs.
pub fn relative_time(block_time: u32) -> String {
    let now = now_unix();
    let age = now.saturating_sub(block_time as i64);
    match age {
        a if a < 90 => "just now".to_string(),
        a if a < 3600 => format!("{} minutes ago", a / 60),
        a if a < 86_400 => format!("{} hours ago", a / 3600),
        a => format!("{} days ago", a / 86_400),
    }
}

#[cfg(target_arch = "wasm32")]
fn now_unix() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Fetch the next generation pointer, or start reading once both have
/// settled.
///
/// One pointer GET at a time, each with its own deadline. The node reports a
/// missing contract as a bare operation error that does not name the contract,
/// so a second concurrent GET would make a failure unattributable — and
/// attributing it to the wrong pointer would resolve the wrong generation.
fn advance_generations() {
    let next = GENERATIONS.write().next_pointer();
    let Some(id) = next else {
        if GENERATIONS.read().settled() {
            on_generations_settled();
        }
        return;
    };
    node::get_pointer(id);
    node::spawn(async move {
        node::sleep_ms(POINTER_TIMEOUT_MS).await;
        if GENERATIONS.read().in_flight() != Some(id) {
            return;
        }
        // Silence, never absence: a stalled GET must not read as "no pointer
        // was ever published", which is the one answer that would let the page
        // treat its build-time generation as confirmed.
        GENERATIONS.write().on_pointer_unreachable(id);
        advance_generations();
    });
}

/// Both generations are known: start reading contracts.
fn on_generations_settled() {
    let (address_code_hash, tip_code_hash, tip_usable, address_usable) = {
        let g = GENERATIONS.read();
        (
            g.code_hash(Artifact::Address),
            g.code_hash(Artifact::Tip),
            g.usable(Artifact::Tip),
            g.usable(Artifact::Address),
        )
    };

    let queued = {
        let mut app = APP.write();
        app.derivation = Derivation {
            address_code_hash,
            tip_code_hash,
        };
        std::mem::take(&mut app.queued_lookups)
    };

    if tip_usable {
        subscribe_to_tip();
        node::spawn(async move {
            node::sleep_ms(TIP_PATIENCE_MS).await;
            let mut app = APP.write();
            if app.tip.is_none() {
                app.tip_silent = true;
            }
        });
    }
    if address_usable {
        lookup_demo_address();
        for lookup in queued {
            issue_lookup(lookup);
        }
    }
}

fn subscribe_to_tip() {
    let (network, code_hash) = {
        let app = APP.read();
        (app.network, app.derivation.tip_code_hash)
    };
    let bridges = config::trusted_bridges(network);
    if bridges.is_empty() {
        return;
    }
    if let Ok(id) = keys::tip_contract_id_at(&code_hash, network, &bridges) {
        node::get_and_subscribe(id);
    }
}

fn lookup_demo_address() {
    let network = APP.read().network;
    let Some(demo) = config::demo_address(network) else {
        return;
    };
    if let Ok(script) = address::to_script_pubkey(demo.address, network) {
        start_lookup(demo.address.to_string(), script, network, true);
    }
}

fn start_lookup(address: String, script: Vec<u8>, network: BitcoinNetwork, is_demo: bool) {
    let lookup = state::Lookup {
        address,
        script_pubkey: script,
        network,
        is_demo,
    };
    // Before the generation is known there is no correct address to derive.
    // Guessing and re-deriving later would leave a subscription standing on a
    // contract nobody writes to, which is the failure this all exists to stop.
    if !GENERATIONS.read().settled() {
        let mut app = APP.write();
        if !lookup.is_demo {
            app.pending = Some(lookup.address.clone());
        }
        app.queued_lookups.push(lookup);
        return;
    }
    issue_lookup(lookup);
}

fn issue_lookup(lookup: state::Lookup) {
    if !GENERATIONS.read().usable(Artifact::Address) {
        APP.write().error = Some(
            "This bridge has withdrawn its address contract, so there is nothing to look up."
                .into(),
        );
        return;
    }
    let code_hash = APP.read().derivation.address_code_hash;
    let bridges = config::trusted_bridges(lookup.network);
    let Ok(id) =
        keys::address_contract_id_at(&code_hash, lookup.network, &lookup.script_pubkey, &bridges)
    else {
        APP.write().error = Some("could not derive the contract for that address".into());
        return;
    };
    {
        let mut app = APP.write();
        if !lookup.is_demo {
            app.pending = Some(lookup.address.clone());
        }
        app.lookups.insert(id.as_bytes().to_vec(), lookup);
    }
    node::get_and_subscribe(id);
}

fn handle_incoming(msg: node::Incoming) {
    use freenet_stdlib::client_api::{ContractResponse, HostResponse};

    let resp = match msg {
        node::Incoming::Response(r) => r,
        node::Incoming::Failed(f) => return handle_failure(f),
    };

    if let HostResponse::ContractResponse(cr) = resp {
        match cr {
            ContractResponse::GetResponse { key, state, .. } => {
                let id = *key.id();
                // A pointer's reply settles a generation rather than filling
                // the page, so it is routed first and never parsed as
                // contract state.
                if GENERATIONS.read().in_flight() == Some(id) {
                    GENERATIONS.write().on_pointer_state(id, state.as_ref());
                    advance_generations();
                    return;
                }
                APP.write()
                    .on_contract_state(id.as_bytes().to_vec(), state.as_ref().to_vec());
            }
            // A delta's wire shape differs from full state, so re-GET rather
            // than trying to parse it as state — the bug that made Harvest's
            // updates silently never arrive.
            ContractResponse::UpdateNotification { key, .. } => {
                node::get_and_subscribe(*key.id());
            }
            _ => {}
        }
    }
}

/// A request the node refused.
///
/// This used to be dropped on the floor, which is how "there is no such
/// contract" became indistinguishable from "the contract is empty". The one
/// case that must be got right is a pointer: a definitive absence is the only
/// answer that permits treating this build's own generation as the answer, and
/// anything else has to stay an unconfirmed guess.
fn handle_failure(f: node::Failure) {
    let waiting = GENERATIONS.read().in_flight();
    let Some(pointer) = waiting else {
        if let Some(message) = describe_failure(&f) {
            APP.write().error = Some(message);
        }
        return;
    };
    // Attribute by key when the error names one; otherwise by the fact that
    // exactly one pointer GET is ever outstanding.
    if f.key.is_some_and(|k| k != pointer) {
        return;
    }
    if f.not_found {
        GENERATIONS.write().on_pointer_absent(pointer);
    } else {
        GENERATIONS.write().on_pointer_unreachable(pointer);
    }
    advance_generations();
}

fn describe_failure(f: &node::Failure) -> Option<String> {
    if f.not_found {
        // Expected for an address nobody has ever published observations for.
        // The address card already distinguishes that from "not scanned".
        return None;
    }
    Some(format!(
        "The node could not complete a request: {}",
        f.message
    ))
}
