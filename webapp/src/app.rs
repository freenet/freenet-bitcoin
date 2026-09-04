//! The page.

use dioxus::prelude::*;
use freenet_bitcoin_common::BitcoinNetwork;

use crate::state::{AddressView, PaymentRow, RowStatus, APP};
use crate::verify::{fmt_sats, Verification};
use crate::{address, config, keys, node, state};

#[component]
pub fn App() -> Element {
    // Connect once, then pump host responses into state for the page's life.
    use_future(move || async move {
        match node::connect().await {
            Ok(mut rx) => {
                subscribe_to_tip();
                lookup_demo_address();
                use futures::StreamExt;
                while let Some(msg) = rx.next().await {
                    if let Ok(resp) = msg {
                        handle_response(resp);
                    }
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
    let Some(tip) = app.tip.clone() else {
        return rsx! {
            section { class: "card",
                h2 { "The chain" }
                p { class: "muted",
                    if config::trusted_bridges(network).is_empty() {
                        "No bridge publishes for this network yet, so there is nothing to show."
                    } else {
                        "Waiting for the tip contract…"
                    }
                }
            }
        };
    };

    let age = crate::app::relative_time(tip.last_block_time);
    rsx! {
        section { class: "card",
            div { class: "card-head",
                h2 { "The chain" }
                span { class: "pill", "{network.as_str()}" }
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

fn subscribe_to_tip() {
    let network = APP.read().network;
    let bridges = config::trusted_bridges(network);
    if bridges.is_empty() {
        return;
    }
    if let Ok(id) = keys::tip_contract_id(network, &bridges) {
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
    let bridges = config::trusted_bridges(network);
    let Ok(id) = keys::address_contract_id(network, &script, &bridges) else {
        APP.write().error = Some("could not derive the contract for that address".into());
        return;
    };
    {
        let mut app = APP.write();
        app.lookups.insert(
            id.as_bytes().to_vec(),
            state::Lookup {
                address: address.clone(),
                script_pubkey: script,
                network,
                is_demo,
            },
        );
        if !is_demo {
            app.pending = Some(address);
        }
    }
    node::get_and_subscribe(id);
}

fn handle_response(resp: freenet_stdlib::client_api::HostResponse) {
    use freenet_stdlib::client_api::{ContractResponse, HostResponse};
    if let HostResponse::ContractResponse(cr) = resp {
        match cr {
            ContractResponse::GetResponse { key, state, .. } => {
                APP.write()
                    .on_contract_state(key.id().as_bytes().to_vec(), state.as_ref().to_vec());
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
