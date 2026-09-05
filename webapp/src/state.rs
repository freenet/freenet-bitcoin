//! Everything the page knows, and how contract updates reach it.

use std::collections::HashMap;

use dioxus::prelude::*;
use freenet_bitcoin_common::address_state::BitcoinAddressStateV1;
use freenet_bitcoin_common::tip_state::BitcoinTipStateV1;
use freenet_bitcoin_common::{from_cbor, BitcoinNetwork, BridgeId, OutpointStatus, TipEntryBody};
use freenet_stdlib::prelude::ContractInstanceId;

use crate::{config, keys, verify};

/// Which contract generation the page is deriving addresses from.
///
/// Starts as what this build embeds and is replaced once the bridge's
/// generation pointers resolve (see [`crate::generation`]). It is `Copy` so it
/// can live inside [`App`] without dragging the resolver machinery — which is
/// neither `Clone` nor cheap — along with it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Derivation {
    pub address_code_hash: [u8; 32],
    pub tip_code_hash: [u8; 32],
}

impl Default for Derivation {
    fn default() -> Self {
        Self {
            address_code_hash: keys::embedded_address_code_hash(),
            tip_code_hash: keys::embedded_tip_code_hash(),
        }
    }
}

pub static APP: GlobalSignal<App> = GlobalSignal::new(App::default);

#[derive(Clone)]
pub struct App {
    pub network: BitcoinNetwork,
    pub tip: Option<TipView>,
    /// Address contracts we have asked for, by instance id.
    pub addresses: HashMap<Vec<u8>, AddressView>,
    /// Which instance id belongs to which address, so a response can be routed.
    pub lookups: HashMap<Vec<u8>, Lookup>,
    pub pending: Option<String>,
    pub error: Option<String>,
    /// The contract generation being read. See [`Derivation`].
    pub derivation: Derivation,
    /// Set when a contract answered with state this build cannot decode.
    ///
    /// This is the one failure that following the bridge's generation can
    /// produce and embedding cannot: a generation whose wire format moved. It
    /// gets its own field because it must be shown as loudly as possible —
    /// silently ignoring the parse, which is what this code used to do, turns
    /// an incompatible bridge into a blank page.
    pub unreadable: Option<String>,
    /// True once the tip contract has stayed silent long enough that the
    /// page should say so rather than keep spinning.
    pub tip_silent: bool,
    /// Lookups requested before the generation pointers settled.
    ///
    /// Deriving an address from the wrong generation and re-deriving later
    /// would leave a subscription outstanding on a contract nobody writes to,
    /// so a lookup asked for early waits rather than guessing.
    pub queued_lookups: Vec<Lookup>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Lookup {
    pub address: String,
    pub script_pubkey: Vec<u8>,
    pub network: BitcoinNetwork,
    /// Set for the operator's curated example, so the UI can say why it is here.
    pub is_demo: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            network: config::default_network(),
            tip: None,
            addresses: HashMap::new(),
            lookups: HashMap::new(),
            pending: None,
            error: None,
            derivation: Derivation::default(),
            unreadable: None,
            tip_silent: false,
            queued_lookups: Vec::new(),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct TipView {
    pub height: u32,
    pub last_block_time: u32,
    pub recent: Vec<TipEntryBody>,
    pub attested_by: Vec<BridgeId>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddressView {
    pub address: String,
    pub is_demo: bool,
    /// The state as received. Derived figures (confirmations, confirmed vs
    /// pending) are recomputed from this whenever the tip moves, rather than
    /// frozen at parse time -- the address state routinely arrives BEFORE the
    /// tip does, and a confirmation count computed against a tip height of
    /// zero reported every settled payment as pending.
    pub raw: BitcoinAddressStateV1,
    pub network: BitcoinNetwork,
    pub script_pubkey: Vec<u8>,
    /// Why the operator chose to show this one, when it is the example.
    pub demo_note: Option<String>,
    /// None means no bridge has reported on this script at all — which is a
    /// different fact from "no payments", and the UI must not blur them.
    pub scanned_to: Option<u32>,
    pub payments: Vec<PaymentRow>,
    pub confirmed_sats: u64,
    pub pending_sats: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct PaymentRow {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub status: RowStatus,
    pub verification: Option<verify::Verification>,
    pub evidence_bytes: usize,
}

#[derive(Clone, PartialEq, Debug)]
pub enum RowStatus {
    Confirmed { height: u32, confirmations: u32 },
    Unconfirmed,
    Reorged,
}

impl App {
    /// Contract instance ids this page wants, for the current network.
    pub fn tip_id(&self) -> Option<ContractInstanceId> {
        let bridges = config::trusted_bridges(self.network);
        if bridges.is_empty() {
            return None;
        }
        keys::tip_contract_id_at(&self.derivation.tip_code_hash, self.network, &bridges).ok()
    }

    /// Route an arriving contract state to whatever asked for it.
    ///
    /// A decode failure is recorded rather than dropped. The bytes came from
    /// the contract the bridge is publishing to, so failing to read them means
    /// this build and that generation disagree about the wire format — which
    /// the page must say, not swallow.
    pub fn on_contract_state(&mut self, id: Vec<u8>, bytes: Vec<u8>) {
        if Some(id.as_slice()) == self.tip_id().map(|i| i.as_bytes().to_vec()).as_deref() {
            match from_cbor::<BitcoinTipStateV1>(&bytes) {
                Ok(tip) => self.apply_tip(&tip),
                Err(e) => {
                    self.unreadable = Some(format!(
                        "The tip contract returned {} bytes this build could not decode ({e}).",
                        bytes.len()
                    ))
                }
            }
            return;
        }
        if let Some(lookup) = self.lookups.get(&id).cloned() {
            match from_cbor::<BitcoinAddressStateV1>(&bytes) {
                Ok(state) => {
                    self.apply_address(&lookup, &state);
                    self.pending = None;
                }
                Err(e) => {
                    self.pending = None;
                    self.unreadable = Some(format!(
                        "An address contract returned {} bytes this build could not decode ({e}).",
                        bytes.len()
                    ));
                }
            }
        }
    }

    /// Recompute every address view against the current tip.
    fn recompute_addresses(&mut self) {
        let ids: Vec<Vec<u8>> = self.addresses.keys().cloned().collect();
        for id in ids {
            let Some(view) = self.addresses.get(&id).cloned() else {
                continue;
            };
            let rebuilt = self.derive_view(
                &view.address,
                view.is_demo,
                view.network,
                &view.script_pubkey,
                &view.raw,
            );
            self.addresses.insert(id, rebuilt);
        }
    }

    fn apply_tip(&mut self, tip: &BitcoinTipStateV1) {
        let recent = tip.blocks.recent(8);
        let Some(head) = recent.first() else { return };
        self.tip = Some(TipView {
            height: head.anchor.height,
            last_block_time: head.block_time,
            recent,
            attested_by: config::trusted_bridges(self.network),
        });
        // The tip is what confirmations are measured against, so everything
        // already on screen is now stale.
        self.recompute_addresses();
    }

    fn apply_address(&mut self, lookup: &Lookup, state: &BitcoinAddressStateV1) {
        let view = self.derive_view(
            &lookup.address,
            lookup.is_demo,
            lookup.network,
            &lookup.script_pubkey,
            state,
        );
        if let Ok(id) = keys::address_contract_id_at(
            &self.derivation.address_code_hash,
            lookup.network,
            &lookup.script_pubkey,
            &config::trusted_bridges(lookup.network),
        ) {
            self.addresses.insert(id.as_bytes().to_vec(), view);
        }
    }

    fn derive_view(
        &self,
        address: &str,
        is_demo: bool,
        network: BitcoinNetwork,
        script_pubkey: &[u8],
        state: &BitcoinAddressStateV1,
    ) -> AddressView {
        let lookup = Lookup {
            address: address.to_string(),
            script_pubkey: script_pubkey.to_vec(),
            network,
            is_demo,
        };
        let params = keys::address_params(
            lookup.network,
            &lookup.script_pubkey,
            &config::trusted_bridges(lookup.network),
        );
        let tip_height = self.tip.as_ref().map(|t| t.height).unwrap_or(0);

        // Re-verify every claim here rather than trusting the fold that
        // produced the summary: this is the whole promise of the page.
        let mut verifications: HashMap<(Vec<u8>, u32), verify::Verification> = HashMap::new();
        let mut evidence: HashMap<(Vec<u8>, u32), usize> = HashMap::new();
        for body in state.claims.claim_bodies() {
            if let freenet_bitcoin_common::Claim::ConfirmedOutput { outpoint, spv, .. } =
                &body.claim
            {
                evidence.insert(
                    (outpoint.txid.0.to_vec(), outpoint.vout),
                    verify::evidence_bytes(spv),
                );
            }
            if let Some(v) = verify::verify_claim(&params, &body) {
                verifications.insert((v.outpoint.txid.0.to_vec(), v.outpoint.vout), v);
            }
        }

        let mut payments: Vec<PaymentRow> = state
            .claims
            .outpoint_statuses()
            .into_iter()
            .map(|(op, status)| {
                let key = (op.txid.0.to_vec(), op.vout);
                let verification = verifications.get(&key).cloned();
                let (value_sats, status) = match status {
                    // `confirmations_at`, not raw tip arithmetic: the UI shows
                    // the depth a verifier would act on, capped by what the
                    // signing bridge actually attested. Showing the larger
                    // number would tell a user a payment is deeper than
                    // anything they could prove it to be.
                    OutpointStatus::Confirmed {
                        value_sats, anchor, ..
                    } => (
                        value_sats,
                        RowStatus::Confirmed {
                            height: anchor.height,
                            confirmations: status.confirmations_at(tip_height),
                        },
                    ),
                    OutpointStatus::Unconfirmed { value_sats } => {
                        (value_sats, RowStatus::Unconfirmed)
                    }
                    OutpointStatus::Retracted => (0, RowStatus::Reorged),
                };
                PaymentRow {
                    txid: verify::fmt_txid(&op.txid),
                    vout: op.vout,
                    value_sats,
                    status,
                    evidence_bytes: evidence.get(&key).copied().unwrap_or(0),
                    verification,
                }
            })
            .collect();

        // Newest first: what changed most recently is what a visitor came for.
        payments.sort_by_key(|p| std::cmp::Reverse(height_of(p)));

        let min_conf = lookup.network.default_confirmation_target();
        AddressView {
            address: lookup.address.clone(),
            is_demo: lookup.is_demo,
            raw: state.clone(),
            network: lookup.network,
            script_pubkey: lookup.script_pubkey.clone(),
            demo_note: lookup
                .is_demo
                .then(|| config::demo_address(lookup.network).map(|d| d.why.to_string()))
                .flatten(),
            scanned_to: state.scanned_to(),
            confirmed_sats: state.claims.confirmed_value_sats(tip_height, min_conf),
            pending_sats: state.claims.pending_value_sats(tip_height, min_conf),
            payments,
        }
    }
}

fn height_of(p: &PaymentRow) -> u32 {
    match p.status {
        RowStatus::Confirmed { height, .. } => height,
        _ => u32::MAX, // unconfirmed and reorged sort to the top
    }
}
