//! Everything the page knows, and how contract updates reach it.

use std::collections::HashMap;

use dioxus::prelude::*;
use freenet_bitcoin_common::address_state::BitcoinAddressStateV1;
use freenet_bitcoin_common::tip_state::BitcoinTipStateV1;
use freenet_bitcoin_common::{from_cbor, BitcoinNetwork, BridgeId, OutpointStatus, TipEntryBody};
use freenet_stdlib::prelude::ContractInstanceId;

use crate::{config, keys, verify};

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
        keys::tip_contract_id(self.network, &bridges).ok()
    }

    /// Route an arriving contract state to whatever asked for it.
    pub fn on_contract_state(&mut self, id: Vec<u8>, bytes: Vec<u8>) {
        if Some(id.as_slice()) == self.tip_id().map(|i| i.as_bytes().to_vec()).as_deref() {
            if let Ok(tip) = from_cbor::<BitcoinTipStateV1>(&bytes) {
                self.apply_tip(&tip);
            }
            return;
        }
        if let Some(lookup) = self.lookups.get(&id).cloned() {
            if let Ok(state) = from_cbor::<BitcoinAddressStateV1>(&bytes) {
                self.apply_address(&lookup, &state);
                self.pending = None;
            }
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
    }

    fn apply_address(&mut self, lookup: &Lookup, state: &BitcoinAddressStateV1) {
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
                    OutpointStatus::Confirmed { value_sats, anchor } => (
                        value_sats,
                        RowStatus::Confirmed {
                            height: anchor.height,
                            confirmations: freenet_bitcoin_common::confirmations(
                                &anchor, tip_height,
                            ),
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
        self.addresses.insert(
            keys::address_contract_id(
                lookup.network,
                &lookup.script_pubkey,
                &config::trusted_bridges(lookup.network),
            )
            .map(|i| i.as_bytes().to_vec())
            .unwrap_or_default(),
            AddressView {
                address: lookup.address.clone(),
                is_demo: lookup.is_demo,
                demo_note: lookup
                    .is_demo
                    .then(|| config::demo_address(lookup.network).map(|d| d.why.to_string()))
                    .flatten(),
                scanned_to: state.scanned_to(),
                confirmed_sats: state.claims.confirmed_value_sats(tip_height, min_conf),
                pending_sats: state.claims.pending_value_sats(tip_height, min_conf),
                payments,
            },
        );
    }
}

fn height_of(p: &PaymentRow) -> u32 {
    match p.status {
        RowStatus::Confirmed { height, .. } => height,
        _ => u32::MAX, // unconfirmed and reorged sort to the top
    }
}
