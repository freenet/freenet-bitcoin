//! Inbox state, its merge, and synchronization.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::digest::BucketDigest;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

use crate::{
    cert_key, verify_certificate, verify_entry, ByteBuf, CertKey, EntryKey, GhostkeyId, InboxEntry,
    InboxEntryBody, InboxParameters, SignedFloor, SignedTombstone, MAX_RECORDS,
    MAX_RECORDS_PER_GHOSTKEY, WINDOW_BLOCKS,
};
use freenet_bitcoin_common::from_cbor;

/// State of one bridge's inbox.
///
/// Every map is a `BTreeMap`: peers decide they have converged by comparing
/// state bytes, so iteration order must be a function of the contents.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct InboxStateV1 {
    /// Absent until the bridge opens the inbox. Nothing is admitted before
    /// then, so nobody can seed an inbox before its owner has.
    pub floor: Option<SignedFloor>,
    /// Certificates, stored once and shared by every entry of one Ghost Key.
    pub certificates: BTreeMap<CertKey, String>,
    pub entries: BTreeMap<EntryKey, InboxEntry>,
    pub tombstones: BTreeMap<EntryKey, SignedTombstone>,
}

/// An entry as it travels between peers: with its certificate, because the
/// receiver may not hold that certificate yet.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct WireEntry {
    pub entry: InboxEntry,
    pub certificate_pem: String,
}

impl WireEntry {
    /// Build an entry from what the ghostkey delegate's `SignResult` returned.
    ///
    /// Nothing here is trusted: the contract verifies all of it. This only
    /// lifts out the two values the state is ordered by.
    pub fn from_sign_result(
        certificate_pem: String,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, String> {
        let cert = GhostkeyCertificateV1::from_armored_string(&certificate_pem)
            .map_err(|e| format!("certificate does not parse: {e:?}"))?;
        let scoped: ghostkey_common::ScopedPayload = from_cbor(&scoped_payload)?;
        let body = InboxEntryBody::from_signing_payload(&scoped.payload)?;
        Ok(WireEntry {
            entry: InboxEntry {
                mainnet_height: body.mainnet_height,
                ghostkey: GhostkeyId(*cert.verifying_key.as_bytes()),
                cert: cert_key(&certificate_pem),
                scoped_payload: ByteBuf(scoped_payload),
                signature: ByteBuf(signature),
            },
            certificate_pem,
        })
    }
}

/// Changes to send a peer.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct InboxDelta {
    pub floor: Option<SignedFloor>,
    pub entries: Vec<WireEntry>,
    pub tombstones: Vec<SignedTombstone>,
}

impl InboxDelta {
    pub fn is_empty(&self) -> bool {
        self.floor.is_none() && self.entries.is_empty() && self.tombstones.is_empty()
    }
}

/// What a peer holds, in a fixed size whatever the inbox holds.
///
/// Bucketed, so `delta` may resend a whole bucket rather than one record. That
/// is sound only because applying an already-held record changes nothing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InboxSummary {
    pub floor: Option<u32>,
    pub entries: BucketDigest,
    pub tombstones: BucketDigest,
}

/// One slot in the caps' order: (height, key, Ghost Key).
type Record = (u32, EntryKey, GhostkeyId);

impl InboxStateV1 {
    pub fn floor_height(&self) -> Option<u32> {
        self.floor.as_ref().map(|f| f.height)
    }

    /// Full verification of a state: every signature and identity, the window,
    /// the caps, and that it is in normal form. A state honest merges produce
    /// always passes; there is exactly one byte representation of each.
    pub fn verify(&self, params: &InboxParameters) -> Result<(), String> {
        let Some(floor) = &self.floor else {
            if self.entries.is_empty() && self.tombstones.is_empty() && self.certificates.is_empty()
            {
                return Ok(());
            }
            return Err("the inbox holds records but its bridge has not opened it".into());
        };
        floor.verify(&params.bridge)?;
        let floor = floor.height;

        let mut certified: BTreeMap<CertKey, VerifyingKey> = BTreeMap::new();
        for (k, pem) in &self.certificates {
            if cert_key(pem) != *k {
                return Err("certificate filed under a key that is not its digest".into());
            }
            certified.insert(*k, verify_certificate(pem, &params.ghostkey_master)?);
        }

        let mut referenced: BTreeSet<CertKey> = BTreeSet::new();
        for (k, e) in &self.entries {
            if e.key() != *k {
                return Err("entry filed under a key that is not its digest".into());
            }
            let vk = certified
                .get(&e.cert)
                .ok_or("entry references a certificate the state does not hold")?;
            verify_entry(e, vk, params)?;
            if e.mainnet_height < floor {
                return Err("entry below the floor: state is not in normal form".into());
            }
            if e.mainnet_height > floor.saturating_add(WINDOW_BLOCKS) {
                return Err("entry dated beyond the window above the floor".into());
            }
            if self.tombstones.contains_key(k) {
                return Err("a removed entry is still present".into());
            }
            referenced.insert(e.cert);
        }
        if referenced.len() != self.certificates.len() {
            return Err("state holds a certificate no entry uses".into());
        }

        for (k, t) in &self.tombstones {
            if t.entry != *k {
                return Err("tombstone filed under another entry's key".into());
            }
            t.verify(&params.bridge)?;
            if t.entry_height < floor {
                return Err("tombstone below the floor: state is not in normal form".into());
            }
        }

        let records = self.records();
        if records.len() > MAX_RECORDS {
            return Err(format!(
                "inbox holds {} records, cap is {MAX_RECORDS}",
                records.len()
            ));
        }
        let mut per: BTreeMap<GhostkeyId, usize> = BTreeMap::new();
        for (_, _, g) in &records {
            let c = per.entry(*g).or_insert(0);
            *c += 1;
            if *c > MAX_RECORDS_PER_GHOSTKEY {
                return Err(format!(
                    "a Ghost Key holds more than {MAX_RECORDS_PER_GHOSTKEY} records"
                ));
            }
        }
        Ok(())
    }

    /// Every record, entry or tombstone, as its slot in the caps' order.
    fn records(&self) -> Vec<Record> {
        self.entries
            .iter()
            .map(|(k, e)| (e.mainnet_height, *k, e.ghostkey))
            .chain(
                self.tombstones
                    .iter()
                    .map(|(k, t)| (t.entry_height, *k, t.ghostkey)),
            )
            .collect()
    }

    /// Bring the state to normal form. Deterministic, and a function of the
    /// records present and the floor alone, which is what lets peers that
    /// merged in different orders reach the same bytes.
    ///
    /// # Why the caps commute with removal
    ///
    /// Records are ranked newest first (height descending, then key). Each
    /// Ghost Key keeps its best [`MAX_RECORDS_PER_GHOSTKEY`], and of those the
    /// best [`MAX_RECORDS`] survive overall. Every discarded record therefore
    /// ranks below every kept one. The floor only removes from the bottom of
    /// the order, and a tombstone keeps its entry's slot rather than freeing
    /// it, so nothing that was discarded can ever be needed again. A "lowest
    /// digests" rule, or a tombstone that freed its slot, would each break
    /// this; the tests assert the merge laws on exact bytes to catch either.
    pub fn normalize(&mut self) {
        let Some(floor) = self.floor_height() else {
            self.certificates.clear();
            self.entries.clear();
            self.tombstones.clear();
            return;
        };

        self.entries.retain(|_, e| e.mainnet_height >= floor);
        self.tombstones.retain(|_, t| t.entry_height >= floor);
        let removed: BTreeSet<EntryKey> = self.tombstones.keys().copied().collect();
        self.entries.retain(|k, _| !removed.contains(k));

        let mut records = self.records();
        records.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut per: BTreeMap<GhostkeyId, usize> = BTreeMap::new();
        let mut kept: BTreeSet<EntryKey> = BTreeSet::new();
        for (_, k, g) in &records {
            let c = per.entry(*g).or_insert(0);
            if *c >= MAX_RECORDS_PER_GHOSTKEY || kept.len() >= MAX_RECORDS {
                continue;
            }
            *c += 1;
            kept.insert(*k);
        }
        self.entries.retain(|k, _| kept.contains(k));
        self.tombstones.retain(|k, _| kept.contains(k));

        let used: BTreeSet<CertKey> = self.entries.values().map(|e| e.cert).collect();
        self.certificates.retain(|k, _| used.contains(k));
    }

    /// Apply changes from a peer or a sender. Every incoming record is
    /// verified before it is admitted; nothing arriving here was covered by an
    /// earlier check.
    ///
    /// An entry below the floor is dropped, never an error: a peer whose floor
    /// was lower can legitimately send one. An entry above the window IS an
    /// error, because no valid state can hold one.
    pub fn apply_delta(
        &mut self,
        params: &InboxParameters,
        delta: &InboxDelta,
    ) -> Result<(), String> {
        if let Some(f) = &delta.floor {
            f.verify(&params.bridge)?;
            let adopt = match &self.floor {
                None => true,
                Some(cur) => {
                    f.height > cur.height || (f.height == cur.height && f.signature < cur.signature)
                }
            };
            if adopt {
                self.floor = Some(f.clone());
            }
        }

        for t in &delta.tombstones {
            t.verify(&params.bridge)?;
            let keep_existing = self
                .tombstones
                .get(&t.entry)
                .is_some_and(|cur| cur.signature <= t.signature);
            if !keep_existing {
                self.tombstones.insert(t.entry, t.clone());
            }
        }

        if !delta.entries.is_empty() {
            let floor = self
                .floor_height()
                .ok_or("the inbox is not open yet: its bridge has not set a floor")?;
            let mut certified: BTreeMap<CertKey, VerifyingKey> = BTreeMap::new();
            for w in &delta.entries {
                let ck = cert_key(&w.certificate_pem);
                if ck != w.entry.cert {
                    return Err("entry names a different certificate than it carries".into());
                }
                let vk = match certified.get(&ck) {
                    Some(v) => *v,
                    None => {
                        let v = verify_certificate(&w.certificate_pem, &params.ghostkey_master)?;
                        certified.insert(ck, v);
                        v
                    }
                };
                verify_entry(&w.entry, &vk, params)?;
                if w.entry.mainnet_height > floor.saturating_add(WINDOW_BLOCKS) {
                    return Err(format!(
                        "entry dated {} is beyond the window: the floor is {floor}, so the \
                         latest acceptable height is {}",
                        w.entry.mainnet_height,
                        floor.saturating_add(WINDOW_BLOCKS)
                    ));
                }
                self.certificates.insert(ck, w.certificate_pem.clone());
                self.entries.insert(w.entry.key(), w.entry.clone());
            }
        }

        self.normalize();
        Ok(())
    }

    /// Everything this state holds, as a delta.
    pub fn as_delta(&self) -> InboxDelta {
        InboxDelta {
            floor: self.floor.clone(),
            entries: self.entries.values().map(|e| self.wire(e)).collect(),
            tombstones: self.tombstones.values().cloned().collect(),
        }
    }

    /// Merge another whole state into this one.
    pub fn merge(&mut self, params: &InboxParameters, other: &InboxStateV1) -> Result<(), String> {
        self.apply_delta(params, &other.as_delta())
    }

    fn wire(&self, e: &InboxEntry) -> WireEntry {
        WireEntry {
            entry: e.clone(),
            certificate_pem: self.certificates.get(&e.cert).cloned().unwrap_or_default(),
        }
    }

    pub fn summarize(&self) -> InboxSummary {
        InboxSummary {
            floor: self.floor_height(),
            entries: BucketDigest::from_keys(self.entries.keys().map(|k| &k.0)),
            tombstones: BucketDigest::from_keys(self.tombstones.keys().map(|k| &k.0)),
        }
    }

    /// What a peer with summary `old` is missing. `None` when nothing: a
    /// converged peer must be answered with zero bytes, on every heartbeat.
    pub fn delta(&self, old: &InboxSummary) -> Option<InboxDelta> {
        let floor = match (self.floor_height(), old.floor) {
            (Some(mine), Some(theirs)) if mine > theirs => self.floor.clone(),
            (Some(_), None) => self.floor.clone(),
            _ => None,
        };

        let mine = BucketDigest::from_keys(self.entries.keys().map(|k| &k.0));
        let differing = mine.differing_buckets(&old.entries);
        let entries: Vec<WireEntry> = self
            .entries
            .iter()
            .filter(|(k, _)| differing.contains(&BucketDigest::bucket_of(&k.0)))
            .map(|(_, e)| self.wire(e))
            .collect();

        let mine = BucketDigest::from_keys(self.tombstones.keys().map(|k| &k.0));
        let differing = mine.differing_buckets(&old.tombstones);
        let tombstones: Vec<SignedTombstone> = self
            .tombstones
            .iter()
            .filter(|(k, _)| differing.contains(&BucketDigest::bucket_of(&k.0)))
            .map(|(_, t)| t.clone())
            .collect();

        let d = InboxDelta {
            floor,
            entries,
            tombstones,
        };
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    }
}
