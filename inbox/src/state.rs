//! Inbox state, its merge, and synchronization.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

use crate::{
    canonical_certificate, cert_key, verify_certificate, verify_entry, BatchKey, ByteBuf, CertKey,
    EntryKey, GhostkeyId, InboxEntry, InboxEntryBody, InboxParameters, RemovalBatch, RemovedPrefix,
    SignedFloor, MAX_ENTRIES, MAX_ENTRIES_PER_GHOSTKEY, MAX_REMOVAL_BATCHES, MAX_REMOVED,
    WINDOW_BLOCKS,
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
    /// Certificates in canonical form, stored once and shared by every entry
    /// of one Ghost Key.
    pub certificates: BTreeMap<CertKey, String>,
    /// Requests not yet read.
    pub entries: BTreeMap<EntryKey, InboxEntry>,
    /// What the bridge has read. See [`RemovalBatch`].
    pub removals: BTreeMap<BatchKey, RemovalBatch>,
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
    /// lifts out the values the state is ordered by, and puts the
    /// certificate in the one form the state holds.
    pub fn from_sign_result(
        certificate_pem: String,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, String> {
        let certificate_pem = canonical_certificate(&certificate_pem)?;
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
    pub removals: Vec<RemovalBatch>,
}

impl InboxDelta {
    pub fn is_empty(&self) -> bool {
        self.floor.is_none() && self.entries.is_empty() && self.removals.is_empty()
    }

    /// What a sender sends: its entry, with the floor it read from the inbox.
    ///
    /// A peer whose floor lags the sender's takes the floor first and then
    /// the entry, so the entry is admitted rather than skipped as beyond that
    /// peer's window.
    pub fn submission(floor: Option<SignedFloor>, entry: WireEntry) -> Self {
        InboxDelta {
            floor,
            entries: vec![entry],
            removals: vec![],
        }
    }
}

/// Buckets in a summary digest.
const BUCKETS: usize = 16;
const BUCKET_DOMAIN: &str = "freenet-bitcoin/inbox-bucket/v1";

/// A fixed-size digest of a set of record keys: 16 buckets, each a 128-bit
/// BLAKE3 hash of the sorted keys that fall in it.
///
/// Deliberately not the XOR buckets `freenet_bitcoin_common::digest` uses for
/// claims. Those are sound there because every claim is bridge-signed, so
/// nobody chooses the keys. Here a sender chooses its entry's key freely, by
/// sealing again, and four chosen keys that XOR to zero in one bucket (a
/// generalised birthday search, about 2^22 work) would give two peers equal
/// summaries of different states, which would then never reconcile. A hash of
/// the sorted keys needs a collision search instead: 128 bits, because the
/// attacker controls both sides of the comparison.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Buckets(pub [[u8; 16]; BUCKETS]);

impl Buckets {
    fn bucket_of(key: &[u8; 32]) -> usize {
        (key[0] >> 4) as usize
    }

    /// Keys must arrive in ascending order, as a `BTreeMap` yields them.
    fn of<'a>(keys: impl Iterator<Item = &'a [u8; 32]>) -> Self {
        let mut hashers: Vec<blake3::Hasher> = (0..BUCKETS)
            .map(|i| {
                let mut h = blake3::Hasher::new_derive_key(BUCKET_DOMAIN);
                h.update(&[i as u8]);
                h
            })
            .collect();
        for k in keys {
            hashers[Self::bucket_of(k)].update(k);
        }
        let mut out = [[0u8; 16]; BUCKETS];
        for (slot, h) in out.iter_mut().zip(hashers) {
            slot.copy_from_slice(&h.finalize().as_bytes()[..16]);
        }
        Buckets(out)
    }

    fn differs(&self, other: &Buckets, key: &[u8; 32]) -> bool {
        let b = Self::bucket_of(key);
        self.0[b] != other.0[b]
    }
}

impl Serialize for Buckets {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0.as_flattened())
    }
}

impl<'de> Deserialize<'de> for Buckets {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(d)?;
        if bytes.len() != BUCKETS * 16 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"256 bytes of bucket digests",
            ));
        }
        let mut out = [[0u8; 16]; BUCKETS];
        for (slot, chunk) in out.iter_mut().zip(bytes.chunks_exact(16)) {
            slot.copy_from_slice(chunk);
        }
        Ok(Buckets(out))
    }
}

/// What a peer holds, in a fixed size whatever the inbox holds.
///
/// Bucketed, so `delta` may resend a whole bucket rather than one record. That
/// is sound only because applying an already-held record changes nothing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct InboxSummary {
    pub floor: Option<u32>,
    pub entries: Buckets,
    pub removals: Buckets,
}

/// One entry's place in the caps' order: (height, key, Ghost Key).
type Ranked = (u32, EntryKey, GhostkeyId);

impl InboxStateV1 {
    pub fn floor_height(&self) -> Option<u32> {
        self.floor.as_ref().map(|f| f.height)
    }

    /// Every (height, prefix) a removal batch names. A batch removes entries
    /// of its own height only, so it and the entries it removes leave the
    /// window together, and a batch can never hide an entry that outlives it.
    fn removed(&self) -> BTreeSet<(u32, RemovedPrefix)> {
        self.removals
            .values()
            .flat_map(|b| b.prefixes().map(move |p| (b.height, p)))
            .collect()
    }

    /// Whether the bridge has read the entry with this key, dated `height`,
    /// which is how a sender learns its request arrived. Holds until the
    /// floor passes that height; after that the entry is gone either way.
    pub fn is_removed(&self, key: &EntryKey, height: u32) -> bool {
        let p = key.removal_prefix();
        self.removals
            .values()
            .any(|b| b.height == height && b.prefixes().any(|q| q == p))
    }

    /// Drop every batch another batch covers. Of any set of batches, the ones
    /// nothing covers are the same whichever order they arrived in.
    fn drop_covered(&mut self) {
        let covered: Vec<BatchKey> = self
            .removals
            .iter()
            .filter(|(k, b)| {
                self.removals
                    .iter()
                    .any(|(other, c)| other != *k && b.covered_by(c))
            })
            .map(|(k, _)| *k)
            .collect();
        for k in covered {
            self.removals.remove(&k);
        }
    }

    /// Prefixes named across all batches, counting a prefix once per batch
    /// that names it. What [`MAX_REMOVED`] bounds.
    fn removed_count(&self) -> usize {
        self.removals.values().map(RemovalBatch::len).sum()
    }

    /// Full verification of a state: every signature and identity, the window,
    /// the caps, and that it is in normal form. A state honest merges produce
    /// always passes.
    pub fn verify(&self, params: &InboxParameters) -> Result<(), String> {
        let Some(floor) = &self.floor else {
            if self.entries.is_empty() && self.removals.is_empty() && self.certificates.is_empty() {
                return Ok(());
            }
            return Err("the inbox holds records but its bridge has not opened it".into());
        };
        floor.verify(&params.bridge)?;
        let floor = floor.height;

        // Everything structural first, and the certificates' RSA checks last,
        // once their number is known to be bounded by the entries. Every
        // certificate is public, so a state carrying many that nothing uses
        // would otherwise cost each peer an RSA check apiece before failing.
        if self.entries.len() > MAX_ENTRIES {
            return Err(format!(
                "inbox holds {} entries, cap is {MAX_ENTRIES}",
                self.entries.len()
            ));
        }
        if self.removals.len() > MAX_REMOVAL_BATCHES {
            return Err(format!(
                "inbox holds {} removal batches, cap is {MAX_REMOVAL_BATCHES}",
                self.removals.len()
            ));
        }
        // Bounded before the pairwise check below, which costs the number of
        // batches squared times their length, and before any signature: an
        // unsigned state can carry batches built to make every comparison
        // walk to the end.
        let removed_count = self.removed_count();
        if removed_count > MAX_REMOVED {
            return Err(format!(
                "inbox names {removed_count} removed entries, cap is {MAX_REMOVED}"
            ));
        }
        for (k, b) in &self.removals {
            b.check_shape()?;
            if b.key() != *k {
                return Err("removal batch filed under a key that is not its digest".into());
            }
            if b.height < floor {
                return Err("removal batch below the floor: state is not in normal form".into());
            }
            if b.height > floor.saturating_add(WINDOW_BLOCKS) {
                return Err("removal batch dated beyond the window above the floor".into());
            }
            if self
                .removals
                .iter()
                .any(|(other, c)| other != k && b.covered_by(c))
            {
                return Err("a removal batch another covers is still present".into());
            }
        }
        for b in self.removals.values() {
            b.verify(&params.bridge)?;
        }
        let removed = self.removed();

        let mut referenced: BTreeSet<CertKey> = BTreeSet::new();
        let mut per: BTreeMap<GhostkeyId, usize> = BTreeMap::new();
        for (k, e) in &self.entries {
            if e.key() != *k {
                return Err("entry filed under a key that is not its digest".into());
            }
            if !self.certificates.contains_key(&e.cert) {
                return Err("entry references a certificate the state does not hold".into());
            }
            if e.mainnet_height < floor {
                return Err("entry below the floor: state is not in normal form".into());
            }
            if e.mainnet_height > floor.saturating_add(WINDOW_BLOCKS) {
                return Err("entry dated beyond the window above the floor".into());
            }
            if removed.contains(&(e.mainnet_height, k.removal_prefix())) {
                return Err("a removed entry is still present".into());
            }
            referenced.insert(e.cert);
            let c = per.entry(e.ghostkey).or_insert(0);
            *c += 1;
            if *c > MAX_ENTRIES_PER_GHOSTKEY {
                return Err(format!(
                    "a Ghost Key holds more than {MAX_ENTRIES_PER_GHOSTKEY} entries"
                ));
            }
        }
        if referenced.len() != self.certificates.len() {
            return Err("state holds a certificate no entry uses".into());
        }

        // The expensive half: at most one RSA check per entry.
        let mut certified: BTreeMap<CertKey, VerifyingKey> = BTreeMap::new();
        for (k, pem) in &self.certificates {
            if cert_key(pem) != *k {
                return Err("certificate filed under a key that is not its digest".into());
            }
            if canonical_certificate(pem)? != *pem {
                return Err("certificate is not in its canonical form".into());
            }
            certified.insert(*k, verify_certificate(pem, &params.ghostkey_master)?);
        }
        for e in self.entries.values() {
            verify_entry(e, &certified[&e.cert], params)?;
        }
        Ok(())
    }

    /// Bring the state to normal form. Deterministic, and a function of the
    /// records present and the floor alone, which is what lets two peers that
    /// exchange state reach the same bytes.
    ///
    /// # What commutes and what does not
    ///
    /// Everything below the floor goes, and so does every batch another batch
    /// covers: of any set of batches, the ones nothing covers are the same
    /// whichever order they arrived in. Removed entries go next, and only then
    /// are the caps applied, to the entries still waiting. Entries rank newest
    /// first (height descending, then key). Each Ghost Key keeps its best
    /// [`MAX_ENTRIES_PER_GHOSTKEY`], and of those the best [`MAX_ENTRIES`]
    /// survive.
    ///
    /// Because removal happens before the caps, a removal frees its entry's
    /// place, and an entry discarded earlier for lack of room could now fit.
    /// When the caps overflow, the merge is therefore not associative: which
    /// entry survives can depend on whether a peer saw the removal before or
    /// after the entry it displaced. Below the caps nothing is discarded and
    /// the merge laws hold exactly. See the crate documentation, and the tests,
    /// which assert both halves on exact bytes.
    pub fn normalize(&mut self) {
        let Some(floor) = self.floor_height() else {
            self.certificates.clear();
            self.entries.clear();
            self.removals.clear();
            return;
        };

        self.entries.retain(|_, e| e.mainnet_height >= floor);
        self.removals.retain(|_, b| b.height >= floor);
        self.drop_covered();

        let removed = self.removed();
        self.entries
            .retain(|k, e| !removed.contains(&(e.mainnet_height, k.removal_prefix())));

        let mut ranked: Vec<Ranked> = self
            .entries
            .iter()
            .map(|(k, e)| (e.mainnet_height, *k, e.ghostkey))
            .collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut per: BTreeMap<GhostkeyId, usize> = BTreeMap::new();
        let mut kept: BTreeSet<EntryKey> = BTreeSet::new();
        for (_, k, g) in &ranked {
            let c = per.entry(*g).or_insert(0);
            if *c >= MAX_ENTRIES_PER_GHOSTKEY || kept.len() >= MAX_ENTRIES {
                continue;
            }
            *c += 1;
            kept.insert(*k);
        }
        self.entries.retain(|k, _| kept.contains(k));

        let used: BTreeSet<CertKey> = self.entries.values().map(|e| e.cert).collect();
        self.certificates.retain(|k, _| used.contains(k));
    }

    /// Apply changes from a peer or a sender. Every incoming record is
    /// verified before it is admitted, except one already held byte for byte,
    /// which an earlier check covered.
    ///
    /// All or nothing: a delta refused part-way leaves the state as it was.
    /// Whether a delta carrying an invalid batch is refused can depend on what
    /// this peer holds, since a batch covered by one held here is passed over
    /// unchecked; that changes which invalid deltas are refused, never what a
    /// valid one does.
    /// An entry or batch outside the window is dropped, never an error. Below
    /// it, a peer whose floor was lower sent it. Above it, this peer's floor
    /// lags the sender's: every valid state's records lie within its own
    /// floor's window, and a merge only raises the floor, so a whole state
    /// never carries one, but a delta can reach a peer before the floor that
    /// admits it does. Deltas carry that floor with their records (see `delta`
    /// and `submission`), so this is rare, and refusing the rest of the delta
    /// for it would lose more than it protects.
    pub fn apply_delta(
        &mut self,
        params: &InboxParameters,
        delta: &InboxDelta,
    ) -> Result<(), String> {
        // Bounded before anything is verified. Each record is checked on its
        // own, so without this a delta's cost would follow its size rather
        // than the caps; removals are public, so anyone could otherwise send
        // thousands of copies of one. (Decoding the delta, which happens
        // before this, costs time in proportion to its size, which only the
        // node's own message limit bounds.)
        if delta.entries.len() > MAX_ENTRIES || delta.removals.len() > MAX_REMOVAL_BATCHES {
            return Err(format!(
                "a delta may carry at most {MAX_ENTRIES} entries and \
                 {MAX_REMOVAL_BATCHES} removal batches"
            ));
        }
        // An honest delta comes from a state in normal form, or is one
        // sender's submission, so it never carries more entries from one Ghost
        // Key than a state may hold. Refusing more before anything is verified
        // keeps one Ghost Key from making every peer check a hundred of its
        // entries per delta. The key counted is the one each entry claims; an
        // entry that claims another fails `verify_entry` below.
        let mut per: BTreeMap<GhostkeyId, usize> = BTreeMap::new();
        for w in &delta.entries {
            let c = per.entry(w.entry.ghostkey).or_insert(0);
            *c += 1;
            if *c > MAX_ENTRIES_PER_GHOSTKEY {
                return Err(format!(
                    "a delta may carry at most {MAX_ENTRIES_PER_GHOSTKEY} entries from one Ghost Key"
                ));
            }
        }

        let mut next = self.clone();

        if let Some(f) = &delta.floor {
            if next.floor.as_ref() != Some(f) {
                f.verify(&params.bridge)?;
                let adopt = match &next.floor {
                    None => true,
                    Some(cur) => {
                        f.height > cur.height
                            || (f.height == cur.height && f.signature < cur.signature)
                    }
                };
                if adopt {
                    next.floor = Some(f.clone());
                }
            }
        }

        // Batches the floor has passed go first. A batch names entries of its
        // own height only, so one below the floor names nothing in the window
        // and this changes no result; it keeps them out of the work below.
        if let Some(floor) = next.floor_height() {
            next.removals.retain(|_, b| b.height >= floor);
        }

        if !delta.removals.is_empty() {
            let floor = next
                .floor_height()
                .ok_or("the inbox is not open yet: its bridge has not set a floor")?;
            for b in &delta.removals {
                b.check_shape()?;
                let key = b.key();
                if next.removals.get(&key) == Some(b)
                    || b.height < floor
                    || b.height > floor.saturating_add(WINDOW_BLOCKS)
                    || next
                        .removals
                        .iter()
                        .any(|(held, c)| *held != key && b.covered_by(c))
                {
                    // Held already, outside this peer's window (see above), or
                    // covered by a batch already held, which would drop it
                    // again: nothing it could change, so nothing to verify.
                    // Every superseded batch stays validly signed and public,
                    // so without the last test anyone could make each peer
                    // verify them again and again.
                    continue;
                }
                b.verify(&params.bridge)?;
                let keep_existing = next
                    .removals
                    .get(&key)
                    .is_some_and(|cur| cur.signature <= b.signature);
                if !keep_existing {
                    next.removals.insert(key, b.clone());
                }
            }
            // Before the removed set is built from them below, so an entry is
            // skipped as removed only on the strength of a batch the result
            // keeps.
            next.drop_covered();
        }

        if !delta.entries.is_empty() {
            let floor = next
                .floor_height()
                .ok_or("the inbox is not open yet: its bridge has not set a floor")?;
            let removed = next.removed();
            let mut certified: BTreeMap<CertKey, VerifyingKey> = BTreeMap::new();
            for w in &delta.entries {
                let key = w.entry.key();
                if next.entries.get(&key) == Some(&w.entry)
                    || removed.contains(&(w.entry.mainnet_height, key.removal_prefix()))
                    || w.entry.mainnet_height < floor
                    || w.entry.mainnet_height > floor.saturating_add(WINDOW_BLOCKS)
                {
                    // Held already, removed already, or outside this peer's
                    // window: nothing this entry could change, so nothing to
                    // check. Above the window means this peer's floor lags the
                    // sender's; the entry comes again once it catches up, and
                    // the rest of the delta is not refused on its account.
                    continue;
                }
                let pem = canonical_certificate(&w.certificate_pem)?;
                let ck = cert_key(&pem);
                if ck != w.entry.cert {
                    return Err("entry names a different certificate than it carries".into());
                }
                let vk = match certified.get(&ck) {
                    Some(v) => *v,
                    None => {
                        let v = verify_certificate(&pem, &params.ghostkey_master)?;
                        certified.insert(ck, v);
                        v
                    }
                };
                verify_entry(&w.entry, &vk, params)?;
                next.certificates.insert(ck, pem);
                next.entries.insert(key, w.entry.clone());
            }
        }

        next.normalize();

        // Checked after normalizing, so batches the floor passed and batches
        // another covers do not count. Only the bridge signs removals, and it
        // keeps to half of each bound, so an honest inbox never gets here.
        if next.removals.len() > MAX_REMOVAL_BATCHES {
            return Err(format!(
                "the inbox would hold {} removal batches, cap is {MAX_REMOVAL_BATCHES}",
                next.removals.len()
            ));
        }
        let removed_count = next.removed_count();
        if removed_count > MAX_REMOVED {
            return Err(format!(
                "the inbox would name {removed_count} removed entries, cap is {MAX_REMOVED}"
            ));
        }

        *self = next;
        Ok(())
    }

    /// Decode a state, refusing any encoding but its one canonical form.
    ///
    /// Peers decide they agree by comparing bytes, so a re-encoded copy of a
    /// valid state (a byte string sent as an array, a non-minimal integer)
    /// would sit beside the canonical one with an identical summary and never
    /// be healed. Zero bytes is the state of an inbox nobody has written to.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let state: Self = from_cbor(bytes)?;
        if freenet_bitcoin_common::to_cbor(&state)? != bytes {
            return Err("inbox state is not in its canonical encoding".into());
        }
        Ok(state)
    }

    /// The entries whose certificate and signature check out, each on its own.
    ///
    /// For a reader that must act on entries even when the state as a whole
    /// does not pass [`Self::verify`], as a bridge must when its compiled rules
    /// and the contract its node runs disagree: one bad record, or a cap the
    /// two builds count differently, must not stop it reading every good one.
    /// Removed entries are left out.
    pub fn verified_entries(&self, params: &InboxParameters) -> Vec<(EntryKey, &InboxEntry)> {
        let removed = self.removed();
        let mut certified: BTreeMap<CertKey, Option<VerifyingKey>> = BTreeMap::new();
        let mut out = Vec::new();
        for (k, e) in &self.entries {
            if e.key() != *k || removed.contains(&(e.mainnet_height, k.removal_prefix())) {
                continue;
            }
            let vk = *certified.entry(e.cert).or_insert_with(|| {
                let pem = self.certificates.get(&e.cert)?;
                if cert_key(pem) != e.cert {
                    return None;
                }
                verify_certificate(pem, &params.ghostkey_master).ok()
            });
            if let Some(vk) = vk {
                if verify_entry(e, &vk, params).is_ok() {
                    out.push((*k, e));
                }
            }
        }
        out
    }

    /// Everything this state holds, as a delta.
    pub fn as_delta(&self) -> InboxDelta {
        InboxDelta {
            floor: self.floor.clone(),
            entries: self.entries.values().map(|e| self.wire(e)).collect(),
            removals: self.removals.values().cloned().collect(),
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
            entries: Buckets::of(self.entries.keys().map(|k| &k.0)),
            removals: Buckets::of(self.removals.keys().map(|k| &k.0)),
        }
    }

    /// What a peer with summary `old` is missing. `None` when nothing: a
    /// converged peer must be answered with zero bytes, on every heartbeat.
    pub fn delta(&self, old: &InboxSummary) -> Option<InboxDelta> {
        let floor_is_ahead = match (self.floor_height(), old.floor) {
            (Some(mine), Some(theirs)) => mine > theirs,
            (Some(_), None) => true,
            _ => false,
        };

        let mine = Buckets::of(self.entries.keys().map(|k| &k.0));
        let entries: Vec<WireEntry> = self
            .entries
            .iter()
            .filter(|(k, _)| mine.differs(&old.entries, &k.0))
            .map(|(_, e)| self.wire(e))
            .collect();

        let mine = Buckets::of(self.removals.keys().map(|k| &k.0));
        let removals: Vec<RemovalBatch> = self
            .removals
            .iter()
            .filter(|(k, _)| mine.differs(&old.removals, &k.0))
            .map(|(_, b)| b.clone())
            .collect();

        // The floor goes with any record sent, not only when this peer's is
        // ahead by the summary. A peer that missed a floor broadcast looks
        // current to a sender that recorded the broadcast as delivered, and
        // would otherwise skip a record dated in the window of the floor it
        // missed, with nothing to prompt a repair.
        let floor = if floor_is_ahead || !entries.is_empty() || !removals.is_empty() {
            self.floor.clone()
        } else {
            None
        };
        let d = InboxDelta {
            floor,
            entries,
            removals,
        };
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    }
}
