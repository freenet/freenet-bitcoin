//! Finding out which contract generation the bridge is actually publishing to.
//!
//! # What goes wrong without this
//!
//! This app embeds the contract WASM and derives addresses from it, so its
//! derivation can never disagree with the bytes it ships. That removes one
//! failure and leaves the other: the bridge may be running *different* bytes.
//! Then the app derives an address nobody writes to, gets an empty contract
//! back, and renders the page it renders for an address that has never been
//! paid. No error, anywhere, and no way for a visitor to tell the difference
//! between "this address is unused", "the bridge is down", and "this page was
//! built against contracts nobody is publishing to".
//!
//! # What this does instead
//!
//! Each bridge signs a [pointer record] naming the code hash it currently
//! publishes to. The record lives at an address derived from the bridge's key
//! and a frozen contract, so it is computable offline and does not move when
//! our contracts re-key. This module reads it and hands the rest of the app a
//! code hash to derive from.
//!
//! When the pointer names a different generation than this build embeds, the
//! app **follows the bridge** and says so. Following adds no trust: the record
//! is signed by the same key that signs every claim shown on the page, and
//! every claim is still re-verified against its own Bitcoin evidence before it
//! is rendered. What following buys is that a stale build keeps working
//! instead of silently showing nothing.
//!
//! When the pointer cannot be read at all, the app falls back to the
//! generation it embeds and says *that*. The fallback is the honest one — it
//! is the only generation this build can name — but it is exactly the case
//! where the page may be reading contracts nobody writes to, so it is never
//! silent.
//!
//! [pointer record]: freenet_bitcoin_generation

use freenet_bitcoin_common::{BitcoinNetwork, BridgeId};
use freenet_bitcoin_generation::{short, Artifact};
use freenet_migrate::pointer::{PointerFloor, PointerOutcome, PointerResolver};
use freenet_stdlib::prelude::ContractInstanceId;

use crate::{config, keys};

/// How the code hash currently in use was arrived at.
#[derive(Clone, PartialEq, Debug)]
pub enum Source {
    /// The bridge's pointer named exactly the generation this build embeds.
    Agreed,
    /// The pointer named a different generation, and we followed it.
    Followed {
        /// What this build ships, and would have used on its own.
        built_for: [u8; 32],
    },
    /// No pointer could be resolved; using the generation this build embeds.
    Fallback(Reason),
    /// The bridge published a tombstone: it is not serving this contract at
    /// all any more. Nothing is derived, because deriving from the record
    /// would mean deriving from 32 zero bytes.
    Withdrawn,
}

/// Why no pointer was resolved. Each maps to a different sentence, because a
/// visitor being told "the bridge has never published one" and "we could not
/// reach it" should not have to guess which happened.
#[derive(Clone, PartialEq, Debug)]
pub enum Reason {
    /// No trusted bridge is configured for this network, so there is no
    /// pointer to look for.
    NoBridge,
    /// The pointer address answered, positively, that nothing is there.
    NeverPublished,
    /// The GET did not come back, or came back with nothing usable.
    Unreachable,
    /// A record was served that this app refused: malformed, wrongly signed,
    /// or superseded.
    Refused(String),
}

/// One artifact's resolution, from "not asked yet" to a code hash.
#[derive(Debug)]
enum Slot {
    Waiting {
        id: ContractInstanceId,
        resolver: Box<PointerResolver>,
        /// True once the GET has been sent, so the watchdog knows what it is
        /// waiting on.
        asked: bool,
    },
    Settled {
        code_hash: [u8; 32],
        source: Source,
    },
}

impl Slot {
    fn settle(&mut self, code_hash: [u8; 32], source: Source) {
        *self = Slot::Settled { code_hash, source };
    }
}

/// Which generation each contract is being read at, for one network.
#[derive(Debug)]
pub struct Generations {
    bridge: Option<BridgeId>,
    address: Slot,
    tip: Slot,
}

impl Default for Generations {
    fn default() -> Self {
        Self::for_network(config::default_network())
    }
}

impl Generations {
    /// Begin resolution for `network`, using the first bridge this build
    /// trusts there.
    ///
    /// Only the first: `trusted_bridges` is part of a contract's parameters,
    /// so two bridges on the list are two co-writers of one contract instance,
    /// and if they were running different generations there would be no single
    /// address to read. Following the first is the honest simplification;
    /// every deployment today lists exactly one.
    pub fn for_network(network: BitcoinNetwork) -> Self {
        let bridge = config::trusted_bridges(network).into_iter().next();
        let Some(bridge) = bridge else {
            return Generations {
                bridge: None,
                address: Slot::Settled {
                    code_hash: keys::embedded_address_code_hash(),
                    source: Source::Fallback(Reason::NoBridge),
                },
                tip: Slot::Settled {
                    code_hash: keys::embedded_tip_code_hash(),
                    source: Source::Fallback(Reason::NoBridge),
                },
            };
        };

        Generations {
            address: slot_for(
                &bridge,
                Artifact::Address,
                keys::embedded_address_code_hash(),
            ),
            tip: slot_for(&bridge, Artifact::Tip, keys::embedded_tip_code_hash()),
            bridge: Some(bridge),
        }
    }

    /// The next pointer this app should GET, if any.
    ///
    /// Resolution is deliberately **sequential**: one pointer GET outstanding
    /// at a time, and no other contract fetched until both have settled. The
    /// node's error replies do not reliably name the contract they are about
    /// — a "not found" arrives as a bare operation error — so the only way to
    /// attribute a failure to a pointer is for exactly one to be in flight.
    /// Two round trips at startup is a cheap price for not mis-attributing a
    /// failure and resolving the wrong generation.
    pub fn next_pointer(&mut self) -> Option<ContractInstanceId> {
        for slot in [&mut self.address, &mut self.tip] {
            if let Slot::Waiting { id, asked, .. } = slot {
                if !*asked {
                    *asked = true;
                    return Some(*id);
                }
                // One already in flight; wait for it.
                return None;
            }
        }
        None
    }

    /// The pointer GET currently outstanding, if any.
    pub fn in_flight(&self) -> Option<ContractInstanceId> {
        for slot in [&self.address, &self.tip] {
            if let Slot::Waiting {
                id, asked: true, ..
            } = slot
            {
                return Some(*id);
            }
        }
        None
    }

    /// Both artifacts have a code hash to derive from.
    pub fn settled(&self) -> bool {
        matches!(self.address, Slot::Settled { .. }) && matches!(self.tip, Slot::Settled { .. })
    }

    /// Deliver a pointer contract's state.
    pub fn on_pointer_state(&mut self, id: ContractInstanceId, bytes: &[u8]) -> bool {
        self.deliver(id, |r| {
            r.on_response(id, bytes);
        })
    }

    /// Deliver a definitive "there is nothing at that address".
    pub fn on_pointer_absent(&mut self, id: ContractInstanceId) -> bool {
        self.deliver(id, |r| {
            r.on_absent(id);
        })
    }

    /// Deliver "we did not hear back", which is never absence.
    pub fn on_pointer_unreachable(&mut self, id: ContractInstanceId) -> bool {
        self.deliver(id, |r| {
            r.on_unreachable(id);
        })
    }

    fn deliver(&mut self, id: ContractInstanceId, feed: impl Fn(&mut PointerResolver)) -> bool {
        for artifact in Artifact::ALL {
            let embedded = embedded_hash(artifact);
            let slot = self.slot_mut(artifact);
            let Slot::Waiting {
                id: slot_id,
                resolver,
                ..
            } = slot
            else {
                continue;
            };
            if *slot_id != id {
                continue;
            }
            feed(resolver);
            let Some(outcome) = resolver.take_outcome() else {
                return false;
            };
            let (code_hash, source) = interpret(outcome, embedded);
            slot.settle(code_hash, source);
            return true;
        }
        false
    }

    fn slot_mut(&mut self, artifact: Artifact) -> &mut Slot {
        match artifact {
            Artifact::Address => &mut self.address,
            Artifact::Tip => &mut self.tip,
        }
    }

    /// The code hash to derive `artifact`'s contract address from.
    ///
    /// Falls back to what this build embeds while still resolving, which only
    /// matters if something derives an address before settlement; the app
    /// deliberately does not.
    pub fn code_hash(&self, artifact: Artifact) -> [u8; 32] {
        match self.slot(artifact) {
            Slot::Settled { code_hash, .. } => *code_hash,
            Slot::Waiting { .. } => embedded_hash(artifact),
        }
    }

    /// Whether `artifact` has a usable address at all. False only for a
    /// withdrawal, where deriving would mean deriving from a tombstone.
    pub fn usable(&self, artifact: Artifact) -> bool {
        !matches!(
            self.slot(artifact),
            Slot::Settled {
                source: Source::Withdrawn,
                ..
            }
        )
    }

    fn slot(&self, artifact: Artifact) -> &Slot {
        match artifact {
            Artifact::Address => &self.address,
            Artifact::Tip => &self.tip,
        }
    }

    fn source(&self, artifact: Artifact) -> Option<&Source> {
        match self.slot(artifact) {
            Slot::Settled { source, .. } => Some(source),
            Slot::Waiting { .. } => None,
        }
    }

    /// What the page should tell the visitor, if anything.
    ///
    /// Empty when everything agrees, which is the common case; a page that
    /// warns about a healthy deployment trains people to ignore the warning.
    pub fn notices(&self, unreadable: Option<&str>) -> Vec<Notice> {
        let mut out = Vec::new();
        if let Some(detail) = unreadable {
            out.push(Notice {
                severity: Severity::Broken,
                headline: "This page cannot read the contracts the bridge is publishing"
                    .to_string(),
                detail: format!(
                    "{detail} The bridge has moved to a contract generation whose state this \
                     build does not understand, so nothing below can be trusted to be complete. \
                     The app needs rebuilding against the contracts the bridge is running."
                ),
            });
        }

        let bridge = self
            .bridge
            .as_ref()
            .map(|b| short(&b.0))
            .unwrap_or_else(|| "nobody".to_string());

        for artifact in Artifact::ALL {
            let Some(source) = self.source(artifact) else {
                continue;
            };
            let current = self.code_hash(artifact);
            match source {
                Source::Agreed => {}
                Source::Followed { built_for } => out.push(Notice {
                    severity: Severity::Stale,
                    headline: format!(
                        "This app was built for a different {} than the bridge is publishing to",
                        artifact.label()
                    ),
                    detail: format!(
                        "Built for generation {}, bridge {bridge} is publishing to {}. \
                         Showing the bridge's, so what you see below is current — but this \
                         build is behind and should be rebuilt.",
                        short(built_for),
                        short(&current),
                    ),
                }),
                Source::Withdrawn => out.push(Notice {
                    severity: Severity::Broken,
                    headline: format!("Bridge {bridge} has withdrawn its {}", artifact.label()),
                    detail:
                        "It signed a record saying it no longer publishes this contract at all. \
                         There is nothing to read, and falling back to an older generation would \
                         resurrect exactly what it retired."
                            .to_string(),
                }),
                Source::Fallback(reason) => out.push(Notice {
                    severity: Severity::Unconfirmed,
                    headline: format!(
                        "Cannot confirm which {} bridge {bridge} is publishing to",
                        artifact.label()
                    ),
                    detail: format!(
                        "{} Reading generation {} — the one this app was built with. If it is not \
                         the one the bridge is writing to, everything below will look exactly \
                         like an address that has never been used.",
                        reason.sentence(),
                        short(&current),
                    ),
                }),
            }
        }
        out
    }
}

impl Reason {
    fn sentence(&self) -> &'static str {
        match self {
            Reason::NoBridge => "No bridge is configured for this network.",
            Reason::NeverPublished => "This bridge has never published a generation pointer.",
            Reason::Unreachable => "Its generation pointer did not answer.",
            Reason::Refused(_) => "The record served at its pointer was refused.",
        }
    }
}

/// How much a notice should shout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    /// Working, but this build is behind the bridge.
    Stale,
    /// Might be working; nothing confirms it either way.
    Unconfirmed,
    /// Not working, and the page below cannot be relied on.
    Broken,
}

impl Severity {
    pub fn css(self) -> &'static str {
        match self {
            Severity::Stale => "notice notice-stale",
            Severity::Unconfirmed => "notice notice-unconfirmed",
            Severity::Broken => "notice notice-broken",
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Notice {
    pub severity: Severity,
    pub headline: String,
    pub detail: String,
}

/// What this build ships for `artifact`, and would derive from unaided.
fn embedded_hash(artifact: Artifact) -> [u8; 32] {
    match artifact {
        Artifact::Address => keys::embedded_address_code_hash(),
        Artifact::Tip => keys::embedded_tip_code_hash(),
    }
}

fn slot_for(bridge: &BridgeId, artifact: Artifact, embedded: [u8; 32]) -> Slot {
    // A reader with no durable storage starts from `never_resolved`. It cannot
    // seed a build-time floor because it does not know the bridge's version at
    // build time — only its own code hash — and `PointerFloor::at` needs both.
    // The exposure is that a peer serving a genuine but superseded record can
    // point this page at an older generation of our own contracts. That is
    // stale display, not forgery: whatever generation is read, every claim in
    // it is signed by this same bridge and re-checked against its own Bitcoin
    // evidence before it reaches the screen.
    match freenet_bitcoin_generation::resolver(bridge, artifact, PointerFloor::never_resolved()) {
        Ok(mut resolver) => {
            let id = match resolver.next_action() {
                freenet_migrate::Step::Get(id) => id,
                freenet_migrate::Step::Done => {
                    return Slot::Settled {
                        code_hash: embedded,
                        source: Source::Fallback(Reason::Unreachable),
                    }
                }
            };
            // `next_action` marks the GET outstanding, but the app has not sent
            // it yet; `asked` tracks the app's side so the sequencing above can
            // issue exactly one at a time.
            Slot::Waiting {
                id,
                resolver: Box::new(resolver),
                asked: false,
            }
        }
        Err(e) => Slot::Settled {
            code_hash: embedded,
            source: Source::Fallback(Reason::Refused(e.to_string())),
        },
    }
}

/// Turn a resolver outcome into a code hash and an explanation.
///
/// The rule `freenet-migrate` insists on: only `NeverPublished` — a positive
/// answer that nothing was ever published — permits falling back to a
/// build-time constant. Everything else must keep whatever was last resolved.
/// A page holds nothing from a previous run, so its "last resolved" is the
/// generation it embeds, and it uses that while saying plainly that nothing
/// confirms it. The alternative is a blank screen with no explanation, which
/// is the failure this whole module exists to remove.
fn interpret(
    outcome: Result<PointerOutcome, freenet_migrate::pointer::PointerError>,
    embedded: [u8; 32],
) -> ([u8; 32], Source) {
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => return (embedded, Source::Fallback(Reason::Refused(e.to_string()))),
    };
    match outcome {
        PointerOutcome::Resolved(r) | PointerOutcome::Unchanged(r) => {
            let hash = r.code_hash();
            if hash == embedded {
                (hash, Source::Agreed)
            } else {
                (
                    hash,
                    Source::Followed {
                        built_for: embedded,
                    },
                )
            }
        }
        PointerOutcome::Withdrawn { .. } => (embedded, Source::Withdrawn),
        PointerOutcome::NeverPublished => (embedded, Source::Fallback(Reason::NeverPublished)),
        PointerOutcome::Unavailable => (embedded, Source::Fallback(Reason::Unreachable)),
        PointerOutcome::Stale { served, floor } => (
            embedded,
            Source::Fallback(Reason::Refused(format!(
                "version {served} does not supersede {floor}"
            ))),
        ),
        PointerOutcome::CompetingRecord { version, .. } => (
            embedded,
            Source::Fallback(Reason::Refused(format!(
                "two different records at version {version}"
            ))),
        ),
        // `PointerOutcome` is #[non_exhaustive]; a variant added later must
        // land somewhere that does not claim confirmation it does not have.
        _ => (embedded, Source::Fallback(Reason::Unreachable)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug in one test: a bridge on a different generation must produce a
    /// notice, not silence.
    #[test]
    fn following_a_different_generation_is_announced() {
        let mut g = Generations::for_network(BitcoinNetwork::Signet);
        assert!(!g.settled());
        let other = [42u8; 32];
        g.tip.settle(
            other,
            Source::Followed {
                built_for: keys::embedded_tip_code_hash(),
            },
        );
        g.address
            .settle(keys::embedded_address_code_hash(), Source::Agreed);

        assert_eq!(g.code_hash(Artifact::Tip), other, "must follow the bridge");
        let notices = g.notices(None);
        assert_eq!(notices.len(), 1, "exactly the tip contract is out of step");
        assert_eq!(notices[0].severity, Severity::Stale);
        assert!(
            notices[0].headline.contains("built for a different"),
            "the headline must name the actual problem: {}",
            notices[0].headline
        );
    }

    /// Agreement must be silent. A page that warns when everything is fine
    /// teaches people to ignore the warning that matters.
    #[test]
    fn agreement_says_nothing() {
        let mut g = Generations::for_network(BitcoinNetwork::Signet);
        g.address
            .settle(keys::embedded_address_code_hash(), Source::Agreed);
        g.tip.settle(keys::embedded_tip_code_hash(), Source::Agreed);
        assert!(g.settled());
        assert!(g.notices(None).is_empty());
    }

    /// An unreachable pointer must not pass as confirmation. This is the case
    /// that used to render a blank page.
    #[test]
    fn an_unreachable_pointer_is_reported_not_assumed() {
        let (hash, source) = interpret(Ok(PointerOutcome::Unavailable), [1u8; 32]);
        assert_eq!(hash, [1u8; 32], "falls back to what this build embeds");
        assert_eq!(source, Source::Fallback(Reason::Unreachable));

        let mut g = Generations::for_network(BitcoinNetwork::Signet);
        g.address.settle([1u8; 32], Source::Agreed);
        g.tip.settle(hash, source);
        let notices = g.notices(None);
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].severity, Severity::Unconfirmed);
        assert!(notices[0].detail.contains("did not answer"));
    }

    /// A withdrawal must not silently resurrect the generation this build
    /// happens to embed.
    #[test]
    fn a_withdrawal_stops_the_page_using_the_contract() {
        let mut g = Generations::for_network(BitcoinNetwork::Signet);
        g.address
            .settle(keys::embedded_address_code_hash(), Source::Agreed);
        g.tip
            .settle(keys::embedded_tip_code_hash(), Source::Withdrawn);
        assert!(!g.usable(Artifact::Tip));
        assert!(g.usable(Artifact::Address));
        assert_eq!(g.notices(None)[0].severity, Severity::Broken);
    }

    /// A network with no configured bridge has nothing to resolve, and must
    /// not sit waiting for a pointer that will never be asked for.
    #[test]
    fn a_network_with_no_bridge_settles_immediately() {
        let g = Generations::for_network(BitcoinNetwork::Regtest);
        let mut g = g;
        assert!(g.settled());
        assert_eq!(g.next_pointer(), None, "nothing to ask for");
        assert_eq!(g.notices(None).len(), 2, "one per artifact");
    }

    /// Exactly one pointer GET at a time, because a failure reply cannot
    /// reliably be attributed to a contract otherwise.
    #[test]
    fn pointers_are_fetched_one_at_a_time() {
        let mut g = Generations::for_network(BitcoinNetwork::Signet);
        let first = g.next_pointer().expect("a pointer to fetch");
        assert_eq!(
            g.next_pointer(),
            None,
            "must not ask for the second while the first is outstanding"
        );
        assert_eq!(g.in_flight(), Some(first));

        g.on_pointer_absent(first);
        let second = g.next_pointer().expect("now the second");
        assert_ne!(first, second);
    }

    /// Unparseable state is its own, louder failure: following a pointer can
    /// land on a generation whose wire format moved, and that is the one case
    /// where the page genuinely cannot show the data.
    #[test]
    fn unreadable_state_is_the_loudest_notice() {
        let mut g = Generations::for_network(BitcoinNetwork::Signet);
        g.address
            .settle(keys::embedded_address_code_hash(), Source::Agreed);
        g.tip.settle(keys::embedded_tip_code_hash(), Source::Agreed);
        let notices = g.notices(Some(
            "The tip contract returned 412 bytes this build cannot decode.",
        ));
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].severity, Severity::Broken);
    }
}
