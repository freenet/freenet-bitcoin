//! Bitcoin on Freenet — a verifiable address viewer.
//!
//! # What this is for
//!
//! Not a block explorer. An explorer asks you to believe it; this shows you
//! Bitcoin facts that arrived over Freenet **and re-checks them in your
//! browser** against the transaction, the Merkle branch and the headers'
//! proof-of-work. The bridge that observed them is left trusted for
//! availability and for which fork is the best chain, and for nothing else.
//!
//! It is deliberately useful with nothing watched and no credential: the chain
//! tip, recent blocks and any address you care to look up are all public.

mod app;
mod config;
mod keys;
mod node;
mod state;
mod verify;

fn main() {
    dioxus::launch(app::App);
}
