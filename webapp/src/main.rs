//! Bitcoin on Freenet — a verifiable address viewer.
//!
//! # What this is for
//!
//! Not a block explorer. It shows Bitcoin observations that arrived over
//! Freenet **and re-checks them in your browser** against the transaction, the
//! Merkle branch and the target each header names — so what is displayed is
//! the result of that check rather than a restatement of what a bridge said.
//!
//! The bridge is still trusted, and for the thing that matters most: which
//! blocks are on Bitcoin. Nothing here anchors a header to the real chain, so
//! the re-check establishes that the evidence is self-consistent and pays the
//! script it says it pays — not that the payment happened. See
//! `freenet_bitcoin_common::spv` for the boundary in full.
//!
//! It is deliberately useful with nothing watched and no credential: the chain
//! tip, recent blocks and any address you care to look up are all public.

mod address;
mod app;
mod config;
mod keys;
mod node;
mod state;
mod verify;

fn main() {
    dioxus::launch(app::App);
}
