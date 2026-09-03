#![allow(unexpected_cfgs)]
//! A generic Freenet contract holding bridge-signed Bitcoin observations for
//! one output script.
//!
//! One instance per `(network, scriptPubKey)`. The contract is a distributed
//! index shard for Bitcoin activity involving that destination and nothing
//! else: it does not know who watches the script, who owns it, who asked a
//! bridge to synchronize it, or why anybody cares. Those facts exist nowhere
//! in Freenet by design.
//!
//! Validity is `verify`: every claim must be signed by a bridge this instance
//! trusts, and must name this instance's script and network. The merge is set
//! union over a digest-keyed map plus a per-bridge maximum, which is
//! associative, commutative and idempotent -- see the tests in
//! `freenet_bitcoin_common::address_state`.
use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::*;

use freenet_bitcoin_common::address_state::{BitcoinAddressStateV1, BitcoinAddressStateV1Delta, BitcoinAddressStateV1Summary};
use freenet_bitcoin_common::BitcoinAddressParameters;

fn decode_params(p: &Parameters<'static>) -> Result<BitcoinAddressParameters, ContractError> {
    from_reader::<BitcoinAddressParameters, &[u8]>(p.as_ref()).map_err(|e| ContractError::Deser(e.to_string()))
}

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let params = decode_params(&parameters)?;
        let st = from_reader::<BitcoinAddressStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        st.verify(&st, &params)
            .map(|_| ValidateResult::Valid)
            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("state verification failed: {e}"),
            })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = decode_params(&parameters)?;
        let mut st = if state.as_ref().is_empty() {
            BitcoinAddressStateV1::default()
        } else {
            from_reader::<BitcoinAddressStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let incoming = from_reader::<BitcoinAddressStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.merge(&st.clone(), &params, &incoming).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                    })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<BitcoinAddressStateV1Delta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.apply_delta(&st.clone(), &params, &Some(delta)).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                    })?;
                }
                UpdateData::StateAndDelta { state: s, delta: d } => {
                    let incoming = from_reader::<BitcoinAddressStateV1, &[u8]>(s.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.merge(&st.clone(), &params, &incoming).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                    })?;
                    if !d.as_ref().is_empty() {
                        let delta = from_reader::<BitcoinAddressStateV1Delta, &[u8]>(d.as_ref())
                            .map_err(|e| ContractError::Deser(e.to_string()))?;
                        st.apply_delta(&st.clone(), &params, &Some(delta)).map_err(|e| {
                            ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                        })?;
                    }
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }

        let mut out = vec![];
        into_writer(&st, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(UpdateModification::valid(out.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let params = decode_params(&parameters)?;
        let st = from_reader::<BitcoinAddressStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let mut out = vec![];
        into_writer(&st.summarize(&st, &params), &mut out)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(out))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let params = decode_params(&parameters)?;
        let st = from_reader::<BitcoinAddressStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // An empty summary means the peer holds nothing yet, so it needs
        // everything -- the default summary produces exactly that delta.
        let old = if summary.as_ref().is_empty() {
            // The macro-generated summary type has no Default, and inventing
            // one would risk it disagreeing with what an empty state actually
            // summarizes to. Summarize an empty state instead: that is by
            // construction the summary of a peer holding nothing.
            let empty = BitcoinAddressStateV1::default();
            empty.summarize(&empty, &params)
        } else {
            from_reader::<BitcoinAddressStateV1Summary, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
        match st.delta(&st, &params, &old) {
            Some(delta) => {
                let mut out = vec![];
                into_writer(&delta, &mut out)
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(out))
            }
            // Zero bytes, not an encoded empty struct: reconciling with an
            // already-converged peer must cost nothing, and this runs on every
            // anti-entropy heartbeat forever.
            None => Ok(StateDelta::from(vec![])),
        }
    }
}
