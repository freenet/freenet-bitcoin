#![allow(unexpected_cfgs)]
//! A generic Freenet contract holding a public Bitcoin chain-tip view for one
//! network.
//!
//! One instance per network. It exists so that confirmation depth can be
//! computed without every address contract duplicating the global chain tip,
//! and so an application's first screen can show live Bitcoin data before the
//! user has watched anything or authenticated with anything.
use ciborium::{de::from_reader, ser::into_writer};
use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::*;

use freenet_bitcoin_common::tip_state::{BitcoinTipStateV1, BitcoinTipStateV1Delta, BitcoinTipStateV1Summary};
use freenet_bitcoin_common::BitcoinTipParameters;

fn decode_params(p: &Parameters<'static>) -> Result<BitcoinTipParameters, ContractError> {
    from_reader::<BitcoinTipParameters, &[u8]>(p.as_ref()).map_err(|e| ContractError::Deser(e.to_string()))
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
        let st = from_reader::<BitcoinTipStateV1, &[u8]>(state.as_ref())
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
            BitcoinTipStateV1::default()
        } else {
            from_reader::<BitcoinTipStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let incoming = from_reader::<BitcoinTipStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.merge(&st.clone(), &params, &incoming).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                    })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<BitcoinTipStateV1Delta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.apply_delta(&st.clone(), &params, &Some(delta)).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                    })?;
                }
                UpdateData::StateAndDelta { state: s, delta: d } => {
                    let incoming = from_reader::<BitcoinTipStateV1, &[u8]>(s.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.merge(&st.clone(), &params, &incoming).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo { reason: e.to_string() }
                    })?;
                    if !d.as_ref().is_empty() {
                        let delta = from_reader::<BitcoinTipStateV1Delta, &[u8]>(d.as_ref())
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
        let st = from_reader::<BitcoinTipStateV1, &[u8]>(state.as_ref())
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
        let st = from_reader::<BitcoinTipStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // An empty summary means the peer holds nothing yet, so it needs
        // everything -- the default summary produces exactly that delta.
        let old = if summary.as_ref().is_empty() {
            // The macro-generated summary type has no Default, and inventing
            // one would risk it disagreeing with what an empty state actually
            // summarizes to. Summarize an empty state instead: that is by
            // construction the summary of a peer holding nothing.
            let empty = BitcoinTipStateV1::default();
            empty.summarize(&empty, &params)
        } else {
            from_reader::<BitcoinTipStateV1Summary, &[u8]>(summary.as_ref())
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
