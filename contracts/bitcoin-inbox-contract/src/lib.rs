#![allow(unexpected_cfgs)]
//! A bridge's Ghost Key gated request inbox, as a Freenet contract.
//!
//! One instance per bridge. Anyone holding a Ghost Key appends a sealed
//! request; the bridge reads it, acts, and removes it with a signed removal
//! batch.
//! All the rules live in `freenet_bitcoin_inbox`; this is the contract
//! surface over them. Design of record: freenet/freenet-bitcoin#3.
//!
//! Built in its own cargo invocation, never alongside the address and tip
//! contracts: cargo merges dependency features across everything built in one
//! command, so building them together could change those contracts' bytes and
//! therefore their addresses.
use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use freenet_bitcoin_inbox::{InboxDelta, InboxParameters, InboxStateV1, InboxSummary};

fn decode_params(p: &Parameters<'static>) -> Result<InboxParameters, ContractError> {
    from_reader::<InboxParameters, &[u8]>(p.as_ref())
        .map_err(|e| ContractError::Deser(e.to_string()))
}

fn decode_state(s: &[u8]) -> Result<InboxStateV1, ContractError> {
    // Zero bytes means "no state here yet", not a malformed encoding.
    if s.is_empty() {
        return Ok(InboxStateV1::default());
    }
    from_reader::<InboxStateV1, &[u8]>(s).map_err(|e| ContractError::Deser(e.to_string()))
}

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, ContractError> {
    let mut out = vec![];
    into_writer(v, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
    Ok(out)
}

fn invalid(reason: String) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason }
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
        // One content, one byte string; see `decode_canonical`, where this is
        // tested.
        let st = InboxStateV1::decode_canonical(state.as_ref()).map_err(invalid)?;
        st.verify(&params)
            .map(|_| ValidateResult::Valid)
            .map_err(|e| invalid(format!("inbox state verification failed: {e}")))
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = decode_params(&parameters)?;
        let mut st = decode_state(state.as_ref())?;
        for update in data {
            match update {
                UpdateData::State(s) => {
                    let incoming = decode_state(s.as_ref())?;
                    st.merge(&params, &incoming).map_err(invalid)?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<InboxDelta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    st.apply_delta(&params, &delta).map_err(invalid)?;
                }
                UpdateData::StateAndDelta { state: s, delta: d } => {
                    let incoming = decode_state(s.as_ref())?;
                    st.merge(&params, &incoming).map_err(invalid)?;
                    if !d.as_ref().is_empty() {
                        let delta = from_reader::<InboxDelta, &[u8]>(d.as_ref())
                            .map_err(|e| ContractError::Deser(e.to_string()))?;
                        st.apply_delta(&params, &delta).map_err(invalid)?;
                    }
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        Ok(UpdateModification::valid(encode(&st)?.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        Ok(StateSummary::from(encode(
            &decode_state(state.as_ref())?.summarize(),
        )?))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        // Guard BOTH empties. A new subscriber summarizes its absent state as
        // zero bytes and asks a holder for the difference, and a holder may
        // itself hold nothing yet; decoding either as CBOR is an error, which
        // would answer the very first exchange with a failure (harvest#55).
        let st = decode_state(state.as_ref())?;
        let old: InboxSummary = if summary.as_ref().is_empty() {
            InboxStateV1::default().summarize()
        } else {
            from_reader::<InboxSummary, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
        match st.delta(&old) {
            Some(d) => Ok(StateDelta::from(encode(&d)?)),
            // Zero bytes: reconciling with a converged peer must cost nothing.
            None => Ok(StateDelta::from(vec![])),
        }
    }
}
